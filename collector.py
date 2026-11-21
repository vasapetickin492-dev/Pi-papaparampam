#!/usr/bin/env python3
"""
Собирает бесплатные VPN-ключи из подписок/каналов, проверяет их и сохраняет
лучшие в sub.txt (base64-подписка для Happ).

Как проверяются ключи (от дешёвой проверки к дорогой):
  1. Быстрый фильтр: порт открыт и проходит TLS-рукопожатие (если есть TLS).
  2. РЕАЛЬНАЯ проверка трафиком: ядро Xray поднимает каждый ключ как прокси,
     через него идёт настоящий HTTP-запрос в интернет. В подписку попадают
     только ключи, через которые запрос реально прошёл.
     Без Xray (переменная XRAY_BIN не задана и xray не найден) скрипт
     работает по шагу 1.
  * Память: живые ключи из прошлого sub.txt остаются в списке до MAX_AGE_DAYS
    дней, но тоже проходят проверку.
  * Метки: к названию ключа дописывается [sN ММДД]: N = номер источника,
    ММДД = когда ключ последний раз был в источнике.

Только стандартная библиотека Python 3.8+ (и бинарник xray для шага 2).
Запуск:  python collector.py
"""
import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
from urllib.parse import parse_qs, quote, unquote, urlparse

# ====== НАСТРОЙКИ ======
# Нумерация идёт сверху вниз: первая ссылка = s1, вторая = s2 и так далее.
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/reality",
    "https://github.com/pie-with-jam/PulseProxy/raw/refs/heads/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
]

MAX_PER_SOURCE = 40       # сколько лучших ключей брать от КАЖДОГО источника
REAL_CHECK = True         # True = реальная проверка трафиком через Xray
MAX_TEST_PER_SOURCE = 300 # сколько ключей от источника отправлять на реальную проверку
DEEP_CHECK = True         # быстрый фильтр: True = TLS-рукопожатие, False = только порт
KEEP_OLD = True           # сохранять живые ключи из прошлого списка
MAX_KEEP_OLD = 30         # сколько таких старых ключей максимум
MAX_AGE_DAYS = 3          # сколько дней старый ключ может жить без источника
NO_CHECK = []             # номера источников, ключи которых вообще не проверяются

TIMEOUT = 5               # секунд на быстрый фильтр
THREADS = 60              # параллельных быстрых проверок
BATCH = 100               # ключей в одной пачке для Xray
TEST_TIMEOUT = 10         # секунд на реальный запрос через ключ
TEST_HOST = "cp.cloudflare.com"   # куда идёт тестовый запрос
TEST_PORT = 80
TEST_PATH = "/generate_204"       # ответ 204 = трафик реально прошёл
BASE_PORT = 21000         # локальные порты для проверки
XRAY_BIN = os.environ.get("XRAY_BIN") or shutil.which("xray")
OUTPUT = "sub.txt"        # итоговый файл подписки
# ========================

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\"'<>]+")
TAG_RE = re.compile(r"\[(\w+) (\d{4})\]")


# ---------- загрузка и разбор ----------

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", errors="ignore")


def b64decode_safe(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


LINE_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://\S")
EXTRA_RE = re.compile(r"([?&]extra=)(.*?)(?=&[A-Za-z]+=|#|$)")


def normalize(link):
    """
    Некоторые источники пишут extra сырым JSON с кавычками. Такой ключ нельзя
    резать по кавычке, а Happ воспринимает его как повреждённый JSON.
    Кодируем extra по правилам URL.
    """
    m = EXTRA_RE.search(link)
    if m and m.group(2).startswith("{"):
        link = link[:m.start(2)] + quote(m.group(2), safe="") + link[m.end(2):]
    return link


def scan(text):
    # Обычный файл: один ключ на строку. Берём строку целиком, чтобы не
    # обрезать ключ на кавычках или пробелах внутри JSON.
    links = [l.strip() for l in text.splitlines() if LINE_RE.match(l.strip())]
    if not links:  # HTML-страница канала и подобное: ищем по шаблону
        links = LINK_RE.findall(text)
    return links


def extract_links(text):
    """Достаёт ключи из текста; если это base64-подписка, сначала раскодирует."""
    links = scan(text)
    if not links:
        links = scan(b64decode_safe(text))
    return [normalize(l.replace("&amp;", "&").rstrip(".,;")) for l in links]


def ss_parts(link):
    """ss://... -> (method, password, host, port) или None."""
    body = link[5:].split("#")[0]
    if "?" in body:
        body, qs = body.split("?", 1)
        if "plugin" in qs:
            return None
    if "@" in body:
        ui, hp = body.rsplit("@", 1)
        if ":" not in ui:
            ui = b64decode_safe(ui)
        ui = unquote(ui)
    else:
        dec = b64decode_safe(body)
        if "@" not in dec:
            return None
        ui, hp = dec.rsplit("@", 1)
    method, _, password = ui.partition(":")
    host, _, port = hp.rpartition(":")
    return method, password, host.strip("[]"), int(port)


# ---------- быстрый фильтр (порт + TLS) ----------

def parse_target(link):
    """
    Возвращает (host, port, sni) или None.
    sni is None  -> обычный TCP, без TLS
    sni == ""    -> TLS без указания имени
    sni = "имя"  -> TLS с этим SNI (для Reality это домен-прикрытие)
    """
    try:
        if link.startswith("vmess://"):
            d = json.loads(b64decode_safe(link[8:]))
            host, port = d["add"], int(d["port"])
            if str(d.get("tls", "")).lower() == "tls":
                return host, port, d.get("sni") or d.get("host") or host
            return host, port, None
        if link.startswith("ss://"):
            p = ss_parts(link)
            return (p[2], p[3], None) if p else None
        u = urlparse(link)
        if u.hostname and u.port:
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            sec = q.get("security", "")
            if link.startswith("trojan://") and sec == "":
                sec = "tls"
            if sec in ("tls", "reality"):
                return u.hostname, u.port, q.get("sni") or q.get("host") or ""
            return u.hostname, u.port, None
    except Exception:
        pass
    return None


def check(link):
    """Возвращает (link, время) если сервер жив, иначе None."""
    t = parse_target(link)
    if not t:
        return None
    host, port, sni = t
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            if DEEP_CHECK and sni is not None:
                name = sni or None
                if name:
                    try:
                        ipaddress.ip_address(name)  # SNI не может быть IP
                        name = None
                    except ValueError:
                        pass
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s.settimeout(TIMEOUT)
                with ctx.wrap_socket(s, server_hostname=name):
                    pass
        return link, time.time() - start
    except Exception:
        return None


# ---------- реальная проверка трафиком (Xray) ----------

def stream_settings(net, q, host_default):
    """Блок streamSettings для Xray или None, если транспорт не поддержан."""
    net = (net or "tcp").lower()
    # транспорт h2/http в Xray 26 удалён, такие ключи пропускаем
    net = {"raw": "tcp", "splithttp": "xhttp"}.get(net, net)
    host = q.get("host", "")
    path = unquote(q.get("path", "")) or "/"
    st = {"network": net}
    if net == "tcp":
        if q.get("headerType", "none") not in ("", "none"):
            return None
    elif net == "ws":
        st["wsSettings"] = {"path": path, "headers": {"Host": host} if host else {}}
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": q.get("serviceName", ""),
                              "multiMode": q.get("mode") == "multi"}
    elif net == "httpupgrade":
        st["httpupgradeSettings"] = {"path": path, "host": host}
    elif net == "xhttp":
        x = {"path": path, "host": host}
        if q.get("mode"):
            x["mode"] = q["mode"]
        if q.get("extra"):
            try:
                x["extra"] = json.loads(unquote(q["extra"]))
            except Exception:
                return None
        st["xhttpSettings"] = x
    elif net == "kcp":
        k = {"header": {"type": q.get("headerType", "none")}}
        if q.get("seed"):
            k["seed"] = q["seed"]
        st["kcpSettings"] = k
    else:
        return None

    sec = (q.get("security") or "none").lower()
    sni = q.get("sni") or q.get("peer") or ""
    fp = q.get("fp") or "chrome"
    if sec == "tls":
        t = {"fingerprint": fp}
        if sni:
            t["serverName"] = sni
        if q.get("alpn"):
            t["alpn"] = unquote(q["alpn"]).split(",")
        # allowInsecure в Xray 26 удалён: ключи с самоподписанным сертификатом
        # не пройдут проверку, это нормально
        st["security"] = "tls"
        st["tlsSettings"] = t
    elif sec == "reality":
        if not q.get("pbk"):
            return None
        st["security"] = "reality"
        st["realitySettings"] = {
            "serverName": sni, "fingerprint": fp, "publicKey": q["pbk"],
            "shortId": q.get("sid", ""), "spiderX": unquote(q.get("spx", "")),
        }
    else:
        st["security"] = "none"
    return st


def to_outbound(link):
    """Превращает ключ в outbound для Xray. None, если формат не поддержан."""
    try:
        if link.startswith("vmess://"):
            d = json.loads(b64decode_safe(link[8:]))
            q = {"host": d.get("host", ""), "path": d.get("path", ""),
                 "serviceName": d.get("path", ""), "sni": d.get("sni", ""),
                 "fp": d.get("fp", ""), "alpn": d.get("alpn", ""),
                 "headerType": d.get("type", "none"),
                 "security": "tls" if str(d.get("tls", "")).lower() == "tls" else "none"}
            st = stream_settings(d.get("net", "tcp"), q, d["add"])
            if st is None:
                return None
            user = {"id": d["id"], "alterId": int(d.get("aid") or 0),
                    "security": d.get("scy") or "auto"}
            return {"protocol": "vmess", "streamSettings": st,
                    "settings": {"vnext": [{"address": d["add"], "port": int(d["port"]),
                                            "users": [user]}]}}
        if link.startswith("ss://"):
            p = ss_parts(link)
            if not p:
                return None
            return {"protocol": "shadowsocks",
                    "settings": {"servers": [{"address": p[2], "port": p[3],
                                              "method": p[0], "password": p[1]}]}}
        u = urlparse(link)
        if not (u.hostname and u.port and u.username):
            return None
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if link.startswith("vless://"):
            st = stream_settings(q.get("type"), q, u.hostname)
            if st is None:
                return None
            user = {"id": unquote(u.username), "encryption": q.get("encryption") or "none"}
            if q.get("flow"):
                user["flow"] = q["flow"]
            return {"protocol": "vless", "streamSettings": st,
                    "settings": {"vnext": [{"address": u.hostname, "port": u.port,
                                            "users": [user]}]}}
        if link.startswith("trojan://"):
            q.setdefault("security", "tls")
            st = stream_settings(q.get("type"), q, u.hostname)
            if st is None:
                return None
            return {"protocol": "trojan", "streamSettings": st,
                    "settings": {"servers": [{"address": u.hostname, "port": u.port,
                                              "password": unquote(u.username)}]}}
    except Exception:
        pass
    return None


def build_config(items):
    inb, outb, rules = [], [], []
    for i, (_, ob) in enumerate(items):
        ob = dict(ob)
        ob["tag"] = f"o{i}"
        outb.append(ob)
        inb.append({"tag": f"i{i}", "listen": "127.0.0.1", "port": BASE_PORT + i,
                    "protocol": "socks", "settings": {"auth": "noauth", "udp": False}})
        rules.append({"type": "field", "inboundTag": [f"i{i}"], "outboundTag": f"o{i}"})
    return {"log": {"loglevel": "none"}, "inbounds": inb, "outbounds": outb,
            "routing": {"rules": rules}}


def xray_accepts(items, workdir):
    """True, если Xray принимает конфиг целиком (режим -test)."""
    path = os.path.join(workdir, "test.json")
    with open(path, "w") as f:
        json.dump(build_config(items), f)
    try:
        r = subprocess.run([XRAY_BIN, "run", "-test", "-c", path],
                           capture_output=True, timeout=60)
        return r.returncode == 0
    except Exception:
        return False


def split_valid(items, workdir):
    """Оставляет только ключи, которые Xray принимает; битые отсеивает бисекцией."""
    if not items:
        return []
    if xray_accepts(items, workdir):
        return items
    if len(items) == 1:
        return []
    mid = len(items) // 2
    return split_valid(items[:mid], workdir) + split_valid(items[mid:], workdir)


def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise IOError("eof")
        buf += chunk
    return buf


def proxy_probe(port):
    """Реальный HTTP-запрос через локальный SOCKS5-порт. Время или None."""
    start = time.time()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=TEST_TIMEOUT) as s:
            s.settimeout(TEST_TIMEOUT)
            s.sendall(b"\x05\x01\x00")
            if recv_exact(s, 2) != b"\x05\x00":
                return None
            h = TEST_HOST.encode()
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + TEST_PORT.to_bytes(2, "big"))
            head = recv_exact(s, 4)
            if head[1] != 0:
                return None
            if head[3] == 3:
                recv_exact(s, recv_exact(s, 1)[0] + 2)
            else:
                recv_exact(s, 6 if head[3] == 1 else 18)
            s.sendall((f"GET {TEST_PATH} HTTP/1.1\r\nHost: {TEST_HOST}\r\n"
                       "User-Agent: curl/8.5\r\nConnection: close\r\n\r\n").encode())
            line = b""
            while b"\r\n" not in line and len(line) < 200:
                chunk = s.recv(200)
                if not chunk:
                    break
                line += chunk
            status = line.split(b"\r\n", 1)[0]
            if status.startswith(b"HTTP/") and b" 204" in status[:16]:
                return time.time() - start
    except Exception:
        pass
    return None


def run_batch(items):
    """Поднимает Xray с пачкой ключей и проверяет каждый. [(link, время)]."""
    with tempfile.TemporaryDirectory() as wd:
        path = os.path.join(wd, "run.json")
        with open(path, "w") as f:
            json.dump(build_config(items), f)
        proc = subprocess.Popen([XRAY_BIN, "run", "-c", path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            last = BASE_PORT + len(items) - 1
            ready = False
            for _ in range(100):  # до 10 секунд ждём запуска
                if proc.poll() is not None:
                    return []
                try:
                    socket.create_connection(("127.0.0.1", last), timeout=0.5).close()
                    ready = True
                    break
                except OSError:
                    time.sleep(0.1)
            if not ready:
                return []
            ports = [BASE_PORT + i for i in range(len(items))]
            with ThreadPoolExecutor(len(items)) as ex:
                times = list(ex.map(proxy_probe, ports))
            return [(l, t) for (l, _), t in zip(items, times) if t is not None]
        finally:
            proc.terminate()
            try:
                proc.wait(5)
            except Exception:
                proc.kill()


def real_check(links):
    """Реальная проверка трафиком. Возвращает [(link, время)] только рабочих."""
    items = []
    for l in links:
        ob = to_outbound(l)
        if ob:
            items.append((l, ob))
    print(f"  в формат Xray переведено: {len(items)} из {len(links)}")
    ok = []
    with tempfile.TemporaryDirectory() as wd:
        for i in range(0, len(items), BATCH):
            chunk = split_valid(items[i:i + BATCH], wd)
            if chunk:
                ok += run_batch(chunk)
    return ok


# ---------- метки и память ----------

def core(link):
    """Ключ без названия: по нему сравниваем ключи между запусками."""
    try:
        if link.startswith("vmess://"):
            d = json.loads(b64decode_safe(link[8:]))
            return f'vmess|{d.get("add")}|{d.get("port")}|{d.get("id")}'
    except Exception:
        pass
    return link.split("#")[0]


def link_name(link):
    try:
        if link.startswith("vmess://"):
            return json.loads(b64decode_safe(link[8:])).get("ps", "")
    except Exception:
        return ""
    return unquote(link.partition("#")[2])


def tag_link(link, tag):
    """Дописывает метку в название ключа, чтобы она была видна в Happ."""
    try:
        if link.startswith("vmess://"):
            data = json.loads(b64decode_safe(link[8:]))
            data["ps"] = f'{data.get("ps", "")} [{tag}]'.strip()
            raw = json.dumps(data, ensure_ascii=False).encode()
            return "vmess://" + base64.b64encode(raw).decode()
        base, _, frag = link.partition("#")
        return f"{base}#{quote(f'{unquote(frag)} [{tag}]'.strip())}"
    except Exception:
        return link


def age_days(link, today):
    """Сколько дней назад ключ последний раз был в источнике; None = даты нет."""
    m = TAG_RE.search(link_name(link))
    if not m:
        return None
    try:
        mm, dd = int(m.group(2)[:2]), int(m.group(2)[2:])
        d = date(today.year, mm, dd)
        if d > today:
            d = date(today.year - 1, mm, dd)
        return (today - d).days
    except Exception:
        return None


def load_previous():
    if not (KEEP_OLD and os.path.exists(OUTPUT)):
        return []
    try:
        with open(OUTPUT) as f:
            text = b64decode_safe(f.read())
        lines = [l.strip() for l in text.splitlines()]
        return [l for l in lines if LINK_RE.match(l)]
    except Exception:
        return []


# ---------- главная программа ----------

def main():
    if not SOURCES:
        sys.exit("Добавьте ссылки в SOURCES внутри collector.py")

    now = datetime.now(timezone.utc)
    today, stamp = now.date(), now.strftime("%m%d")
    use_real = REAL_CHECK and bool(XRAY_BIN)
    if REAL_CHECK and not XRAY_BIN:
        print("ВНИМАНИЕ: Xray не найден, реальной проверки трафиком не будет "
              "(только порт/TLS). Задайте XRAY_BIN.")

    stats = {}
    tag_of = {}  # ключ -> метка первого источника, где он встретился
    for i, url in enumerate(SOURCES, 1):
        tag = f"s{i}"
        stats[tag] = {"url": url, "found": 0, "unique": 0, "tls": 0,
                      "real": 0, "used": 0, "error": ""}
        try:
            found = extract_links(fetch(url))
        except Exception as e:
            stats[tag]["error"] = str(e)[:80]
            continue
        stats[tag]["found"] = len(found)
        for l in found:
            if l not in tag_of:
                tag_of[l] = tag
                stats[tag]["unique"] += 1

    links = list(tag_of)
    mode = "TLS-рукопожатие" if DEEP_CHECK else "порт"
    print(f"Всего уникальных ключей: {len(links)}. Быстрый фильтр: {mode}...")

    skip_tags = {f"s{n}" for n in NO_CHECK}
    to_check = [l for l in links if tag_of[l] not in skip_tags]
    unchecked = [(l, 999.0) for l in links if tag_of[l] in skip_tags]

    with ThreadPoolExecutor(THREADS) as ex:
        alive = [r for r in ex.map(check, to_check) if r]
    alive.sort(key=lambda x: x[1])
    for l, _ in alive:
        stats[tag_of[l]]["tls"] += 1

    pool = alive
    if use_real:
        cand, cnt = [], {}
        for l, _ in alive:  # уже отсортированы по скорости
            t = tag_of[l]
            if cnt.get(t, 0) < MAX_TEST_PER_SOURCE:
                cnt[t] = cnt.get(t, 0) + 1
                cand.append(l)
        print(f"Реальная проверка трафиком: {len(cand)} ключей...")
        pool = real_check(cand)
        for l, _ in pool:
            stats[tag_of[l]]["real"] += 1
    pool = sorted(pool + unchecked, key=lambda x: x[1])

    # квота на каждый источник, чтобы один быстрый не вытеснял остальные
    taken, best = {}, []
    for l, lat in pool:
        t = tag_of[l]
        if taken.get(t, 0) < MAX_PER_SOURCE:
            taken[t] = taken.get(t, 0) + 1
            best.append((l, lat))
            stats[t]["used"] += 1

    out = [tag_link(l, f"{tag_of[l]} {stamp}") for l, _ in best]

    # ключи из прошлого списка, которые всё ещё живы
    kept = 0
    if KEEP_OLD:
        chosen = {core(l) for l, _ in best}
        prev, seen = [], set()
        for l in load_previous():
            c = core(l)
            age = age_days(l, today)
            if c in chosen or c in seen or (age is not None and age > MAX_AGE_DAYS):
                continue
            seen.add(c)
            prev.append(l)
        with ThreadPoolExecutor(THREADS) as ex:
            prev_alive = [r for r in ex.map(check, prev) if r]
        if use_real and prev_alive:
            print(f"Реальная проверка ключей из прошлого списка: {len(prev_alive)}...")
            prev_alive = real_check([l for l, _ in prev_alive])
        prev_alive.sort(key=lambda x: x[1])
        for l, _ in prev_alive[:MAX_KEEP_OLD]:
            # у ключей без даты (от старой версии скрипта) ставим дату сейчас,
            # чтобы они тоже со временем устаревали
            out.append(l if age_days(l, today) is not None
                       else tag_link(l, f"old {stamp}"))
            kept += 1

    print("\n=== Статистика по источникам ===")
    for tag, s in stats.items():
        if s["error"]:
            print(f"{tag}: ОШИБКА загрузки ({s['error']})\n    {s['url']}")
            continue
        real = f", трафик ОК {s['real']}" if use_real else ""
        print(f"{tag}: найдено {s['found']}, новых {s['unique']}, "
              f"порт/TLS ок {s['tls']}{real}, в подписке {s['used']}\n    {s['url']}")
    print(f"\nСвежих в подписке: {len(best)}. Сохранено из прошлого списка: {kept}")

    if not out:
        print("ВНИМАНИЕ: рабочих ключей нет, sub.txt не перезаписан (остаётся прошлый).")
        return

    payload = base64.b64encode("\n".join(out).encode()).decode()
    with open(OUTPUT, "w") as f:
        f.write(payload)
    print(f"Готово: {OUTPUT} ({len(out)} ключей)")


if __name__ == "__main__":
    main()
