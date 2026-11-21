#!/usr/bin/env python3
"""
Собирает бесплатные VPN-ключи из подписок/каналов, проверяет их и сохраняет
лучшие в sub.txt (base64-подписка для Happ).

Что делает:
  * Глубокая проверка: для ключей с TLS/Reality скрипт не просто открывает порт,
    а проходит настоящее TLS-рукопожатие с SNI из ключа. Так отсеиваются
    серверы, где порт открыт, а VPN уже не работает.
  * Память: живые ключи из прошлого sub.txt остаются в списке до MAX_AGE_DAYS
    дней, даже если источник уже убрал их или они не попали в квоту.
  * Метки: к названию каждого ключа дописывается [sN ММДД]: N = номер
    источника, ММДД = когда ключ последний раз был в источнике.

Только стандартная библиотека Python 3.8+. Ничего ставить не нужно.
Запуск:  python collector.py
"""
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
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

MAX_PER_SOURCE = 40    # сколько лучших ключей брать от КАЖДОГО источника
DEEP_CHECK = True      # True = TLS-рукопожатие, False = только открытый порт
KEEP_OLD = True        # сохранять живые ключи из прошлого списка
MAX_KEEP_OLD = 30      # сколько таких старых ключей максимум
MAX_AGE_DAYS = 3       # сколько дней старый ключ может жить без источника
# Номера источников (1 = s1, 2 = s2 ...), ключи которых НЕ проверяются.
NO_CHECK = []

TIMEOUT = 5            # секунд на проверку одного ключа
THREADS = 60           # параллельных проверок
OUTPUT = "sub.txt"     # итоговый файл подписки
# ========================

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\"'<>]+")
TAG_RE = re.compile(r"\[(\w+) (\d{4})\]")


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


def extract_links(text):
    """Достаёт ключи из текста; если это base64-подписка, сначала раскодирует."""
    links = LINK_RE.findall(text)
    if not links:
        links = LINK_RE.findall(b64decode_safe(text))
    return [l.replace("&amp;", "&").rstrip(".,;") for l in links]


def ss_host_port(link):
    """ss://BASE64(method:pass@host:port) -> (host, port) или None."""
    body = link[5:].split("#")[0].split("?")[0]
    decoded = b64decode_safe(body)
    if "@" in decoded:
        h, p = decoded.rsplit("@", 1)[1].rsplit(":", 1)
        return h, int(p)
    return None


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
        u = urlparse(link)
        if u.hostname and u.port:
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            sec = q.get("security", "")
            if link.startswith("trojan://") and sec == "":
                sec = "tls"
            if sec in ("tls", "reality"):
                return u.hostname, u.port, q.get("sni") or q.get("host") or ""
            return u.hostname, u.port, None
        if link.startswith("ss://"):
            hp = ss_host_port(link)
            if hp:
                return hp[0], hp[1], None
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


def main():
    if not SOURCES:
        sys.exit("Добавьте ссылки в SOURCES внутри collector.py")

    now = datetime.now(timezone.utc)
    today, stamp = now.date(), now.strftime("%m%d")

    stats = {}
    tag_of = {}  # ключ -> метка первого источника, где он встретился
    for i, url in enumerate(SOURCES, 1):
        tag = f"s{i}"
        stats[tag] = {"url": url, "found": 0, "unique": 0,
                      "alive": 0, "used": 0, "error": ""}
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
    print(f"Всего уникальных ключей: {len(links)}. Проверка: {mode}...")

    skip_tags = {f"s{n}" for n in NO_CHECK}
    to_check = [l for l in links if tag_of[l] not in skip_tags]
    unchecked = [(l, 999.0) for l in links if tag_of[l] in skip_tags]

    with ThreadPoolExecutor(THREADS) as ex:
        alive = [r for r in ex.map(check, to_check) if r]
    alive += unchecked
    alive.sort(key=lambda x: x[1])

    for l, _ in alive:
        stats[tag_of[l]]["alive"] += 1

    # квота на каждый источник, чтобы один быстрый не вытеснял остальные
    taken, best = {}, []
    for l, lat in alive:
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
        pct = round(100 * s["alive"] / s["unique"]) if s["unique"] else 0
        print(f"{tag}: найдено {s['found']}, новых {s['unique']}, "
              f"живых {s['alive']} ({pct}%), в подписке {s['used']}\n    {s['url']}")
    print(f"\nЖивых всего: {len(alive)}. Свежих в подписке: {len(best)}. "
          f"Сохранено из прошлого списка: {kept}")

    if not out:
        sys.exit("Рабочих ключей нет, файл не перезаписан")

    payload = base64.b64encode("\n".join(out).encode()).decode()
    with open(OUTPUT, "w") as f:
        f.write(payload)
    print(f"Готово: {OUTPUT} ({len(out)} ключей)")


if __name__ == "__main__":
    main()
