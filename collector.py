#!/usr/bin/env python3
"""
Собирает бесплатные VPN-ключи из подписок/каналов, проверяет, какие порты
реально отвечают, и сохраняет лучшие в sub.txt (base64-подписка для Happ).

Каждый ключ получает в названии метку источника: [s1], [s2] и т.д.
В логе запуска (Actions) выводится таблица: какой источник сколько дал.

Только стандартная библиотека Python 3.8+. Ничего ставить не нужно.
Запуск:  python collector.py
"""
import base64
import json
import re
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote, unquote, urlparse

# ====== НАСТРОЙКИ ======
# Нумерация идёт сверху вниз: первая ссылка = s1, вторая = s2 и так далее.
# Если добавляете новые, лучше писать их в конец списка, чтобы метки
# старых источников не поменялись.
SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://github.com/pie-with-jam/PulseProxy/raw/refs/heads/main/githubmirror/1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
]

MAX_KEYS = 40          # сколько лучших ключей оставить
TIMEOUT = 4            # секунд на проверку одного ключа
THREADS = 60           # параллельных проверок
OUTPUT = "sub.txt"     # итоговый файл подписки
# ========================

LINK_RE = re.compile(r"(?:vless|vmess|trojan|ss|hysteria2|hy2)://[^\s\"'<>]+")


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
        decoded = b64decode_safe(text)
        links = LINK_RE.findall(decoded)
    # t.me/s/ отдаёт HTML, где & превращается в &amp;
    return [l.replace("&amp;", "&").rstrip(".,;") for l in links]


def host_port(link):
    """Возвращает (host, port) или None."""
    try:
        if link.startswith("vmess://"):
            data = json.loads(b64decode_safe(link[8:]))
            return data["add"], int(data["port"])
        u = urlparse(link)
        if u.hostname and u.port:
            return u.hostname, u.port
        if link.startswith("ss://"):  # формат ss://BASE64(method:pass@host:port)
            body = link[5:].split("#")[0].split("?")[0]
            decoded = b64decode_safe(body)
            if "@" in decoded:
                hp = decoded.rsplit("@", 1)[1]
                h, p = hp.rsplit(":", 1)
                return h, int(p)
    except Exception:
        pass
    return None


def check(link):
    hp = host_port(link)
    if not hp:
        return None
    start = time.time()
    try:
        with socket.create_connection(hp, timeout=TIMEOUT):
            return link, time.time() - start
    except Exception:
        return None


def tag_link(link, tag):
    """Дописывает метку источника в название ключа, чтобы она была видна в Happ."""
    try:
        if link.startswith("vmess://"):
            data = json.loads(b64decode_safe(link[8:]))
            data["ps"] = f'{data.get("ps", "")} [{tag}]'.strip()
            raw = json.dumps(data, ensure_ascii=False).encode()
            return "vmess://" + base64.b64encode(raw).decode()
        base, _, frag = link.partition("#")
        name = f"{unquote(frag)} [{tag}]".strip()
        return f"{base}#{quote(name)}"
    except Exception:
        return link


def main():
    if not SOURCES:
        sys.exit("Добавьте ссылки в SOURCES внутри collector.py")

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
    print(f"Всего уникальных ключей: {len(links)}. Проверяю...")

    with ThreadPoolExecutor(THREADS) as ex:
        alive = [r for r in ex.map(check, links) if r]
    alive.sort(key=lambda x: x[1])

    for l, _ in alive:
        stats[tag_of[l]]["alive"] += 1
    best = alive[:MAX_KEYS]
    for l, _ in best:
        stats[tag_of[l]]["used"] += 1

    print("\n=== Статистика по источникам ===")
    for tag, s in stats.items():
        if s["error"]:
            print(f"{tag}: ОШИБКА загрузки ({s['error']})\n    {s['url']}")
            continue
        pct = round(100 * s["alive"] / s["unique"]) if s["unique"] else 0
        print(f"{tag}: найдено {s['found']}, новых {s['unique']}, "
              f"живых {s['alive']} ({pct}%), в подписке {s['used']}\n    {s['url']}")
    print(f"\nЖивых всего: {len(alive)}. В подписку попало: {len(best)}")

    if not best:
        sys.exit("Рабочих ключей нет, файл не перезаписан")

    out = [tag_link(l, tag_of[l]) for l, _ in best]
    payload = base64.b64encode("\n".join(out).encode()).decode()
    with open(OUTPUT, "w") as f:
        f.write(payload)
    print(f"Готово: {OUTPUT}")


if __name__ == "__main__":
    main()
