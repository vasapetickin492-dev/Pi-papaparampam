#!/usr/bin/env python3
"""
Собирает бесплатные VPN-ключи из подписок/каналов, проверяет, какие порты
реально отвечают, и сохраняет лучшие в sub.txt (base64-подписка для Happ).

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
from urllib.parse import urlparse

# ====== НАСТРОЙКИ ======
# Сюда вставьте ссылки на подписки (текстовые файлы со списком ключей или
# base64-подписки). Ищите на GitHub: "free v2ray subscription", "vless sub".
# Для публичных Telegram-каналов можно использовать страницу https://t.me/s/ИМЯ_КАНАЛА
SOURCES = [
    # "https://raw.githubusercontent.com/USER/REPO/main/sub.txt",
    # "https://t.me/s/имя_канала",
]

MAX_KEYS = 40          # сколько лучших ключей оставить
TIMEOUT = 4            # секунд на проверку одного ключа
THREADS = 60           # параллельных проверок
OUTPUT = "sub.txt"     # итоговый файл подписки
# ========================

PROTOS = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://")
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


def main():
    if not SOURCES:
        sys.exit("Добавьте ссылки в SOURCES внутри collector.py")

    links = []
    for url in SOURCES:
        try:
            found = extract_links(fetch(url))
            print(f"{url}: найдено {len(found)}")
            links += found
        except Exception as e:
            print(f"{url}: ошибка {e}")

    links = list(dict.fromkeys(links))  # убрать дубли, сохранив порядок
    print(f"Всего уникальных: {len(links)}. Проверяю...")

    with ThreadPoolExecutor(THREADS) as ex:
        alive = [r for r in ex.map(check, links) if r]

    alive.sort(key=lambda x: x[1])
    best = [l for l, _ in alive[:MAX_KEYS]]
    print(f"Живых: {len(alive)}. Сохраняю лучших: {len(best)}")

    if not best:
        sys.exit("Рабочих ключей нет, файл не перезаписан")

    payload = base64.b64encode("\n".join(best).encode()).decode()
    with open(OUTPUT, "w") as f:
        f.write(payload)
    print(f"Готово: {OUTPUT}")


if __name__ == "__main__":
    main()
