#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_device.py — сканер TCP-портов домофона (для поиска способов
удалённой перезагрузки: telnet, ssh, web, adb и т.п.).

Прошивка STM83xx не выполняет TLV 465 (протокольная перезагрузка);
других reboot-команд в OWSP нет (проверено по всему списку TLV из APK).
У OEM-прошивок часто открыты служебные порты — если найдём telnet/ssh/
adb/web, перезагрузку можно сделать напрямую.

Использование:
    python3 scan_device.py 192.168.1.50            # все 65535 портов
    python3 scan_device.py 192.168.1.50 1-1024     # диапазон

Полный скан 65535 портов из ~400 потоков занимает ~1-3 минуты в LAN.
"""
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

KNOWN_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "TELNET (!)",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1723: "PPTP",
    3306: "MySQL",
    5000: "upnp/сервис",
    5555: "ADB (!) — android-отладка, shell reboot",
    5556: "ADB",
    6668: "сервис",
    8000: "HTTP alt",
    8080: "HTTP alt",
    8554: "RTSP alt",
    8899: "сервис (goolink?)",
    9527: "отладка hisilicon (?)",
    10000: "web-админ",
    15000: "сервис",
    30001: "сервис",
    30002: "сервис",
    30003: "сервис",
    30004: "сервис",
    30005: "OWSP max packet / сервис",
}


def scan_port(host, port, timeout=0.5):
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return port
    except OSError:
        return None


def grab_banner(host, port, timeout=1.5):
    """Прочитать приветствие службы (telnet/ssh/http шлют баннер сами)."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            data = s.recv(256)
        except socket.timeout:
            data = b""
        s.close()
        return data
    except OSError:
        return b""


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    host = sys.argv[1]
    if len(sys.argv) > 2 and "-" in sys.argv[2]:
        lo, hi = sys.argv[2].split("-", 1)
        ports = range(int(lo), int(hi) + 1)
    else:
        ports = range(1, 65536)

    print("сканирую %s (%d портов)..." % (host, len(ports)), flush=True)
    open_ports = []
    with ThreadPoolExecutor(max_workers=400) as ex:
        for res in ex.map(lambda p: scan_port(host, p), ports):
            if res:
                open_ports.append(res)
    if not open_ports:
        print("открытых TCP-портов не найдено")
        return
    print("открытые порты: %d" % len(open_ports))
    for p in open_ports:
        note = KNOWN_PORTS.get(p, "")
        banner = grab_banner(host, p)
        btxt = ""
        if banner:
            btxt = " баннер: %r" % banner[:80]
        print("  %-6d %s%s" % (p, note, btxt), flush=True)
    if any(p in (23, 22, 5555, 80, 8080) for p in open_ports):
        print("\nесть служебные порты — перезагрузка возможна напрямую:")
        if 23 in open_ports:
            print("  telnet %s   (логины: admin/admin, root/root, "
                  "admin/<пусто>…; затем 'reboot' или 'sdupdate/reboot')"
                  % host)
        if 22 in open_ports:
            print("  ssh root@%s  (root/root, root/<пусто>)" % host)
        if 5555 in open_ports:
            print("  adb connect %s:5555 && adb shell reboot" % host)
        if 80 in open_ports or 8080 in open_ports:
            print("  http://%s  (web-интерфейс: настройки/перезагрузка)"
                  % host)


if __name__ == "__main__":
    main()
