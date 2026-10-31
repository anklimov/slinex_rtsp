#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""udp_monitor.py — монитор UDP-пакетов домофона (эксперимент: события вызова).

В OWSP-протоколе (APK com.gooclient.mobileeyedoor.plus, полный список
Command.java) нет TLV «звонок»: приложение получало вызовы через вендорное
облако push2u.com (MQTT), которое умерло. Этот скрипт проверяет вторую
возможность — spontaneous UDP-пакеты от устройства в LAN.

Слушает порты, которые использует приложение:
  1500  — discovery/P2P (GooLinkPack.Define.GROUP_PORT; запросы идут на
          255.255.255.255 и multicast 235.10.10.10)
  23456 — GooLinkPack.Define.UDP_RECEIVE_PORT (P2P-приём приложения)

Запуск на хосте шлюза (internal):
  python3 udp_monitor.py            # оба порта
  python3 udp_monitor.py 1500       # один порт

Дальше нажми кнопку вызова на панели и смотри, прилетит ли пакет.
Печатает: время, src, длина, hex (первые 96 байт).
"""
import socket
import struct
import sys
import threading
import time

GROUP_IP = "235.10.10.10"

# типы сообщений GooLinkPack (для расшифровки того, что прилетит)
MSG_TYPES = {
    40962: "OPEN_CONN_RESPONSE", 40963: "CLOSE_CONN_REQUEST",
    40964: "CLOSE_CONN_RESPONSE", 40965: "DEVICE_STATUS_REQUEST",
    40966: "DEVICE_STATUS_RESPONSE", 40967: "SEARCH_DEVICE_REQUEST",
    40968: "SEARCH_DEVICE_RESPONSE", 40969: "CREATE_CLOUDYSTORAGE_REQUEST",
    40976: "CREATE_CLOUDYSTORAGE_RESPONSE", 40977: "RENEW_CLOUDYSTORAGE_REQUEST",
    40978: "RENEW_CLOUDYSTORAGE_RESPONSE", 40979: "FAILED_OPENUDP_CONN_REQUEST",
    40980: "FAILED_OPENUDP_CONN_RESPONSE", 40982: "FAILED_OPENUPNP_CONN_RESPONSE",
    40983: "OPEN_CONN_REQUEST", 40985: "FAILED_OPENUPNP_CONN_REQUEST",
    40992: "OPEN_CONN_REQUEST4",
}


def describe(data):
    """Первый u16 LE — тип сообщения GooLink (если это оно)."""
    if len(data) >= 2:
        mtype = struct.unpack_from("<H", data)[0]
        name = MSG_TYPES.get(mtype)
        if name:
            return "msg=%d (%s)" % (mtype, name)
        return "msg=%d" % mtype
    return ""


def listener(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    except OSError:
        pass
    try:  # вступаем в multicast-группу discovery (не критично)
        mreq = socket.inet_aton(GROUP_IP) + socket.inet_aton("0.0.0.0")
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass
    s.bind(("0.0.0.0", port))
    print("[udp] слушает 0.0.0.0:%d" % port, flush=True)
    while True:
        try:
            data, addr = s.recvfrom(2048)
        except OSError:
            continue
        print("%s :%d <- %s:%d  %d байт  %s\n  hex: %s"
              % (time.strftime("%H:%M:%S"), port, addr[0], addr[1],
                 len(data), describe(data), data[:96].hex()), flush=True)


def main():
    ports = [int(a) for a in sys.argv[1:]] or [1500, 23456]
    for port in ports:
        threading.Thread(target=listener, args=(port,),
                         daemon=True).start()
    print("[udp] монитор событий: жду пакеты (нажми кнопку на панели)...")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
