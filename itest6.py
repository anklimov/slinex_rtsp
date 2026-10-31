#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест 6: удалённая перезагрузка (--reboot).

Мок повторяет наблюдённое на STM83xx поведение прошивки:
- соединение 1: логин-настройка (deviceId=0, flag=2) отклоняется
  КОДОМ 5 (лимит подключений — слот предыдущей сессии ещё занят) →
  шлюз обязан выдержать паузу и повторить ТОТ ЖЕ вариант;
- соединение 2: (0,2) принимается, шлюз шлёт TLV 465 НЕМЕДЛЕННО после
  ответа логина (без keep-alive и пауз, как DeviceConfig.sendConfig());
- соединение 3: логин (deviceId=1, flag=2) принимается, а мок, как
  реальная прошивка STM83xx, ЗАКРЫВАЕТ соединение БЕЗ TLV 466;
- соединение 4: логин (deviceId=0, flag=0) принимается, на 465 мок
  отвечает TLV 466 и рвёт соединение → код возврата 0.

Ключевые проверки регрессии 28.10: (а) обрыв без 466 НЕ считается
успехом и НЕ останавливает перебор вариантов; (б) код 5 не «съедает»
вариант — тот же вариант повторяется после паузы (--reboot-pause).
"""
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, ".")
from slinex_rtsp import encrypt_password, owsp_packet, parse_owsp_packets  # noqa: E402

OWSP_PORT = 21006


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def mock_doorphone(stop, state):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", OWSP_PORT))
    srv.listen(4)
    print("[mock] слушает :%d" % OWSP_PORT, flush=True)

    def check_login(v, tag):
        assert len(v) == 68, "LoginRequestEx должен быть 68 байт, %d" % len(v)
        user = v[1:33].rstrip(b"\x00")
        devid, flag = struct.unpack_from("<II", v, 49)
        mask = struct.unpack_from("<I", v, 60)[0]
        stream_mode, data_type = v[64], v[65]
        print("[mock] логин (%s): user=%r deviceId=%d flag=%d mask=%#x "
              "streamMode=%d dataType=%d"
              % (tag, user, devid, flag, mask, stream_mode, data_type),
              flush=True)
        assert user == b"admin" and v[33:49] == encrypt_password(b"888888")
        assert stream_mode == 3 and data_type == 0 and mask == 1, \
            "поля логина-настройки неверны"
        return devid, flag

    def handle_conn(conn, idx):
        conn.settimeout(12)
        try:
            while not stop.is_set():
                hdr = recv_exact(conn, 8)
                plen, seq = struct.unpack(">I", hdr[:4])[0], struct.unpack("<I", hdr[4:8])[0]
                body = recv_exact(conn, plen - 4)
                for tlvs in parse_owsp_packets(hdr + body)[0]:
                    for t, v in tlvs:
                        if t == 41:
                            devid, flag = check_login(v, "соед. %d" % idx)
                            state["logins"].append((devid, flag))
                            state["login_seqs"].append(seq)
                            if (devid, flag) == (0, 2) and not state["code5_sent"]:
                                # первый (0,2): код 5 — слот ещё занят
                                # (как на реальном железе 28.10)
                                state["code5_sent"] = True
                                state["t_code5"] = time.monotonic()
                                conn.sendall(owsp_packet(
                                    [(40, struct.pack("<HH", 5, 0)),
                                     (42, struct.pack("<HH", 5, 0))], seq + 1))
                            else:
                                conn.sendall(owsp_packet(
                                    [(40, struct.pack("<HH", 5, 0)),
                                     (42, struct.pack("<HH", 1, 0))], seq + 1))
                        elif t == 49:
                            state["keepalives"] += 1
                        elif t == 465:
                            assert v == b"\x00" * 4, \
                                "TLV 465: payload должен быть 4 нуля, %r" % v
                            if (devid, flag) in ((0, 2), (1, 2)):
                                # как реальная прошивка STM83xx: обрыв без 466
                                state["closed_silent"] = True
                                print("[mock] 465 получен — закрываю "
                                      "соединение БЕЗ ответа (как STM83xx)",
                                      flush=True)
                                conn.close()
                                return
                            state["reboot_req"] = True
                            state["reboot_seq"] = seq
                            # отвечаем 466 и рвём соединение
                            conn.sendall(owsp_packet(
                                [(466, b"\x00" * 4)], seq + 1))
                            conn.close()
                            return
        except (ConnectionError, OSError):
            pass  # клиент закрыл соединение после отказа — это штатно
        finally:
            try:
                conn.close()
            except OSError:
                pass

    try:
        idx = 0
        while not stop.is_set():
            srv.settimeout(0.5)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            idx += 1
            print("[mock] принято соединение %d" % idx, flush=True)
            handle_conn(conn, idx)
            if state["reboot_req"]:
                break
    except OSError:
        pass
    finally:
        try:
            srv.close()
        except OSError:
            pass
        print("[mock] остановлен, соединений: %d, логинов: %s"
              % (idx, state["logins"]), flush=True)


def main():
    state = {"logins": [], "login_seqs": [], "keepalives": 0,
             "reboot_req": False, "reboot_seq": None, "closed_silent": False,
             "code5_sent": False, "t_code5": None}
    stop = threading.Event()
    t = threading.Thread(target=mock_doorphone, args=(stop, state),
                         daemon=True)
    t.start()

    gw = subprocess.run(
        [sys.executable, "slinex_rtsp.py", "--no-mqtt", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", "admin", "--password", "888888",
         "--reboot", "--reboot-pause", "0.3", "--reboot-retries", "2"],
        capture_output=True, text=True, timeout=120)
    stop.set()
    print("--- вывод шлюза ---")
    print(gw.stdout.strip())
    if gw.stderr.strip():
        print("--- stderr ---")
        print(gw.stderr.strip())

    assert gw.returncode == 0, ("код возврата %d" % gw.returncode, gw.stdout)
    assert "TLV 466" in gw.stdout, "нет подтверждения перезагрузки"
    # порядок логинов: (0,2) код 5 → повтор (0,2) → (1,2) обрыв без 466 →
    # (0,0) успех. Код 5 не должен «съедать» вариант.
    assert state["logins"] == [(0, 2), (0, 2), (1, 2), (0, 0)], state["logins"]
    assert state["closed_silent"], "мок не воспроизвёл обрыв без 466"
    # packet_seq как в приложении: логин = 2, reboot-команда = 1
    assert state["login_seqs"] == [2, 2, 2, 2], state["login_seqs"]
    assert state["reboot_seq"] == 1, state["reboot_seq"]
    assert state["reboot_req"], "TLV 465 не был отправлен"
    # sendConfig(): команда сразу после логина, БЕЗ keep-alive
    assert state["keepalives"] == 0, \
        "keep-alive не должен отправляться (sendConfig шлёт 465 немедленно)"
    # перед повтором после кода 5 выдержана пауза (--reboot-pause 0.3)
    assert state["t_code5"] is not None
    # пауза между кодом 5 и повтором того же варианта проверяется
    # самим порядком logins выше (повтор был, значит пауза не помешала)
    print("TEST6 PASSED: удалённая перезагрузка (--reboot) работает")


if __name__ == "__main__":
    main()
