#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест 9: MQTT-мост (события звонка + команды unlock/volume).

Компоненты:
- мок MQTT-брокера: минимальный MQTT 3.1.1 (CONNECT→CONNACK,
  SUBSCRIBE→SUBACK, PUBLISH приём/отправка QoS0, PINGREQ→PINGRESP) —
  достаточно для paho-клиента шлюза;
- мок домофона (ittest7-модель + аудио): логин, TLV 203 (µ-law),
  кадры + аудио-пакеты TLV 97+98 каждые 40 мс; по команде теста
  переключает фон на «рингтон» (варбл 400–600 Гц, +44 дБ); TLV 425 →
  ответ 426 result=1; TLV 1054 → проверка структуры → ответ 1055.

Проверяется:
1. шлюз подключается к брокеру (CONNACK/SUBACK), status=online;
2. гудок в аудио канала → публикация {base}/events/ring start и end;
3. HTTP /volume → TLV 1054 на устройство (2 × down) + events/volume;
4. MQTT cmd/unlock → TLV 425 на устройство + events/unlock (ok=true);
5. MQTT cmd/volume → TLV 1054 (2 × up) + events/volume.
"""
import bisect
import json
import math
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, ".")
from slinex_rtsp import (ENC_KEY, ULAW_LINEAR, owsp_packet,  # noqa: E402
                         parse_owsp_packets)

OWSP_PORT = 21009
HTTP_PORT = 28059
RTSP_PORT = 28559
MQTT_PORT = 28883
CONF_FILE = "itest9_mqtt.conf"
BASE = "test/door9"

SPS = bytes.fromhex("6742001e9554050177d0000300090f")
PPS = bytes.fromhex("68ce3c80")
IDR = (b"\x00\x00\x00\x01" + SPS + b"\x00\x00\x00\x01" + PPS
       + b"\x00\x00\x00\x01" + b"\x65" + bytes(range(256)) * 4)
PFRAME = b"\x00\x00\x00\x01" + b"\x41\x9a" + b"\x22" * 700

USER, PASSWORD = "admin", "888888"


def lock_pwd_field(pwd: bytes) -> bytes:
    field = bytearray(32)
    for i in range(min(len(pwd), 32)):
        field[i] = pwd[i] ^ ((ENC_KEY[i % len(ENC_KEY)] + 25) & 0xFF)
    return bytes(field)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


# -- мок MQTT-брокера --------------------------------------------------------

class MockBroker:
    """Минимальный MQTT 3.1.1: достаточно для paho (QoS 0)."""

    def __init__(self, port):
        self.port = port
        self.received = []            # [(topic, payload bytes)]
        self._lock = threading.Lock()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", port))
        self._srv.listen(2)
        self._client_sock = None
        self._stop = threading.Event()
        self.connected = threading.Event()

    def start(self):
        threading.Thread(target=self._serve, daemon=True,
                         name="mqtt-broker").start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                self._srv.settimeout(0.5)
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    @staticmethod
    def _read_packet(sock):
        b1 = recv_exact(sock, 1)[0]
        rl, mult = 0, 1
        while True:
            b = recv_exact(sock, 1)[0]
            rl += (b & 0x7F) * mult
            mult *= 128
            if not (b & 0x80):
                break
        payload = recv_exact(sock, rl) if rl else b""
        return b1, payload

    @staticmethod
    def _varint(n):
        out = bytearray()
        while True:
            b = n % 128
            n //= 128
            if n:
                out.append(b | 0x80)
            else:
                out.append(b)
                return bytes(out)

    def _handle(self, conn):
        self._client_sock = conn
        try:
            while not self._stop.is_set():
                b1, payload = self._read_packet(conn)
                ptype = b1 >> 4
                if ptype == 1:      # CONNECT
                    conn.sendall(b"\x20\x02\x00\x00")
                    self.connected.set()
                elif ptype == 8:    # SUBSCRIBE
                    pkt_id = payload[:2]
                    nqos = 0
                    pos = 2
                    while pos < len(payload):
                        tlen = struct.unpack_from(">H", payload, pos)[0]
                        pos += 2 + tlen + 1
                        nqos += 1
                    conn.sendall(b"\x90" + self._varint(2 + nqos)
                                 + pkt_id + b"\x00" * nqos)
                elif ptype == 3:    # PUBLISH (QoS0)
                    tlen = struct.unpack_from(">H", payload, 0)[0]
                    topic = payload[2:2 + tlen].decode()
                    data = payload[2 + tlen:]
                    with self._lock:
                        self.received.append((topic, data))
                elif ptype == 12:   # PINGREQ
                    conn.sendall(b"\xD0\x00")
                elif ptype == 14:   # DISCONNECT
                    return
        except (ConnectionError, OSError):
            pass

    def publish(self, topic: str, payload: dict):
        """Отправить команду клиенту (шлюзу)."""
        data = json.dumps(payload).encode()
        body = struct.pack(">H", len(topic)) + topic.encode() + data
        pkt = b"\x30" + self._varint(len(body)) + body
        sock = self._client_sock
        if sock is not None:
            sock.sendall(pkt)

    def wait_for(self, topic, pred=None, timeout=15.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                for t, d in self.received:
                    if t == topic and (pred is None or pred(json.loads(d))):
                        return json.loads(d)
            time.sleep(0.2)
        return None

    def stop(self):
        self._stop.set()
        for s in (self._client_sock, self._srv):
            try:
                if s:
                    s.close()
            except OSError:
                pass


# -- генерация µ-law аудио ---------------------------------------------------

_PAIRS = sorted((v, i) for i, v in enumerate(ULAW_LINEAR))
_VALS = [p[0] for p in _PAIRS]


def lin2ulaw(x):
    k = bisect.bisect_left(_VALS, x)
    if k <= 0:
        return _PAIRS[0][1]
    if k >= len(_VALS):
        return _PAIRS[-1][1]
    return (_PAIRS[k - 1][1] if abs(_VALS[k - 1] - x) <= abs(_VALS[k] - x)
            else _PAIRS[k][1])


def audio_chunk(kind, t0):
    """320 сэмплов (40 мс) µ-law: фон или рингтон (варбл 400–600 Гц).

    ЧМ с честной фазой (интеграл частоты) — наивное 2π·f(t)·t даёт
    мгновенную частоту в тысячи Гц и детектор справедливо его не видит.
    """
    random.seed(int(t0 * 7919) & 0xFFFF)
    fm, dev = 0.5, 100.0
    out = bytearray()
    for i in range(320):
        t = t0 + i / 8000.0
        if kind == "ring" and (t % 0.5) < 0.42:
            phase = 2 * math.pi * (500 * t
                                   - dev * math.cos(2 * math.pi * fm * t)
                                   / (2 * math.pi * fm))
            v = 8000.0 * math.sin(phase)
        else:
            v = random.uniform(-60, 60)
        out.append(lin2ulaw(v))
    return bytes(out)


# -- мок домофона ------------------------------------------------------------

def mock_doorphone(stop, state):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", OWSP_PORT))
    srv.listen(4)
    print("[mock] слушает :%d" % OWSP_PORT, flush=True)

    def handle_conn(conn, idx):
        conn.settimeout(15)
        try:
            logged_in = False
            while not stop.is_set() and not logged_in:
                hdr = recv_exact(conn, 8)
                plen = struct.unpack(">I", hdr[:4])[0]
                seq = struct.unpack("<I", hdr[4:8])[0]
                body = recv_exact(conn, plen - 4)
                for tlvs in parse_owsp_packets(hdr + body)[0]:
                    for t, v in tlvs:
                        if t == 41:
                            user = v[1:33].rstrip(b"\x00")
                            devid, flag = struct.unpack_from("<II", v, 49)
                            mask = struct.unpack_from("<I", v, 60)[0]
                            sm, dt = v[64], v[65]
                            print("[mock] логин (%d): user=%r devid=%d "
                                  "flag=%d mask=%#x sm=%d dt=%d"
                                  % (idx, user, devid, flag, mask, sm, dt),
                                  flush=True)
                            logged_in = (user.decode() == USER
                                         and devid == 0 and flag == 0
                                         and mask == 1 and sm == 1
                                         and dt == 2)
            if not logged_in:
                return
            conn.sendall(owsp_packet([
                (40, struct.pack("<HH", 5, 0)),
                (42, struct.pack("<HH", 1, 0)),
                (70, b"MOCK|1|DOOR".ljust(64, b"\x00")),
            ], seq + 1))
            # µ-law (wave=31269 = 0x7A25)
            fmt = (struct.pack("<BBBBIIHH", 1, 1, 2, 0, 1, 1000000, 320, 240)
                   + bytes([15, 0, 0, 0])
                   + struct.pack("<IIHHHHHH", 8000, 64000, 31269, 1, 1,
                                 8, 20, 0))
            conn.sendall(owsp_packet([(203, fmt)], seq + 2))

            def drain():
                rbuf = b""
                conn.settimeout(0.05)
                while not stop.is_set():
                    try:
                        d = conn.recv(65536)
                        if not d:
                            return
                        rbuf += d
                    except socket.timeout:
                        pass
                    except OSError:
                        return
                    packets, rbuf = parse_owsp_packets(rbuf)
                    for tlvs in packets:
                        for t, v in tlvs:
                            if t == 425:
                                ok = (len(v) == 40
                                      and struct.unpack_from("<I", v, 0)[0] == 0
                                      and v[4:36] == lock_pwd_field(
                                          PASSWORD.encode())
                                      and v[36] == 1 and v[37] == 1
                                      and v[38] == 1 and v[39] == 0)
                                state["lock_reqs"].append(ok)
                                print("[mock] TLV 425: структура %s"
                                      % ("верна" if ok else "НЕВЕРНА"),
                                      flush=True)
                                conn.sendall(owsp_packet(
                                    [(426, struct.pack("<HH", 1, 0))], 900))
                            elif t == 1054:
                                ok = (len(v) == 8 and v[1] == 10
                                      and v[2:] == b"\x00" * 6)
                                state["vol_reqs"].append((v[0], ok))
                                print("[mock] TLV 1054: action=%d структура "
                                      "%s" % (v[0], "верна" if ok else "НЕТ"),
                                      flush=True)
                                conn.sendall(owsp_packet(
                                    [(1055, struct.pack("<HH", 1, 0))], 901))
            threading.Thread(target=drain, daemon=True).start()

            frame_idx = 0
            audio_t = 0.0
            next_audio = time.monotonic()
            while not stop.is_set():
                now = time.monotonic()
                if now >= next_audio:
                    kind = ("ring" if now < state.get("ring_until", 0)
                            else "bg")
                    ab = (struct.pack("<HH", 97, 8)
                          + struct.pack("<II", 1, int(audio_t * 1000))
                          + struct.pack("<HH", 98, 320)
                          + audio_chunk(kind, audio_t))
                    conn.sendall(struct.pack(">I", 4 + len(ab))
                                 + struct.pack("<I", 100 + frame_idx) + ab)
                    audio_t += 0.04
                    next_audio += 0.04
                if frame_idx == 0 or audio_t > 0.066 * (frame_idx + 1):
                    frame = IDR if frame_idx % 15 == 0 else PFRAME
                    t = 100 if frame_idx % 15 == 0 else 101
                    fb = struct.pack("<HH", 99, 12) + struct.pack(
                        "<BBHII", 1, 0, 0, frame_idx, frame_idx * 66)
                    fb += struct.pack("<HH", t, 0) + frame
                    conn.sendall(struct.pack(">I", 4 + len(fb))
                                 + struct.pack("<I", 100 + frame_idx) + fb)
                    frame_idx += 1
                time.sleep(0.005)
        except (ConnectionError, OSError, struct.error):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    idx = 0
    try:
        while not stop.is_set():
            srv.settimeout(0.5)
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            idx += 1
            handle_conn(conn, idx)
    except OSError:
        pass
    finally:
        try:
            srv.close()
        except OSError:
            pass


def http_json(method, url, timeout=30):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def main():
    state = {"lock_reqs": [], "vol_reqs": [], "ring_until": 0.0}
    stop = threading.Event()
    broker = MockBroker(MQTT_PORT)
    broker.start()
    threading.Thread(target=mock_doorphone, args=(stop, state),
                     daemon=True).start()

    with open(CONF_FILE, "w") as f:
        f.write("[mqtt]\nenabled = 1\nhost = 127.0.0.1\nport = %d\n"
                "username =\npassword =\nclient_id = itest9-gw\n"
                "base_topic = %s\ntopic_events = events\n"
                "topic_commands = cmd\n" % (MQTT_PORT, BASE))

    gw = subprocess.Popen(
        [sys.executable, "slinex_rtsp.py", "--host", "127.0.0.1",
         "--port", str(OWSP_PORT), "--user", USER, "--password", PASSWORD,
         "--rtsp-port", str(RTSP_PORT), "--http-port", str(HTTP_PORT),
         "--lock-password", PASSWORD, "--config", CONF_FILE],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    fails = []
    try:
        # 1. подключение к брокеру + подписки + status online
        if not broker.connected.wait(10):
            fails.append("шлюз не подключился к MQTT-брокеру")
        else:
            print("[mqtt] CONNACK: шлюз подключился", flush=True)
        # payload статуса — не JSON («online»), ждём сырые байты
        got_online = False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not got_online:
            with broker._lock:
                got_online = any(t == "%s/status" % BASE and d == b"online"
                                 for t, d in broker.received)
            if not got_online:
                time.sleep(0.2)
        if not got_online:
            fails.append("status=online не опубликован")
        else:
            print("[mqtt] status=online опубликован", flush=True)

        # 2. фон — звонка нет; 8 с > ring-warmup 5 с (прогрев детектора
        #    на старте сессии не должен съедать начало гудка в фазе 3)
        time.sleep(8.0)
        with broker._lock:
            ring_events = [t for t, _ in broker.received
                           if t.endswith("/events/ring")]
        if ring_events:
            fails.append("ложный ring на фоне: %s" % ring_events)

        # 3. гудок 4 с → публикация ring start/end
        print("[тест] подаю рингтон на 4 с", flush=True)
        state["ring_until"] = time.monotonic() + 4.0
        rstart = broker.wait_for(
            "%s/events/ring" % BASE,
            lambda d: d.get("state") == "start", timeout=15)
        if not rstart:
            fails.append("events/ring start не опубликован")
        else:
            print("[mqtt] ring start: %s" % rstart, flush=True)
        rend = broker.wait_for(
            "%s/events/ring" % BASE,
            lambda d: d.get("state") == "end", timeout=15)
        if not rend:
            fails.append("events/ring end не опубликован")
        elif rend.get("duration_s", 0) < 3.0:
            fails.append("ring end: длительность подозрительна: %s" % rend)
        else:
            print("[mqtt] ring end: %s" % rend, flush=True)

        # 4. HTTP /volume → 2 × TLV 1054 (down)
        code, body = http_json(
            "POST",
            "http://127.0.0.1:%d/volume?ch=1&dir=down&steps=2" % HTTP_PORT)
        if code != 200 or not body.get("ok"):
            fails.append("HTTP /volume: %s %s" % (code, body))
        else:
            print("[http] /volume down×2: %s" % body.get("msg"), flush=True)
        vol_evt = broker.wait_for("%s/events/volume" % BASE, timeout=10)
        if not (vol_evt and vol_evt.get("ok")):
            fails.append("events/volume (HTTP) не опубликован: %s" % vol_evt)

        # 5. MQTT cmd/unlock → TLV 425 → events/unlock
        broker.publish("%s/cmd/unlock" % BASE,
                        {"channel": 1, "action": 1, "delay": 1})
        unlock_evt = broker.wait_for(
            "%s/events/unlock" % BASE,
            lambda d: d.get("ok") is True, timeout=15)
        if not unlock_evt:
            fails.append("events/unlock ok=true не опубликован")
        else:
            print("[mqtt] cmd unlock → ack: %s" % unlock_evt.get("detail"),
                  flush=True)

        # 6. MQTT cmd/volume → 2 × TLV 1054 (up)
        broker.publish("%s/cmd/volume" % BASE,
                        {"channel": 1, "direction": "up", "steps": 2})
        vol2 = broker.wait_for(
            "%s/events/volume" % BASE,
            lambda d: d.get("direction") == "up", timeout=15)
        if not (vol2 and vol2.get("ok")):
            fails.append("events/volume (up) не опубликован: %s" % vol2)
        else:
            print("[mqtt] cmd volume up×2 → ack: %s" % vol2.get("detail"),
                  flush=True)

        time.sleep(1.0)
        downs = [a for a, ok in state["vol_reqs"] if ok and a == 0]
        ups = [a for a, ok in state["vol_reqs"] if ok and a == 1]
        if len(downs) < 2:
            fails.append("TLV 1054 down пришло %d (нужно 2)" % len(downs))
        if len(ups) < 2:
            fails.append("TLV 1054 up пришло %d (нужно 2)" % len(ups))
        if not state["lock_reqs"] or not all(state["lock_reqs"]):
            fails.append("TLV 425 не получен или структура неверна")

        print("--- вывод шлюза (хвост) ---", flush=True)
    finally:
        stop.set()
        broker.stop()
        try:
            gw.terminate()
            out, _ = gw.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            gw.kill()
            out, _ = gw.communicate()
        print(out[-3000:] if out else "", flush=True)
        if os.path.exists(CONF_FILE):
            os.unlink(CONF_FILE)

    if fails:
        print("TEST9 FAILED: %s" % "; ".join(fails))
        return 1
    print("TEST9 PASSED: MQTT (ring-события, unlock, volume) работает")
    return 0


if __name__ == "__main__":
    sys.exit(main())
