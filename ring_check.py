#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Оффлайн-прогон ring-детектора по pcap-дампу трафика домофона.

Извлекает G.711-аудио (TLV 98) из OWSP-стримов устройства и прогоняет
его через RingDetector шлюза. Используется для калибровки порогов на
реальных записях (тишина не должна давать событий, звонок — должен).

Использование:
    ./ring_check.py tyk.pcap            # все TCP-стримы от устройства
    ./ring_check.py nop.pcap --gain 10 --tonality 8

Зависимость: tshark (Wireshark). Время событий — по таймстампам дампа.
"""
import argparse
import bisect
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from slinex_rtsp import RingDetector, ULAW_LINEAR  # noqa: E402


def mulaw_decode(data: bytes):
    return [ULAW_LINEAR[b] for b in data]


def tshark_streams(pcap, ip_filter):
    cmd = ["tshark", "-r", pcap,
           "-Y", "ip.src==%s && tcp.payload" % ip_filter,
           "-T", "fields", "-e", "frame.time_relative",
           "-e", "tcp.stream", "-e", "tcp.seq", "-e", "tcp.payload"]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True)
    data = {}
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) != 4 or not parts[3]:
            continue
        t, st, seq, hx = parts
        data.setdefault(st, []).append((int(seq), bytes.fromhex(hx), float(t)))
    return data


def reassemble(pkts):
    """Байтовый поток по порядку seq + карта смещение→время."""
    base = min(s for s, _, _ in pkts)

    def off(s):
        return (s - base) % (1 << 32)

    pkts.sort(key=lambda p: off(p[0]))
    stream = bytearray()
    covers = []
    covered = 0
    for seq, hx, t in pkts:
        o = off(seq)
        if o + len(hx) <= covered:
            continue
        if o > len(stream):
            stream += b"\x00" * (o - len(stream))
        stream[o:o + len(hx)] = hx
        covered = max(covered, o + len(hx))
        covers.append((o, o + len(hx), t))
    covers.sort()
    ends = [c[1] for c in covers]
    times = [c[2] for c in covers]

    def atime(x):
        i = bisect.bisect_right(ends, x) - 1
        return times[max(i, 0)]

    return bytes(stream), atime


def extract_audio(stream, atime):
    """TLV 98 (аудио) с проверкой TLV 97 рядом (защита от ложных срабатываний
    в H.264-данных). Возвращает [(время, µ-law байты)]."""
    chunks = []
    j = 0
    n = len(stream)
    while j < n - 8:
        k = stream.find(b"\x62\x00", j)
        if k < 0:
            break
        tl = int.from_bytes(stream[k + 2:k + 4], "little")
        if 8 <= tl <= 8192 and k + 4 + tl <= n:
            if stream.find(b"\x61\x00\x08\x00", max(0, k - 64), k) >= 0 or k == 0:
                chunks.append((atime(k), stream[k + 4:k + 4 + tl]))
        j = k + 1
    return chunks


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap")
    ap.add_argument("--ip", default="192.168.1.50",
                    help="IP домофона (источник аудио)")
    ap.add_argument("--gain", type=float, default=10.0,
                    help="порог над фоном, дБ")
    ap.add_argument("--tonality", type=float, default=8.0)
    ap.add_argument("--start-windows", type=int, default=3)
    ap.add_argument("--end-silence", type=float, default=1.0)
    args = ap.parse_args()

    try:
        data = tshark_streams(args.pcap, args.ip)
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print("ошибка tshark: %r" % exc, file=sys.stderr)
        return 2

    total_events = 0
    for st in sorted(data, key=int):
        stream, atime = reassemble(data[st])
        chunks = extract_audio(stream, atime)
        if not chunks:
            print("стрим %s: аудио не найдено" % st)
            continue
        dur = max(t for t, _ in chunks)
        nbytes = sum(len(d) for _, d in chunks)

        events = []
        cur_t = [0.0]  # время последнего скормленного чанка (события
        # срабатывают синхронно внутри feed → момент ≈ время чанка)

        def on_start(info, cur_t=cur_t):
            events.append((cur_t[0], "start", info))

        def on_end(info, cur_t=cur_t):
            events.append((cur_t[0], "end", info))

        det = RingDetector(on_start=on_start, on_end=on_end,
                           gain_db=args.gain, min_tonality=args.tonality,
                           start_windows=args.start_windows,
                           end_silence_s=args.end_silence)
        for t, d in chunks:
            cur_t[0] = t
            det.feed(d)
        print("стрим %s: %.1f с аудио, %d байт, событий: %d"
              % (st, dur, nbytes, len(events)))
        for t, kind, info in events:
            print("   t=%6.2f  %s  %s" % (t, kind, info))
        total_events += len(events)

    print("итого событий: %d" % total_events)
    return 0


if __name__ == "__main__":
    sys.exit(main())
