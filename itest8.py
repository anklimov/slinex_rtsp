#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Тест 8: ring-детектор (юнит) + TLV 1054 (структура).

Детектор звонка по аудио валидирован на реальных дампах (tyk.pcap —
звонок, nop.pcap — фон); здесь — те же инварианты на синтетике:
- фон (тихий шум) — 0 событий;
- «рингтон» (варблирующий синус 400–600 Гц, огибающая 0.42/0.5 с,
  +40 дБ над фоном) — ровно один start + один end, адекватная
  длительность, частота в диапазоне;
- громкий широкополосный шум — 0 событий (тональность R < порога);
- «речь» (форманты + шум) — 0 событий;
- короткий тон 0.15 с — 0 событий (нужно 3 окна подряд).

Плюс таблица µ-law (нулевые коды, максимумы, монотонность половин)
и build_volume_req (8 байт: action/volume=10/reserve).
"""
import bisect
import math
import random
import sys
import time

sys.path.insert(0, ".")
from slinex_rtsp import (ULAW_LINEAR, RingDetector,  # noqa: E402
                         build_volume_req)

FAIL = []


def check(cond, msg):
    print("  [%s] %s" % ("+" if cond else "FAIL", msg))
    if not cond:
        FAIL.append(msg)


# -- µ-law таблица ----------------------------------------------------------

def test_ulaw_table():
    print("таблица µ-law:")
    check(ULAW_LINEAR[0x7F] == 0 and ULAW_LINEAR[0xFF] == 0,
          "0x7F и 0xFF — нули")
    check(ULAW_LINEAR[0x80] == 32124 and ULAW_LINEAR[0x00] == -32124,
          "максимумы ±32124 (0x80=+, 0x00=−)")
    pos = [ULAW_LINEAR[b] for b in range(0x80, 0x100)]
    neg = [ULAW_LINEAR[b] for b in range(0x00, 0x80)]
    check(all(pos[i] > pos[i + 1] for i in range(len(pos) - 1)),
          "положительная половина монотонна")
    check(all(neg[i] < neg[i + 1] for i in range(len(neg) - 1)),
          "отрицательная половина монотонна")


# -- TLV 1054 ----------------------------------------------------------------

def test_volume_req():
    print("build_volume_req:")
    up = build_volume_req(1)
    down = build_volume_req(0)
    check(len(up) == 8 and len(down) == 8, "8 байт")
    check(up[0] == 1 and up[1] == 10 and up[2:] == b"\x00" * 6,
          "up: action=1, volume=10, reserve нули (%s)" % up.hex())
    check(down[0] == 0 and down[1] == 10 and down[2:] == b"\x00" * 6,
          "down: action=0, volume=10, reserve нули (%s)" % down.hex())


# -- генераторы µ-law -------------------------------------------------------

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


def warble_phase(t):
    """Фаза ЧМ-варбла 400–600 Гц: честный интеграл частоты."""
    fm, dev = 0.5, 100.0
    return 2 * math.pi * (500 * t - dev * math.cos(2 * math.pi * fm * t)
                         / (2 * math.pi * fm))


def gen(seg_len_s, kind, seed=42):
    random.seed(seed)
    out = bytearray()
    for i in range(int(seg_len_s * 8000)):
        t = i / 8000.0
        if kind == "bg":                      # тихий уличный фон
            v = random.uniform(-60, 60)
        elif kind == "ring":                  # рингтон: варбл 400–600 Гц
            if (t % 0.5) < 0.42:
                v = 8000.0 * math.sin(warble_phase(t))
            else:
                v = random.uniform(-60, 60)
        elif kind == "tone-cont":             # непрерывный чистый синус
            v = 8000.0 * math.sin(2 * math.pi * 700 * t)
        elif kind == "burst":                 # громкий широкополосный
            v = random.uniform(-8000, 8000)
        elif kind == "speech":                # речь-подобное
            v = (2000 * math.sin(2 * math.pi * 480 * t)
                 + 1000 * math.sin(2 * math.pi * 160 * t)
                 + random.uniform(-1000, 1000))
        else:
            raise ValueError(kind)
        out.append(lin2ulaw(v))
    return bytes(out)


def make_detector(events):
    return RingDetector(
        on_start=lambda info: events.append(("start", info)),
        on_end=lambda info: events.append(("end", info)))


def test_detector():
    print("детектор — негативные сценарии (событий быть не должно):")
    for kind, length in (("bg", 12.0), ("burst", 2.0), ("speech", 3.0)):
        events = []
        det = make_detector(events)
        det.feed(gen(length, kind))
        check(not events,
              "%s %.1f с → 0 событий (было: %s)" % (kind, length, events))
    events = []
    det = make_detector(events)
    det.feed(gen(0.15, "ring"))   # 0.15 с < 3 окна
    det.feed(gen(2.0, "bg"))
    check(not events, "короткий тон 0.15 с → 0 событий")

    print("детектор — рингтон 5 с:")
    events = []
    det = make_detector(events)
    det.feed(gen(4.0, "bg"))
    check(not events, "фон до звонка: 0 событий")
    det.feed(gen(5.0, "ring"))
    det.feed(gen(2.5, "bg"))         # после гудка — тишина (end через ~1 с)
    starts = [e for e in events if e[0] == "start"]
    ends = [e for e in events if e[0] == "end"]
    check(len(starts) == 1, "ровно один start (%s)" % (starts,))
    check(len(ends) == 1, "ровно один end (%s)" % (ends,))
    if starts:
        info = starts[0][1]
        check(400 <= (info.get("freq") or 0) <= 650,
              "частота старта в диапазоне рингтона: %s" % info)
        check(info.get("gain_db", 0) >= 20, "гейн над фоном ≥20 дБ: %s" % info)
    if starts and ends:
        dur = ends[0][1].get("duration_s")
        check(4.0 <= dur <= 6.5,
              "длительность 4.0–6.5 с (5 с тон ± старт/конец): %s" % dur)

    print("детектор — параметры:")
    events = []
    det2 = RingDetector(lambda i: events.append(("s", i)),
                        lambda i: events.append(("e", i)),
                        start_windows=5, end_silence_s=0.5)
    det2.feed(gen(0.5, "bg"))          # сначала базлайн (как в бою)
    det2.feed(gen(0.8, "tone-cont"))   # 8 окон > start_windows=5
    check(any(e[0] == "s" for e in events),
          "start_windows=5: непрерывный тон 0.8 с — старт (%s)" % (events,))
    det2.feed(gen(1.5, "bg"))
    check(any(e[0] == "e" for e in events),
          "end_silence=0.5: конец пришёл (%s)" % (events,))

    print("детектор — старт шлюза ВО ВРЕМЯ звонка (snap базлайна):")
    events = []
    det3 = make_detector(events)
    det3.feed(gen(2.0, "ring"))       # первый громкий окно попадает в базлайн
    first = [e for e in events if e[0] == "start"]
    check(len(first) == 0,
          "звонок до установления базлайна не детектится (ок): %s" % (first,))
    det3.feed(gen(1.0, "bg"))         # тишина: базлайн снапается вниз
    det3.feed(gen(2.0, "ring"))       # следующий звонок ловится
    second = [e for e in events if e[0] == "start"]
    check(len(second) == 1,
          "после сброса базлайна звонок детектится: %s" % (second,))


def test_warmup():
    """Прогрев (наблюдение 31.10: стартовая транзиентка аудиотракта
    дала ложный ring 450 Гц/+18.6 дБ; end не пришёл — аудио замолчало)."""
    print("детектор — прогрев (warmup_s):")
    # тон в первые секунды (транзиентка) → событие НЕ стреляет
    events = []
    det = RingDetector(lambda i: events.append(("s", i)),
                       lambda i: events.append(("e", i)),
                       warmup_s=2.0)
    det.feed(gen(1.5, "tone-cont"))   # громкий тон внутри прогрева
    check(not events,
          "тон внутри прогрева (1.5 с < warmup 2 с) → 0 событий: %s"
          % (events,))
    # после прогрева тот же тон детектится
    det.feed(gen(0.3, "bg"))           # добить прогрев + базлайн
    det.feed(gen(0.8, "tone-cont"))
    check(any(e[0] == "s" for e in events),
          "после прогрева тон детектится: %s" % (events,))
    # rearm(): новый прогрев на рестарте сессии
    events.clear()
    det.rearm()
    det.feed(gen(1.0, "tone-cont"))    # снова внутри прогрева
    check(not events, "rearm() снова гасит тон на прогреве: %s" % (events,))
    # warmup=0 (по умолчанию) — поведение прежнее
    events = []
    det0 = make_detector(events)
    det0.feed(gen(0.5, "bg"))           # базлайн
    det0.feed(gen(0.8, "tone-cont"))
    check(any(e[0] == "start" for e in events),
          "warmup=0 (умолчание): тон сразу детектится: %s" % (events,))


def test_ring_stuck_cap():
    """Принудительный end по таймауту (Gateway), если аудио замолчало."""
    print("gateway — страховка зависшего звонка:")
    from slinex_rtsp import Gateway
    gw = Gateway("unused", 1, "u", "p", channels=[1],
                 ring_max_s=0.05)          # не подключается никуда
    evts = []
    gw._add_event = lambda kind, detail: evts.append((kind, dict(detail)))
    gw._ring_active = True
    gw._ring_channels = {1, 4}
    gw._ring_t0 = time.time() - 10.0       # «активен» уже 10 с
    gw._finish_ring(stuck=True)
    check(len(evts) == 1 and evts[0][1].get("stuck") is True
          and evts[0][1].get("state") == "end"
          and evts[0][1].get("duration_s", 0) >= 10,
          "принудительный end: stuck=true, каналы, длительность (%s)" % (evts,))
    check(not gw._ring_active, "после принудительного end не активен")


def main():
    test_ulaw_table()
    test_volume_req()
    test_detector()
    test_warmup()
    test_ring_stuck_cap()
    if FAIL:
        print("TEST8 FAILED: %s" % "; ".join(FAIL))
        return 1
    print("TEST8 PASSED: ring-детектор и TLV 1054 работают")
    return 0


if __name__ == "__main__":
    sys.exit(main())
