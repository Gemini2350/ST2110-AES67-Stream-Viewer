#!/usr/bin/env python3
"""Generate synthetic AES67/ST-2110 test captures (pcap + pcapng).

Streams: A) L24 stereo audio with jitter/loss/reorder, B) clean L16 mono,
C) 2110-20 raw video 128x72 25fps, D) 2110-22 JPEG XS (synthetic codestream),
plus non-RTP noise. Usage: make_test_pcap.py out.pcap out.pcapng
"""
import math
import random
import struct

RATE = 48000
SPP = 48  # 1 ms packets


def eth_ipv4_udp(src_ip, dst_ip, sport, dport, payload):
    eth = b'\x01\x00\x5e\x00\x00\x01' + b'\x02\x11\x22\x33\x44\x55' + b'\x08\x00'
    total = 20 + 8 + len(payload)
    ip = struct.pack('>BBHHHBBH4s4s', 0x45, 0xB8, total, 0x1234, 0x4000, 64, 17, 0,
                     bytes(int(x) for x in src_ip.split('.')),
                     bytes(int(x) for x in dst_ip.split('.')))
    udp = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    return eth + ip + udp + payload


def rtp(seq, ts, ssrc, pt, payload, marker=False):
    b1 = pt | (0x80 if marker else 0)
    return struct.pack('>BBHII', 0x80, b1, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc) + payload


def ptp_msg(mtype, flags, seq, t=None, domain=127):
    """PTPv2 Sync (mtype 0) / Follow_Up (mtype 8), 44 bytes."""
    sec, ns = (int(t), int(round((t - int(t)) * 1e9))) if t is not None else (0, 0)
    return (bytes([mtype & 0x0F, 0x02]) + struct.pack('>H', 44) +
            bytes([domain, 0]) + struct.pack('>H', flags) +
            b'\x00' * 8 + b'\x00' * 4 +
            b'\x11\x22\x33\xff\xfe\x44\x55\x66\x00\x01' +
            struct.pack('>H', seq) + bytes([0, 0]) +
            sec.to_bytes(6, 'big') + struct.pack('>I', ns))


def make_jxs_codestreams(nframes=25, w=1920, h=1080):
    """Synthetic JPEG XS codestreams: valid SOC+PIH, pseudo-random body."""
    rnd = random.Random(7)
    out = []
    for _ in range(nframes):
        body = bytes(rnd.randrange(256) for _ in range(6000))
        pih = struct.pack('>HHIHHHH', 0xFF12, 26, 6000, 0, 0, w, h) + b'\x00' * 10
        out.append(b'\xff\x10' + pih + body)
    return out


def sine_payload(start_frame, nframes, freq, channels, width, amp=0.5):
    out = bytearray()
    for i in range(nframes):
        t = (start_frame + i) / RATE
        for ch in range(channels):
            v = amp * math.sin(2 * math.pi * freq * (ch + 1) * t)
            iv = int(v * (2 ** (width * 8 - 1) - 1))
            out += iv.to_bytes(width, 'big', signed=True)
    return bytes(out)


def build_packets():
    """Return list of (wall_ts, frame_bytes)."""
    pkts = []
    n = 2 * RATE // SPP  # 2 seconds
    # Stream A: L24 stereo, 239.69.1.10:5004, starts near seq/ts wrap
    seq0, ts0 = 65500, 0xFFFFF000
    rnd = random.Random(42)
    for i in range(n):
        if i in (500, 501, 502, 900):  # dropped packets
            continue
        jit = rnd.gauss(0, 0.00015)          # ~0.15 ms network jitter
        if 1200 <= i < 1220:                 # congestion burst: increasing delay
            jit += (i - 1199) * 0.0004
        p = rtp(seq0 + i, ts0 + i * SPP, 0xAABBCC01, 96,
                sine_payload(i * SPP, SPP, 440, 2, 3))
        pkts.append((10.0 + i * 0.001 + jit,
                     eth_ipv4_udp('192.168.1.10', '239.69.1.10', 5004, 5004, p)))
    # swap two packets to test reordering
    pkts[100], pkts[101] = (pkts[100][0], pkts[101][1]), (pkts[101][0], pkts[100][1])
    # Stream B: L16 mono, 239.69.1.20:5004 – PTP-locked timestamps:
    # PTP time = wall + 37 (TAI), rtp_ts = PTP*48000 = (10+37)*48000 + 48*i
    for i in range(n):
        p = rtp(100 + i, 2256000 + 48 * i, 0xAABBCC02, 97,
                sine_payload(i * SPP, SPP, 1000, 1, 2))
        pkts.append((10.0 + i * 0.001, eth_ipv4_udp('192.168.1.11', '239.69.1.20', 5004, 5004, p)))
    # PTP grandmaster: two-step Sync/Follow_Up, 8/s, PTP time = wall + 37 s
    for k in range(16):
        t = 10.0 + k * 0.125
        pkts.append((t, eth_ipv4_udp('192.168.1.250', '224.0.1.129', 319, 319,
                                     ptp_msg(0x0, 0x0200, k))))
        pkts.append((t + 0.002, eth_ipv4_udp('192.168.1.250', '224.0.1.129', 320, 320,
                                             ptp_msg(0x8, 0x0000, k, t + 37.0))))
    # Stream C: ST 2110-20 raw video, 128x72 YCbCr 4:2:2 10bit, 25 fps,
    # each row sent as two SRD packets (offset 0 and 64 px)
    VW, VH = 128, 72
    seqc = 0
    for fr in range(25):
        ts = 900000 + fr * 3600
        rows = []
        for y in range(VH):
            row = b''
            for x in range(0, VW, 2):
                y0 = (64 + x * 6 + y * 8 + fr * 12) % 960
                y1 = (64 + (x + 1) * 6 + y * 8 + fr * 12) % 960
                v = (512 << 30) | (y0 << 20) | (512 << 10) | y1
                row += v.to_bytes(5, 'big')
            rows.append(row)
        pno = 0
        for y in range(VH):
            for half in range(2):
                data = rows[y][half * 160:(half + 1) * 160]
                payload = (struct.pack('>H', 0) +
                           struct.pack('>HHH', len(data), y, half * 64) + data)
                last = (y == VH - 1 and half == 1)
                p = rtp(seqc, ts, 0xAABBCC03, 100, payload, marker=last)
                pkts.append((10.0 + fr * 0.04 + pno * 0.0001,
                             eth_ipv4_udp('192.168.1.12', '239.69.2.10', 5004, 5004, p)))
                seqc += 1
                pno += 1
    # Stream D: ST 2110-22 JPEG XS (synthetic codestream), 25 fps
    seqd = 0
    for fr, cs in enumerate(make_jxs_codestreams()):
        ts = 700000 + fr * 3600
        chunks = [cs[i:i + 1200] for i in range(0, len(cs), 1200)]
        for pi, ch in enumerate(chunks):
            last = pi == len(chunks) - 1
            hdr = (1 << 31) | ((1 if last else 0) << 29) | ((fr % 32) << 22) | pi
            p = rtp(seqd, ts, 0xAABBCC04, 101, struct.pack('>I', hdr) + ch, marker=last)
            pkts.append((10.0 + fr * 0.04 + pi * 0.0002,
                         eth_ipv4_udp('192.168.1.13', '239.69.2.20', 5004, 5004, p)))
            seqd += 1
    # noise: PTP-like multicast UDP (not RTP) + random unicast UDP
    for i in range(50):
        pkts.append((10.0 + i * 0.01, eth_ipv4_udp('192.168.1.1', '224.0.1.129', 319, 319,
                                                   b'\x12\x02' + b'\x00' * 42)))
        pkts.append((10.0 + i * 0.01, eth_ipv4_udp('192.168.1.1', '192.168.1.99', 4000, 4000,
                                                   b'hello world' * 3)))
    pkts.sort(key=lambda x: x[0])
    return pkts


def write_pcap(path, pkts):
    with open(path, 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for ts, data in pkts:
            f.write(struct.pack('<IIII', int(ts), int((ts % 1) * 1e6), len(data), len(data)))
            f.write(data)


def write_pcapng(path, pkts):
    def block(btype, body):
        pad = (-len(body)) % 4
        tl = 12 + len(body) + pad
        return struct.pack('<II', btype, tl) + body + b'\x00' * pad + struct.pack('<I', tl)

    with open(path, 'wb') as f:
        shb = struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)
        f.write(block(0x0A0D0D0A, shb))
        # IDB with if_tsresol = 9 (nanoseconds)
        opts = struct.pack('<HH', 9, 1) + b'\x09\x00\x00\x00' + struct.pack('<HH', 0, 0)
        f.write(block(0x00000001, struct.pack('<HHI', 1, 0, 65535) + opts))
        for ts, data in pkts:
            t = int(ts * 1e9)
            body = struct.pack('<IIIII', 0, t >> 32, t & 0xFFFFFFFF, len(data), len(data)) + data
            f.write(block(0x00000006, body))


if __name__ == '__main__':
    import sys
    pkts = build_packets()
    write_pcap(sys.argv[1], pkts)
    write_pcapng(sys.argv[2], pkts)
    print(f"wrote {len(pkts)} packets")
