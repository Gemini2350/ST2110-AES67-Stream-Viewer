#!/usr/bin/env python3
"""
AES67 PCAP -> WAV extractor & player

Loads .pcap / .pcapng captures, detects RTP audio streams (AES67: L16/L24),
lists them by multicast address and exports selected streams as WAV.
Optional playback with seek bar (requires the 'sounddevice' package).

Pure standard library except for optional 'sounddevice' (playback only).

CLI usage (GUI opens when run without --list/--export):
    aes67_pcap_to_wav.py capture.pcap --list
    aes67_pcap_to_wav.py capture.pcap --export 1 out.wav [--bits 24] [--channels 2] [--rate 48000]
"""

import argparse
import binascii
import os
import queue
import socket
import struct
import sys
import threading
import time
import wave
import zlib
from collections import Counter

STANDARD_RATES = (44100, 48000, 88200, 96000, 176400, 192000)


# ---------------------------------------------------------------------------
# Capture file reading (classic pcap + pcapng), yields (ts_seconds, linktype, frame)
# ---------------------------------------------------------------------------

def iter_capture(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
        if len(magic) < 4:
            raise ValueError("File is too short / empty")
        if magic == b'\x0a\x0d\x0d\x0a':
            f.seek(0)
            yield from _iter_pcapng(f)
        elif magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1',
                       b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1'):
            yield from _iter_pcap(f, magic)
        else:
            raise ValueError("Not a pcap/pcapng file (unknown magic bytes)")


def _iter_pcap(f, magic):
    if magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
        endian = '>'
    else:
        endian = '<'
    nanos = magic in (b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1')
    frac_div = 1e9 if nanos else 1e6
    hdr = f.read(20)
    if len(hdr) < 20:
        return
    _vmaj, _vmin, _tz, _sig, _snap, network = struct.unpack(endian + 'HHiIII', hdr)
    linktype = network & 0x0FFFFFFF
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, incl, _orig = struct.unpack(endian + 'IIII', rec)
        data = f.read(incl)
        if len(data) < incl:
            return
        yield ts_sec + ts_frac / frac_div, linktype, data


def _iter_pcapng(f):
    endian = '<'
    interfaces = []  # list of (linktype, ticks_per_second)
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            return
        btype = struct.unpack(endian + 'I', hdr[0:4])[0]
        if btype == 0x0A0D0D0A:  # Section Header Block: determine endianness first
            bom = f.read(4)
            if len(bom) < 4:
                return
            if bom == b'\x4d\x3c\x2b\x1a':    # 0x1A2B3C4D little endian on disk
                endian = '<'
            elif bom == b'\x1a\x2b\x3c\x4d':  # big endian on disk
                endian = '>'
            else:
                return
            blen = struct.unpack(endian + 'I', hdr[4:8])[0]
            body = f.read(blen - 12)
            if len(body) < blen - 12:
                return
            interfaces = []
            continue
        blen = struct.unpack(endian + 'I', hdr[4:8])[0]
        if blen < 12 or blen > 256 * 1024 * 1024:
            return
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]  # strip trailing block length
        if btype == 0x00000001:  # Interface Description Block
            if len(body) < 8:
                continue
            linktype = struct.unpack(endian + 'H', body[0:2])[0]
            tps = 1_000_000
            # parse options for if_tsresol (code 9)
            opts = body[8:]
            pos = 0
            while pos + 4 <= len(opts):
                code, olen = struct.unpack(endian + 'HH', opts[pos:pos + 4])
                if code == 0:
                    break
                val = opts[pos + 4:pos + 4 + olen]
                if code == 9 and olen >= 1:
                    v = val[0]
                    tps = 2 ** (v & 0x7F) if v & 0x80 else 10 ** v
                pos += 4 + ((olen + 3) & ~3)
            interfaces.append((linktype, tps))
        elif btype == 0x00000006:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            iface, ts_hi, ts_lo, caplen, _orig = struct.unpack(endian + 'IIIII', body[0:20])
            data = body[20:20 + caplen]
            if iface < len(interfaces):
                linktype, tps = interfaces[iface]
            else:
                linktype, tps = 1, 1_000_000
            ts = ((ts_hi << 32) | ts_lo) / tps
            yield ts, linktype, data
        elif btype == 0x00000003:  # Simple Packet Block (no timestamp)
            if len(body) < 4 or not interfaces:
                continue
            origlen = struct.unpack(endian + 'I', body[0:4])[0]
            data = body[4:4 + min(origlen, len(body) - 4)]
            yield 0.0, interfaces[0][0], data
        # all other block types are skipped


# ---------------------------------------------------------------------------
# Frame -> UDP -> RTP
# ---------------------------------------------------------------------------

def _parse_ipv4(data):
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl + 8:
        return None
    total = int.from_bytes(data[2:4], 'big')
    if 20 <= total <= len(data):
        data = data[:total]
    if data[9] != 17:  # UDP only
        return None
    if int.from_bytes(data[6:8], 'big') & 0x1FFF:  # non-first fragment
        return None
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    u = data[ihl:]
    if len(u) < 8:
        return None
    sport = int.from_bytes(u[0:2], 'big')
    dport = int.from_bytes(u[2:4], 'big')
    ulen = int.from_bytes(u[4:6], 'big')
    payload = u[8:ulen] if 8 <= ulen <= len(u) else u[8:]
    return src, sport, dst, dport, payload


def extract_udp(linktype, data):
    """Return (src_ip, sport, dst_ip, dport, udp_payload) or None."""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        et = int.from_bytes(data[12:14], 'big')
        off = 14
        while et in (0x8100, 0x88A8, 0x9100) and len(data) >= off + 4:
            et = int.from_bytes(data[off + 2:off + 4], 'big')
            off += 4
        if et != 0x0800:
            return None
        return _parse_ipv4(data[off:])
    if linktype == 113:  # Linux cooked v1
        if len(data) < 16 or int.from_bytes(data[14:16], 'big') != 0x0800:
            return None
        return _parse_ipv4(data[16:])
    if linktype == 276:  # Linux cooked v2
        if len(data) < 20 or int.from_bytes(data[0:2], 'big') != 0x0800:
            return None
        return _parse_ipv4(data[20:])
    if linktype == 101:  # raw IP
        return _parse_ipv4(data)
    if linktype == 0:  # BSD loopback (4-byte AF, host endian)
        if len(data) < 4 or 2 not in (data[0], data[3]):
            return None
        return _parse_ipv4(data[4:])
    return None


def parse_rtp(data):
    """Return (seq, timestamp, ssrc, pt, payload) or None."""
    if len(data) < 16:
        return None
    b0 = data[0]
    if b0 >> 6 != 2:  # RTP version 2
        return None
    pad = (b0 >> 5) & 1
    ext = (b0 >> 4) & 1
    cc = b0 & 0x0F
    pt = data[1] & 0x7F
    if 72 <= pt <= 76:  # RTCP conflict range
        return None
    seq = int.from_bytes(data[2:4], 'big')
    ts = int.from_bytes(data[4:8], 'big')
    ssrc = int.from_bytes(data[8:12], 'big')
    off = 12 + cc * 4
    if ext:
        if len(data) < off + 4:
            return None
        extlen = int.from_bytes(data[off + 2:off + 4], 'big')
        off += 4 + extlen * 4
    end = len(data)
    if pad:
        p = data[-1]
        if p == 0 or off + p > end:
            return None
        end -= p
    if off >= end:
        return None
    return seq, ts, ssrc, pt, data[off:end]


# ---------------------------------------------------------------------------
# PTP (IEEE 1588): reconstruct grandmaster time from Sync/Follow_Up messages
# ---------------------------------------------------------------------------

def parse_ptp(data):
    """PTPv2 Sync/Follow_Up -> dict, or None."""
    if len(data) < 44 or (data[1] & 0x0F) != 2:
        return None
    mtype = data[0] & 0x0F
    if mtype not in (0x0, 0x8):  # Sync, Follow_Up
        return None
    flags = int.from_bytes(data[6:8], 'big')
    corr = int.from_bytes(data[8:16], 'big', signed=True) / 65536.0  # ns
    sec = int.from_bytes(data[34:40], 'big')
    ns = int.from_bytes(data[40:44], 'big')
    return {'type': 'sync' if mtype == 0 else 'followup',
            'two_step': bool(flags & 0x0200), 'domain': data[4],
            'seq': int.from_bytes(data[30:32], 'big'),
            't': sec + ns / 1e9, 'corr_ns': corr,
            'src': data[20:30].hex()}


class PtpClock:
    """Maps capture wall-clock time to PTP time via linear fit over all
    Sync events (two-step: Follow_Up carries the precise timestamp)."""

    def __init__(self):
        self.points = []   # (sync_wall_ts, ptp_time, src)
        self._pend = {}    # (src, seq) -> sync wall ts (waiting for Follow_Up)
        self._fu = {}      # (src, seq) -> ptp time (Follow_Up seen first)
        self.sources = Counter()
        self.domains = set()
        self.gm = None
        self.n_points = 0
        self.resid_ms = 0.0
        self._fit = None

    def add(self, wall, m):
        key = (m['src'], m['seq'])
        self.domains.add(m['domain'])
        if m['type'] == 'sync':
            self.sources[m['src']] += 1
            if not m['two_step'] and m['t'] > 0:
                self.points.append((wall, m['t'] + m['corr_ns'] / 1e9, m['src']))
            elif key in self._fu:
                self.points.append((wall, self._fu.pop(key), m['src']))
            else:
                self._pend[key] = wall
        else:
            t = m['t'] + m['corr_ns'] / 1e9
            if key in self._pend:
                self.points.append((self._pend.pop(key), t, m['src']))
            else:
                self._fu[key] = t

    def fit(self):
        """Least-squares wall->PTP mapping over the dominant grandmaster."""
        if self._fit is not None:
            return self._fit is not False
        if not self.sources:
            self._fit = False
            return False
        gm = self.sources.most_common(1)[0][0]
        pts = [(w, t) for w, t, s in self.points if s == gm]
        if len(pts) < 2:
            self._fit = False
            return False
        w0 = pts[0][0]
        xs = [w - w0 for w, _ in pts]
        ys = [t for _, t in pts]
        n = len(pts)
        mx, my = sum(xs) / n, sum(ys) / n
        var = sum((x - mx) ** 2 for x in xs)
        if var <= 0:
            self._fit = False
            return False
        b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var
        a = my - b * mx
        resid = [y - (a + b * x) for x, y in zip(xs, ys)]
        self.resid_ms = (sum(r * r for r in resid) / n) ** 0.5 * 1000.0
        self.gm = gm
        self.n_points = n
        self._fit = (w0, a, b)
        return True

    def ptp_at(self, wall):
        w0, a, b = self._fit
        return a + b * (wall - w0)


# ---------------------------------------------------------------------------
# ST 2110 video payloads: RFC 4175 (2110-20 raw) & RFC 9134 (2110-22 JPEG XS)
# ---------------------------------------------------------------------------

VIDEO_CLOCK = 90000

SAMPLINGS = {  # name -> (bytes per pgroup, pixels per pgroup)
    'YCbCr 4:2:2 10 bit': (5, 2),
    'YCbCr 4:2:2 8 bit': (4, 2),
    'RGB 4:4:4 8 bit': (3, 1),
}
DEFAULT_SAMPLING = 'YCbCr 4:2:2 10 bit'
SAMPLING_CLI = {'422-10': 'YCbCr 4:2:2 10 bit', '422-8': 'YCbCr 4:2:2 8 bit',
                'rgb-8': 'RGB 4:4:4 8 bit'}


def parse_rfc4175(payload):
    """RFC 4175 payload -> list of (field, line, offset_px, data), or None."""
    if len(payload) < 10:
        return None
    pos = 2  # extended sequence number
    hdrs = []
    while True:
        if pos + 6 > len(payload) or len(hdrs) > 64:
            return None
        length, lf, of = struct.unpack('>HHH', payload[pos:pos + 6])
        pos += 6
        hdrs.append((length, (lf >> 15) & 1, lf & 0x7FFF, of & 0x7FFF))
        if not (of & 0x8000):
            break
    out = []
    for length, f, line, off in hdrs:
        if length == 0 or pos + length > len(payload):
            return None
        out.append((f, line, off, payload[pos:pos + length]))
        pos += length
    if pos != len(payload):
        return None
    return out


def parse_jxs_header(payload):
    """RFC 9134 payload header -> dict, or None."""
    if len(payload) < 6:
        return None
    b = struct.unpack('>I', payload[0:4])[0]
    return {'last': (b >> 29) & 1, 'frame': (b >> 22) & 0x1F,
            'sep': (b >> 11) & 0x7FF, 'pkt': b & 0x7FF, 'data': payload[4:]}


def jxs_dimensions(codestream):
    """Width/height from the JPEG XS picture header (PIH, marker 0xFF12)."""
    i = codestream.find(b'\xff\x12', 0, 512)
    if i < 0 or i + 16 > len(codestream):
        return None
    w, h = struct.unpack('>HH', codestream[i + 12:i + 16])
    if 16 <= w <= 16384 and 16 <= h <= 8704:
        return w, h
    return None


_LUT_CACHE = {}


def _bt709_luts(bits):
    """Code value -> RGB contribution LUTs (BT.709, limited range)."""
    n = 1 << bits
    ymin, yspan = 16 << (bits - 8), 219 << (bits - 8)
    cmid, cspan = 128 << (bits - 8), 224 << (bits - 8)
    y = [round((v - ymin) * 255.0 / yspan) for v in range(n)]
    rcr = [round(1.5748 * (v - cmid) * 255.0 / cspan) for v in range(n)]
    gcb = [round(-0.1873 * (v - cmid) * 255.0 / cspan) for v in range(n)]
    gcr = [round(-0.4681 * (v - cmid) * 255.0 / cspan) for v in range(n)]
    bcb = [round(1.8556 * (v - cmid) * 255.0 / cspan) for v in range(n)]
    return y, rcr, gcb, gcr, bcb


def ycbcr422_row_to_rgb(row, bits):
    """One row of packed 4:2:2 -> RGB888 (10 bit: 5-byte pgroups Cb Y0 Cr Y1;
    8 bit: UYVY)."""
    if bits not in _LUT_CACHE:
        _LUT_CACHE[bits] = _bt709_luts(bits)
    ylut, rcr, gcb, gcr, bcb = _LUT_CACHE[bits]
    out = bytearray()
    if bits == 10:
        for i in range(0, len(row) - 4, 5):
            v = int.from_bytes(row[i:i + 5], 'big')
            cb = (v >> 30) & 0x3FF
            y0 = (v >> 20) & 0x3FF
            cr = (v >> 10) & 0x3FF
            y1 = v & 0x3FF
            r_, g_, b_ = rcr[cr], gcb[cb] + gcr[cr], bcb[cb]
            for y in (ylut[y0], ylut[y1]):
                out.append(min(255, max(0, y + r_)))
                out.append(min(255, max(0, y + g_)))
                out.append(min(255, max(0, y + b_)))
    else:
        for i in range(0, len(row) - 3, 4):
            cb, y0, cr, y1 = row[i], row[i + 1], row[i + 2], row[i + 3]
            r_, g_, b_ = rcr[cr], gcb[cb] + gcr[cr], bcb[cb]
            for y in (ylut[y0], ylut[y1]):
                out.append(min(255, max(0, y + r_)))
                out.append(min(255, max(0, y + g_)))
                out.append(min(255, max(0, y + b_)))
    return bytes(out)


def decode_raw_frame(packets, row_bytes, height, sampling=DEFAULT_SAMPLING):
    """Reassemble one RFC 4175 frame -> (width, height, rgb888_bytes)."""
    pgb, pgp = SAMPLINGS[sampling]
    width = row_bytes // pgb * pgp
    rows = [bytearray(row_bytes) for _ in range(height)]
    for p in packets:
        for _f, line, off, data in (parse_rfc4175(p) or ()):
            bo = off * pgb // pgp
            if line < height and bo + len(data) <= row_bytes:
                rows[line][bo:bo + len(data)] = data
    rgb = bytearray()
    for r in rows:
        if sampling == 'RGB 4:4:4 8 bit':
            rgb += r[:width * 3]
        else:
            rgb += ycbcr422_row_to_rgb(bytes(r), 10 if '10' in sampling else 8)
    return width, height, bytes(rgb)


def write_png(path, w, h, rgb):
    def chunk(tag, data):
        return (struct.pack('>I', len(data)) + tag + data +
                struct.pack('>I', binascii.crc32(tag + data) & 0xFFFFFFFF))
    raw = b''.join(b'\x00' + rgb[y * w * 3:(y + 1) * w * 3] for y in range(h))
    with open(path, 'wb') as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        f.write(chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0)))
        f.write(chunk(b'IDAT', zlib.compress(raw, 6)))
        f.write(chunk(b'IEND', b''))


def ffmpeg_jxs_to_png(jxs_path, png_path):
    """Decode a .jxs frame via FFmpeg if a JPEG-XS-capable build is installed."""
    import shutil
    import subprocess
    ff = shutil.which('ffmpeg')
    if not ff:
        return False
    try:
        r = subprocess.run([ff, '-v', 'error', '-y', '-i', jxs_path, png_path],
                           capture_output=True, timeout=30)
    except Exception:
        return False
    return r.returncode == 0 and os.path.exists(png_path)


def jxs_ffmpeg_hint(pattern='frame%05d.jxs', fps=25.0):
    """User-facing instructions for decoding exported .jxs frames externally."""
    f = (f"{fps:.2f}".rstrip('0').rstrip('.')) if fps else '25'
    return (
        "Viewing exported JPEG XS frames externally:\n"
        "\n"
        "1. Install an FFmpeg with JPEG XS decoding - a build that includes\n"
        "   the SVT-JPEG-XS plugin (instructions in the repo:\n"
        "   github.com/OpenVisualCloud/SVT-JPEG-XS, folder ffmpeg-plugin;\n"
        "   stock FFmpeg from Homebrew etc. usually can NOT decode JPEG XS).\n"
        "\n"
        "2. Single frame as PNG:\n"
        "   ffmpeg -i frame.jxs image.png\n"
        "\n"
        f"3. Frame sequence as a movie ({f} fps):\n"
        f"   ffmpeg -framerate {f} -i {pattern} -c:v prores_ks movie.mov\n"
        "\n"
        "Alternatively, the SVT project's command-line tool (SvtJpegxsDecApp)\n"
        "decodes individual codestreams without FFmpeg."
    )


def export_video_frames(stream, outdir, sampling=DEFAULT_SAMPLING,
                        indices=None, progress=None):
    """Write frames of a video stream. Raw -> PNG; JPEG XS -> .jxs
    (+ .png alongside when FFmpeg can decode JPEG XS). Returns written paths."""
    frames = stream.frames()
    if indices is None:
        indices = range(len(frames))
    base = f"{stream.dst_ip.replace('.', '-')}_{stream.dst_port}"
    written = []
    try_png = None  # None = unknown, probe on first frame
    if stream.kind == 'video-jxs':
        hint_path = os.path.join(outdir, 'README-JPEG-XS.txt')
        with open(hint_path, 'w', encoding='utf-8') as f:
            f.write(jxs_ffmpeg_hint(f"{base}_frame%05d.jxs", stream.fps) + "\n")
        written.append(hint_path)
    for i in indices:
        if not 0 <= i < len(frames):
            continue
        _ts, pls = frames[i]
        if stream.kind == 'video-raw':
            w, h, rgb = decode_raw_frame(pls, stream.row_bytes, stream.height, sampling)
            path = os.path.join(outdir, f"{base}_frame{i:05d}.png")
            write_png(path, w, h, rgb)
        else:
            cs = b''.join(h['data'] for h in map(parse_jxs_header, pls) if h)
            path = os.path.join(outdir, f"{base}_frame{i:05d}.jxs")
            with open(path, 'wb') as f:
                f.write(cs)
            if try_png is not False:
                ok = ffmpeg_jxs_to_png(path, path[:-4] + '.png')
                if ok:
                    written.append(path[:-4] + '.png')
                if try_png is None:
                    try_png = ok
        written.append(path)
        if progress:
            progress(f"Frame {i + 1}/{len(frames)} exported …")
    return written


# ---------------------------------------------------------------------------
# Stream collection & analysis
# ---------------------------------------------------------------------------

class Stream:
    def __init__(self, dst_ip, dst_port, src_ip, src_port, ssrc, pt):
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.src_port = src_port
        self.ssrc = ssrc
        self.pt = pt
        self.sources = {(src_ip, src_port)}   # all senders seen for this stream
        self.packets = []  # (wall_ts, seq, rtp_ts, payload)
        # filled by analyze():
        self.ordered = []          # (ext_seq, ext_ts, payload) sorted, deduped
        self.ordered_full = []     # (ext_seq, ext_ts, wall_ts, payload) sorted, deduped
        self._arrival = []         # (ext_seq, wall_ts, raw_rtp_ts) in arrival order
        self.samples_per_packet = 0
        self.bytes_per_frame = 0
        self.payload_size = 0
        self.guess_bits = 0
        self.guess_channels = 0
        self.guess_rate = 0
        self.lost = 0
        self.duration = 0.0
        self.kind = 'audio'        # 'audio' | 'video-raw' | 'video-jxs'
        self.fps = 0.0
        self.nframes = 0
        self.width = 0
        self.height = 0
        self.row_bytes = 0

    @property
    def is_multicast(self):
        try:
            return 224 <= int(self.dst_ip.split('.')[0]) <= 239
        except ValueError:
            return False

    def frames(self):
        """Group ordered payloads by RTP timestamp -> [(ext_ts, [payload, ...])]."""
        out = []
        cur = None
        for _e, t, p in self.ordered:
            if t != cur:
                out.append((t, []))
                cur = t
            out[-1][1].append(p)
        return out

    def _detect_video(self):
        """Classify 2110-20 / 2110-22 payloads; fills video fields on success."""
        frames = self.frames()
        # video = several packets per RTP timestamp (frame); audio never has that
        if len(frames) < 2 or len(self.ordered) < len(frames) * 2:
            return False
        probe = self.ordered[:64]
        n4175 = sum(1 for _e, _t, p in probe if parse_rfc4175(p) is not None)
        kind = None
        if n4175 >= max(4, len(probe) * 3 // 4):
            kind = 'video-raw'
        else:
            ok = checked = 0
            for _ts, pls in frames[:16]:
                h = parse_jxs_header(pls[0])
                checked += 1
                if h and h['pkt'] == 0 and h['data'][:2] == b'\xff\x10':
                    ok += 1
            if checked >= 2 and ok >= checked * 3 // 4:
                kind = 'video-jxs'
        if kind is None:
            return False
        deltas = Counter(b[0] - a[0] for a, b in zip(frames, frames[1:]))
        ftd = deltas.most_common(1)[0][0]
        if ftd <= 0:
            return False
        self.kind = kind
        self.guess_rate = VIDEO_CLOCK
        self.samples_per_packet = ftd   # RTP ticks per frame (for timing math)
        self.nframes = len(frames)
        span = frames[-1][0] - frames[0][0]
        self.fps = VIDEO_CLOCK * (len(frames) - 1) / span if span > 0 else 0.0
        if kind == 'video-raw':
            lines = {}
            for p in frames[0][1]:
                for _f, line, _off, data in (parse_rfc4175(p) or ()):
                    lines[line] = lines.get(line, 0) + len(data)
            if lines:
                self.height = max(lines) + 1
                self.row_bytes = max(lines.values())
                pgb, pgp = SAMPLINGS[DEFAULT_SAMPLING]
                self.width = self.row_bytes // pgb * pgp
        else:
            cs = b''.join(h['data'] for h in map(parse_jxs_header, frames[0][1]) if h)
            dim = jxs_dimensions(cs)
            if dim:
                self.width, self.height = dim
        return True

    def analyze(self):
        pkts = self.packets
        if len(pkts) < 2:
            return False
        # unwrap 16-bit sequence numbers in arrival order
        ext = []
        last_seq = pkts[0][1]
        acc = last_seq
        for wall, seq, ts, payload in pkts:
            d = (seq - last_seq + 32768) % 65536 - 32768
            acc += d
            last_seq = seq
            ext.append((acc, wall, ts, payload))
        self._arrival = [(e, w, t) for e, w, t, _p in ext]
        ext.sort(key=lambda e: e[0])
        # dedupe + unwrap 32-bit RTP timestamps in sequence order
        ordered = []
        seen = set()
        last_ts = ext[0][2]
        ts_acc = 0
        for eseq, wall, ts, payload in ext:
            if eseq in seen:
                continue
            seen.add(eseq)
            d = (ts - last_ts) & 0xFFFFFFFF
            if d >= 1 << 31:
                d -= 1 << 32
            ts_acc += d
            last_ts = ts
            ordered.append((eseq, ts_acc, wall, payload))
        self.ordered_full = ordered
        self.ordered = [(e, t, p) for e, t, _w, p in ordered]

        self.payload_size = Counter(len(p) for _e, _t, p in self.ordered).most_common(1)[0][0]
        expected = ordered[-1][0] - ordered[0][0] + 1
        self.lost = max(0, expected - len(ordered))
        if self._detect_video():
            ts_span = ordered[-1][1] - ordered[0][1]
            self.duration = (ts_span + self.samples_per_packet) / self.guess_rate
            return True
        # samples per packet: RTP ts delta between consecutive sequence numbers
        deltas = Counter()
        for a, b in zip(ordered, ordered[1:]):
            dseq = b[0] - a[0]
            dts = b[1] - a[1]
            if dseq > 0 and dts > 0 and dts % dseq == 0:
                deltas[dts // dseq] += 1
        if not deltas:
            return False
        self.samples_per_packet = deltas.most_common(1)[0][0]
        if self.samples_per_packet <= 0 or self.payload_size % self.samples_per_packet:
            return False
        self.bytes_per_frame = self.payload_size // self.samples_per_packet
        bpf = self.bytes_per_frame
        if bpf % 3 == 0:            # AES67 default is L24
            self.guess_bits, self.guess_channels = 24, bpf // 3
        elif bpf % 2 == 0:
            self.guess_bits, self.guess_channels = 16, bpf // 2
        else:
            return False
        # static payload types 10/11: L16 44.1 kHz stereo/mono
        if self.pt in (10, 11) and bpf in (2, 4):
            self.guess_bits, self.guess_channels = 16, bpf // 2

        wall_span = ordered[-1][2] - ordered[0][2]
        ts_span = ordered[-1][1] - ordered[0][1]
        if wall_span > 0 and ts_span > 0:
            raw = ts_span / wall_span
            self.guess_rate = min(STANDARD_RATES, key=lambda r: abs(r - raw))
            if abs(self.guess_rate - raw) / self.guess_rate > 0.10:
                self.guess_rate = max(1, int(round(raw)))
        else:
            self.guess_rate = 48000
        self.duration = (ts_span + self.samples_per_packet) / self.guess_rate
        return True

    def media_desc(self):
        if self.kind == 'audio':
            return f"L{self.guess_bits}, {self.guess_channels} ch, {self.guess_rate} Hz"
        names = {'video-raw': "Raw video (2110-20)", 'video-jxs': "JPEG XS (2110-22)"}
        dim = f", {self.width}×{self.height}" if self.width else ""
        fps = ""
        if self.fps:
            fps = f", {f'{self.fps:.2f}'.rstrip('0').rstrip('.')} fps"
        return names[self.kind] + dim + fps

    def quality(self):
        """Detailed loss/jitter report. Requires analyze() to have succeeded."""
        rate = self.guess_rate or 48000
        spp = self.samples_per_packet or 1
        t0 = self._arrival[0][1]
        # --- arrival order: duplicates, reordering, RFC 3550 jitter -------
        seen = set()
        dups = reordered = 0
        highest = None
        jitter = 0.0            # RFC 3550 interarrival jitter, seconds
        jitter_max = 0.0        # max |D| ever observed
        j_series = []           # (t_rel_s, jitter_ms)
        ia_series = []          # (t_rel_s, interarrival_ms)
        prev_wall = prev_transit = None
        last_raw = self._arrival[0][2]
        ts_acc = 0
        for eseq, wall, raw_ts in self._arrival:
            d = (raw_ts - last_raw) & 0xFFFFFFFF
            if d >= 1 << 31:
                d -= 1 << 32
            ts_acc += d
            last_raw = raw_ts
            if eseq in seen:
                dups += 1
                continue
            seen.add(eseq)
            if highest is not None and eseq < highest:
                reordered += 1
            highest = eseq if highest is None else max(highest, eseq)
            transit = wall - ts_acc / rate
            if prev_transit is not None:
                dd = abs(transit - prev_transit)
                jitter += (dd - jitter) / 16.0
                jitter_max = max(jitter_max, dd)
                ia_series.append((wall - t0, (wall - prev_wall) * 1000.0))
                j_series.append((wall - t0, jitter * 1000.0))
            prev_transit = transit
            prev_wall = wall
        # --- sequence order: loss events -----------------------------------
        events = []             # (first_missing_ext_seq, count, t_in_stream_s, wall_before_gap)
        lost = 0
        of = self.ordered_full
        first_ts = of[0][1]
        for a, b in zip(of, of[1:]):
            gap = b[0] - a[0] - 1
            if gap > 0:
                lost += gap
                events.append((a[0] + 1, gap, (a[1] - first_ts + spp) / rate, a[2]))
        ia = [v for _t, v in ia_series]
        n = len(ia)
        mean = sum(ia) / n if n else 0.0
        std = (sum((v - mean) ** 2 for v in ia) / n) ** 0.5 if n else 0.0
        expected = of[-1][0] - of[0][0] + 1
        return {
            'received': len(of), 'expected': expected, 'lost': lost,
            'loss_pct': 100.0 * lost / expected if expected else 0.0,
            'dups': dups, 'reordered': reordered, 'events': events,
            'jitter_ms': jitter * 1000.0, 'jitter_max_ms': jitter_max * 1000.0,
            'ia_mean_ms': mean, 'ia_std_ms': std,
            'ia_min_ms': min(ia) if ia else 0.0, 'ia_max_ms': max(ia) if ia else 0.0,
            'ia_expected_ms': (1000.0 * spp / rate if self.kind == 'audio'
                               else mean),  # video: packets are sent in bursts per frame

            'ia_series': ia_series, 'jitter_series': j_series,
        }

    def ptp_offsets(self, ptp):
        """Compare RTP timestamps against reconstructed PTP time.
        Returns (series [(t_rel_s, offset_ms)], stats). offset = PTP time at
        arrival minus RTP timestamp time; positive = timestamp lags PTP."""
        rate = self.guess_rate or 48000
        arr = self._arrival
        step = max(1, len(arr) // 4000)
        t0 = arr[0][1]
        series = []
        for _eseq, wall, raw in arr[::step]:
            exp = ptp.ptp_at(wall) * rate
            ei = int(exp)
            d = (raw - ei) & 0xFFFFFFFF
            if d >= 1 << 31:
                d -= 1 << 32
            ticks = d - (exp - ei)          # actual - expected, in RTP ticks
            series.append((wall - t0, -ticks / rate * 1000.0))
        offs = [o for _t, o in series]
        n = len(offs)
        mean = sum(offs) / n
        std = (sum((o - mean) ** 2 for o in offs) / n) ** 0.5
        med = sorted(offs)[n // 2]
        xs = [t for t, _ in series]
        mx = sum(xs) / n
        var = sum((x - mx) ** 2 for x in xs)
        slope = (sum((x - mx) * (o - mean) for (x, _), o in zip(series, offs)) / var
                 if var > 0 else 0.0)       # ms per second
        return series, {'median': med, 'mean': mean, 'std': std,
                        'min': min(offs), 'max': max(offs),
                        'drift_ppm': slope * 1000.0}

    def src_desc(self):
        extra = len(self.sources) - 1
        return f"{self.src_ip}:{self.src_port}" + (f" (+{extra})" if extra > 0 else "")

    def label(self):
        return f"{self.dst_ip}:{self.dst_port} SSRC 0x{self.ssrc:08X}"

    def default_filename(self):
        return f"{self.dst_ip.replace('.', '-')}_{self.dst_port}_ssrc{self.ssrc:08x}.wav"


def collect_streams(path, progress=None):
    streams = {}
    ptp = PtpClock()
    n = 0
    for wall, linktype, frame in iter_capture(path):
        n += 1
        if progress and n % 20000 == 0:
            progress(f"{n:,} packets read …")
        u = extract_udp(linktype, frame)
        if not u:
            # PTP over Ethernet (L2, Ethertype 0x88F7)?
            if linktype == 1 and len(frame) >= 14:
                et = int.from_bytes(frame[12:14], 'big')
                off = 14
                while et in (0x8100, 0x88A8, 0x9100) and len(frame) >= off + 4:
                    et = int.from_bytes(frame[off + 2:off + 4], 'big')
                    off += 4
                if et == 0x88F7:
                    m = parse_ptp(frame[off:])
                    if m:
                        ptp.add(wall, m)
            continue
        src_ip, sport, dst_ip, dport, payload = u
        if dport in (319, 320):
            m = parse_ptp(payload)
            if m:
                ptp.add(wall, m)
            continue
        r = parse_rtp(payload)
        if not r:
            continue
        seq, ts, ssrc, pt, audio = r
        key = (dst_ip, dport, ssrc, pt)
        st = streams.get(key)
        if st is None:
            st = streams[key] = Stream(dst_ip, dport, src_ip, sport, ssrc, pt)
        st.sources.add((src_ip, sport))
        st.packets.append((wall, seq, ts, audio))
    result = [s for s in streams.values() if len(s.packets) >= 5 and s.analyze()]
    result.sort(key=lambda s: (s.dst_ip, s.dst_port, s.ssrc))
    return result, n, (ptp if ptp.fit() else None)


# ---------------------------------------------------------------------------
# PCM rendering (network byte order -> little endian, gaps filled with silence)
# ---------------------------------------------------------------------------

def _swap_to_le(data, width):
    if width == 1:
        return bytes(data)
    usable = len(data) - (len(data) % width)
    data = data[:usable]
    out = bytearray(usable)
    for i in range(width):
        out[i::width] = data[width - 1 - i::width]
    return bytes(out)


def render_pcm(stream, bits=None, channels=None, rate=None):
    """Return (pcm_le_bytes, channels, rate, sampwidth)."""
    if stream.kind != 'audio':
        raise ValueError("Video stream - WAV export/playback is audio only. "
                         "For video use the frame export / video preview.")
    bits = bits or stream.guess_bits
    channels = channels or stream.guess_channels
    rate = rate or stream.guess_rate
    width = bits // 8
    bpf = width * channels
    if bpf <= 0 or not stream.ordered:
        raise ValueError("Stream has no decodable audio data")
    first_ts = stream.ordered[0][1]
    last_ts = stream.ordered[-1][1]
    last_frames = len(stream.ordered[-1][2]) // bpf
    total_frames = (last_ts - first_ts) + max(last_frames, 1)
    if total_frames <= 0 or total_frames * bpf > 1 << 31:
        raise ValueError("Implausible stream length (corrupt RTP timestamps?)")
    buf = bytearray(total_frames * bpf)
    for _eseq, ts, payload in stream.ordered:
        pos = (ts - first_ts) * bpf
        if pos < 0:
            continue
        chunk = _swap_to_le(payload, width)
        end = min(pos + len(chunk), len(buf))
        if pos < end:
            buf[pos:end] = chunk[:end - pos]
    return bytes(buf), channels, rate, width


def export_wav(stream, path, bits=None, channels=None, rate=None):
    pcm, ch, sr, width = render_pcm(stream, bits, channels, rate)
    with wave.open(path, 'wb') as w:
        w.setnchannels(ch)
        w.setsampwidth(width)
        w.setframerate(sr)
        w.writeframes(pcm)
    return len(pcm) // (ch * width), ch, sr, width


def pcm_to_int16(pcm, width):
    """Reduce LE PCM to 16-bit for playback."""
    if width == 2:
        return pcm
    if width == 3:
        out = bytearray(len(pcm) // 3 * 2)
        out[0::2] = pcm[1::3]
        out[1::2] = pcm[2::3]
        return bytes(out)
    raise ValueError("Only 16/24 bit supported")


# ---------------------------------------------------------------------------
# Playback engine (optional, needs sounddevice)
# ---------------------------------------------------------------------------

try:
    import sounddevice as _sd
except Exception:
    _sd = None


class Player:
    def __init__(self):
        self.stream = None
        self.pcm = b''
        self.channels = 2
        self.rate = 48000
        self.frame_bytes = 4
        self.pos = 0          # byte offset, always frame aligned
        self.playing = False
        self.lock = threading.Lock()

    @property
    def available(self):
        return _sd is not None

    def load(self, pcm, channels, rate):
        self.stop()
        self.pcm = pcm
        self.channels = channels
        self.rate = rate
        self.frame_bytes = channels * 2
        self.pos = 0

    @property
    def duration(self):
        if not self.pcm:
            return 0.0
        return len(self.pcm) / self.frame_bytes / self.rate

    @property
    def position(self):
        return self.pos / self.frame_bytes / self.rate

    def seek(self, seconds):
        with self.lock:
            b = int(seconds * self.rate) * self.frame_bytes
            self.pos = max(0, min(b, len(self.pcm)))

    def _callback(self, outdata, frames, _time, _status):
        need = frames * self.frame_bytes
        with self.lock:
            chunk = self.pcm[self.pos:self.pos + need]
            self.pos += len(chunk)
        outdata[:len(chunk)] = chunk
        if len(chunk) < need:
            outdata[len(chunk):] = b'\x00' * (need - len(chunk))
            raise _sd.CallbackStop()

    def play(self):
        if not self.available or not self.pcm:
            return
        self.stop_stream()
        if self.pos >= len(self.pcm):
            self.pos = 0
        self.stream = _sd.RawOutputStream(
            samplerate=self.rate, channels=self.channels, dtype='int16',
            callback=self._callback, finished_callback=self._finished)
        self.stream.start()
        self.playing = True

    def _finished(self):
        self.playing = False

    def pause(self):
        self.stop_stream()

    def stop(self):
        self.stop_stream()
        self.pos = 0

    def stop_stream(self):
        self.playing = False
        s, self.stream = self.stream, None
        if s is not None:
            try:
                s.abort()
                s.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

def run_gui(initial_file=None, selftest=False, shots_dir=None):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title("ST 2110 / AES67 PCAP Stream Viewer")
    root.geometry("1120x560")
    root.minsize(820, 420)

    streams = []
    ptp_holder = [None]   # PtpClock when the capture contains PTP
    player = Player()
    loaded_key = [None]   # which (stream, fmt) is loaded into the player
    msgq = queue.Queue()
    dragging = [False]

    # --- top bar -----------------------------------------------------------
    top = ttk.Frame(root, padding=(10, 8))
    top.pack(fill='x')
    open_btn = ttk.Button(top, text="Open PCAP…")
    open_btn.pack(side='left')
    only_mc = tk.BooleanVar(value=True)
    ttk.Checkbutton(top, text="multicast only", variable=only_mc).pack(side='left', padx=(12, 0))
    file_lbl = ttk.Label(top, text="No file loaded", foreground='gray')
    file_lbl.pack(side='left', padx=12)

    # --- stream table ------------------------------------------------------
    cols = ('addr', 'port', 'src', 'ssrc', 'pt', 'typ', 'pkts', 'lost', 'fmt', 'dur')
    heads = ('Multicast address', 'Port', 'Source', 'SSRC', 'PT', 'Type', 'Packets',
             'Lost', 'Format (detected)', 'Duration')
    widths = (150, 55, 150, 100, 40, 55, 65, 55, 210, 75)
    mid = ttk.Frame(root, padding=(10, 0))
    mid.pack(fill='both', expand=True)
    tree = ttk.Treeview(mid, columns=cols, show='headings', selectmode='extended')
    for c, h, w in zip(cols, heads, widths):
        tree.heading(c, text=h)
        tree.column(c, width=w, anchor='w', stretch=(c in ('addr', 'fmt')))
    vsb = ttk.Scrollbar(mid, orient='vertical', command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side='left', fill='both', expand=True)
    vsb.pack(side='right', fill='y')

    # --- format overrides + export -----------------------------------------
    fmt = ttk.LabelFrame(root, text="Format (Auto = as detected)", padding=(10, 4))
    fmt.pack(fill='x', padx=10, pady=(8, 0))
    ttk.Label(fmt, text="Bit depth:").pack(side='left')
    bits_cb = ttk.Combobox(fmt, values=('Auto', '16', '24'), width=6, state='readonly')
    bits_cb.set('Auto')
    bits_cb.pack(side='left', padx=(4, 14))
    ttk.Label(fmt, text="Channels:").pack(side='left')
    ch_cb = ttk.Combobox(fmt, values=('Auto', '1', '2', '4', '6', '8', '16'), width=6, state='readonly')
    ch_cb.set('Auto')
    ch_cb.pack(side='left', padx=(4, 14))
    ttk.Label(fmt, text="Sample rate:").pack(side='left')
    rate_cb = ttk.Combobox(fmt, values=('Auto',) + tuple(str(r) for r in STANDARD_RATES),
                           width=8, state='readonly')
    rate_cb.set('Auto')
    rate_cb.pack(side='left', padx=(4, 14))
    export_btn = ttk.Button(fmt, text="Export as WAV…", state='disabled')
    export_btn.pack(side='right')
    analyze_btn = ttk.Button(fmt, text="Analysis…", state='disabled')
    analyze_btn.pack(side='right', padx=(0, 8))
    video_btn = ttk.Button(fmt, text="Video…", state='disabled')
    video_btn.pack(side='right', padx=(0, 8))

    def fmt_overrides():
        b = None if bits_cb.get() == 'Auto' else int(bits_cb.get())
        c = None if ch_cb.get() == 'Auto' else int(ch_cb.get())
        r = None if rate_cb.get() == 'Auto' else int(rate_cb.get())
        return b, c, r

    # --- player -------------------------------------------------------------
    pf = ttk.LabelFrame(root, text="Playback", padding=(10, 4))
    pf.pack(fill='x', padx=10, pady=8)
    play_btn = ttk.Button(pf, text="▶ Play", width=9, state='disabled')
    play_btn.grid(row=0, column=0, padx=(0, 4))
    stop_btn = ttk.Button(pf, text="■ Stop", width=8, state='disabled')
    stop_btn.grid(row=0, column=1, padx=(0, 10))
    pos_var = tk.DoubleVar(value=0.0)
    slider = ttk.Scale(pf, from_=0.0, to=1.0, variable=pos_var, state='disabled')
    slider.grid(row=0, column=2, sticky='ew', padx=(0, 10))
    time_lbl = ttk.Label(pf, text="0:00.0 / 0:00.0", width=17)
    time_lbl.grid(row=0, column=3)
    play_lbl = ttk.Label(pf, text="", foreground='gray')
    play_lbl.grid(row=1, column=0, columnspan=4, sticky='w', pady=(2, 0))
    pf.columnconfigure(2, weight=1)
    if not player.available:
        play_lbl.config(text="Playback disabled - package 'sounddevice' missing "
                             "(pip install sounddevice). Export still works.")

    status = ttk.Label(root, text="Ready", padding=(10, 4), foreground='gray')
    status.pack(fill='x', side='bottom')

    def tfmt(sec):
        m, s = divmod(max(0.0, sec), 60)
        return f"{int(m)}:{s:04.1f}"

    def selected_streams():
        return [streams[int(i)] for i in tree.selection()]

    def refresh_table():
        tree.delete(*tree.get_children())
        for i, s in enumerate(streams):
            if only_mc.get() and not s.is_multicast:
                continue
            tag = 'mc' if s.is_multicast else 'uc'
            tree.insert('', 'end', iid=str(i), tags=(tag,), values=(
                s.dst_ip + ('' if s.is_multicast else '  (unicast)'),
                s.dst_port, s.src_desc(), f"0x{s.ssrc:08X}", s.pt,
                'Audio' if s.kind == 'audio' else 'Video',
                len(s.ordered), s.lost, s.media_desc(), tfmt(s.duration)))
        tree.tag_configure('uc', foreground='gray')

    only_mc.trace_add('write', lambda *_: refresh_table())

    # --- loading ------------------------------------------------------------
    def load_file(path):
        player.stop()
        loaded_key[0] = None
        open_btn.config(state='disabled')
        export_btn.config(state='disabled')
        status.config(text=f"Loading {os.path.basename(path)} …")

        def work():
            try:
                result, npkts, ptpc = collect_streams(
                    path, progress=lambda t: msgq.put(('status', t)))
                msgq.put(('done', (path, result, npkts, ptpc)))
            except Exception as e:
                msgq.put(('error', str(e)))
        threading.Thread(target=work, daemon=True).start()

    def poll_queue():
        try:
            while True:
                kind, val = msgq.get_nowait()
                if kind == 'status':
                    status.config(text=val)
                elif kind == 'error':
                    open_btn.config(state='normal')
                    status.config(text="Load failed")
                    messagebox.showerror("Error", val)
                elif kind == 'done':
                    path, result, npkts, ptpc = val
                    streams.clear()
                    streams.extend(result)
                    ptp_holder[0] = ptpc
                    refresh_table()
                    open_btn.config(state='normal')
                    export_btn.config(state='normal' if streams else 'disabled')
                    analyze_btn.config(state='normal' if streams else 'disabled')
                    video_btn.config(
                        state='normal' if any(s.kind != 'audio' for s in streams)
                        else 'disabled')
                    file_lbl.config(text=os.path.basename(path), foreground='')
                    ptxt = (f" · PTP detected ({ptpc.n_points} syncs)"
                            if ptpc else " · no PTP in capture")
                    status.config(text=f"{npkts:,} packets read, "
                                       f"{len(streams)} stream(s) found{ptxt}")
                    if not streams:
                        messagebox.showinfo(
                            "No streams",
                            "No RTP / AES67 / ST 2110 streams detected in this file.")
                    elif selftest:
                        tree.selection_set(tree.get_children()[0])
                        open_analysis()
                        vids = [str(i) for i, st in enumerate(streams)
                                if st.kind != 'audio']
                        if vids:
                            tree.selection_set(vids[0])
                            open_video()
                    elif shots_dir:
                        tree.selection_set(tree.get_children()[0])
                        root.after(600, shots_run)
        except queue.Empty:
            pass
        root.after(100, poll_queue)

    def choose_file():
        path = filedialog.askopenfilename(
            title="Open PCAP file",
            filetypes=[("Capture files", "*.pcap *.pcapng *.cap"), ("All files", "*")])
        if path:
            load_file(path)
    open_btn.config(command=choose_file)

    # --- export -------------------------------------------------------------
    def do_export():
        sel = selected_streams()
        if not sel:
            messagebox.showinfo("Export", "Select one or more streams first.")
            return
        sel = [s for s in sel if s.kind == 'audio']
        if not sel:
            messagebox.showinfo("Export", "Use \"Video…\" to export video streams.")
            return
        b, c, r = fmt_overrides()
        try:
            if len(sel) == 1:
                s = sel[0]
                path = filedialog.asksaveasfilename(
                    title="Save WAV", defaultextension=".wav",
                    initialfile=s.default_filename(),
                    filetypes=[("WAV file", "*.wav")])
                if not path:
                    return
                frames, ch, sr, w = export_wav(s, path, b, c, r)
                status.config(text=f"Exported: {os.path.basename(path)} "
                                   f"({frames:,} frames, {ch} ch, {sr} Hz, {w * 8} bit)")
            else:
                d = filedialog.askdirectory(title="Destination folder for WAV files")
                if not d:
                    return
                for s in sel:
                    export_wav(s, os.path.join(d, s.default_filename()), b, c, r)
                status.config(text=f"Exported {len(sel)} streams to {d}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))
    export_btn.config(command=do_export)

    # --- analysis window ------------------------------------------------------
    def open_analysis():
        sel = selected_streams()
        if not sel:
            messagebox.showinfo("Analysis", "Select a stream first.")
            return None
        s = sel[0]
        q = s.quality()
        ptpc = ptp_holder[0]
        pseries, pstats = (s.ptp_offsets(ptpc) if ptpc else (None, None))
        win = tk.Toplevel(root)
        win.title(f"Analysis – {s.label()}")
        win.geometry("940x760" if pseries else "940x640")
        win.minsize(700, 480)

        info = ttk.Frame(win, padding=(12, 10))
        info.pack(fill='x')
        pairs = (
            ("Source", s.src_desc()),
            ("Packets received", f"{q['received']:,} of {q['expected']:,}"),
            ("Lost", f"{q['lost']:,} ({q['loss_pct']:.3f} %)"),
            ("Duplicates", f"{q['dups']:,}"),
            ("Reordered", f"{q['reordered']:,}"),
            ("Jitter (RFC 3550)", f"{q['jitter_ms']:.3f} ms"),
            ("Max transit deviation", f"{q['jitter_max_ms']:.3f} ms"),
            ("Packet spacing nominal / mean", f"{q['ia_expected_ms']:.3f} / {q['ia_mean_ms']:.3f} ms"),
            ("Spacing min / max / σ", f"{q['ia_min_ms']:.3f} / {q['ia_max_ms']:.3f} / "
                                      f"{q['ia_std_ms']:.3f} ms"),
        )
        if pstats:
            pairs += (
                ("RTP vs. PTP (median)", f"{pstats['median']:+.3f} ms"),
                ("RTP vs. PTP (σ)", f"{pstats['std']:.3f} ms"),
                ("Drift vs. PTP clock", f"{pstats['drift_ppm']:+.2f} ppm"),
                ("PTP reference", f"{ptpc.n_points} syncs, fit ±{ptpc.resid_ms:.2f} ms"),
            )
        elif ptpc is None:
            pairs += (("PTP", "not in capture"),)
        for i, (k, v) in enumerate(pairs):
            r, c = divmod(i, 4)
            cell = ttk.Frame(info)
            cell.grid(row=r, column=c, sticky='w', padx=(0, 28), pady=3)
            ttk.Label(cell, text=k, foreground='gray').pack(anchor='w')
            ttk.Label(cell, text=v, font=('', 14, 'bold')).pack(anchor='w')

        evf = ttk.LabelFrame(win, text=f"Loss events ({len(q['events'])})", padding=(8, 4))
        evf.pack(side='bottom', fill='x', padx=10, pady=(0, 10))
        if q['events']:
            evt = ttk.Treeview(evf, columns=('t', 'wall', 'seq', 'cnt'), show='headings',
                               height=min(6, len(q['events'])))
            for c, h, w in (('t', "Time in stream", 130), ('wall', "Capture time", 150),
                            ('seq', "From seq no.", 120), ('cnt', "Missing packets", 120)):
                evt.heading(c, text=h)
                evt.column(c, width=w, anchor='w')
            esb = ttk.Scrollbar(evf, orient='vertical', command=evt.yview)
            evt.configure(yscrollcommand=esb.set)
            evt.pack(side='left', fill='x', expand=True)
            esb.pack(side='right', fill='y')
            for seq, cnt, tpos, wall in q['events'][:5000]:
                evt.insert('', 'end', values=(
                    f"{tpos:.3f} s",
                    time.strftime('%H:%M:%S', time.localtime(wall)) + f".{int(wall % 1 * 1000):03d}",
                    seq & 0xFFFF, cnt))
        else:
            ttk.Label(evf, text="No packet loss detected ✓").pack(anchor='w')

        cv = tk.Canvas(win, background='white', highlightthickness=0)
        cv.pack(fill='both', expand=True, padx=10, pady=4)
        if pseries:
            cv2 = tk.Canvas(win, background='white', highlightthickness=0, height=170)
            cv2.pack(fill='x', padx=10, pady=(0, 4))

            def draw2(_ev=None):
                cv2.delete('all')
                W, H = cv2.winfo_width(), cv2.winfo_height()
                if W < 120 or H < 60:
                    return
                L, R, T, B = 58, 16, 22, 24
                pw, ph = W - L - R, H - T - B
                tmax = max(pseries[-1][0], 1e-9)
                lo = min(pstats['min'], pstats['median'])
                hi = max(pstats['max'], pstats['median'])
                pad = max((hi - lo) * 0.15, 0.05)
                lo, hi = lo - pad, hi + pad

                def X(t):
                    return L + t / tmax * pw

                def Y(v):
                    return T + ph - (v - lo) / (hi - lo) * ph

                for i in range(4):
                    v = lo + (hi - lo) * i / 3
                    cv2.create_line(L, Y(v), W - R, Y(v), fill='#e8e8e8')
                    cv2.create_text(L - 6, Y(v), text=f"{v:.2f}", anchor='e',
                                    font=('', 9), fill='#666')
                cv2.create_line(L, Y(pstats['median']), W - R, Y(pstats['median']),
                                fill='#999', dash=(4, 3))
                pts, lastpx = [], None
                for t, v in pseries:
                    px = int(X(t))
                    if px != lastpx:
                        pts += [px, Y(v)]
                        lastpx = px
                if len(pts) >= 4:
                    cv2.create_line(*pts, fill='#8e63ce', width=2)
                cv2.create_text(L + 4, 10, anchor='w', font=('', 10), fill='#8e63ce',
                                text="RTP timestamp offset vs. PTP time (ms) — "
                                     "positive = timestamp lags PTP (latency)")
            cv2.bind('<Configure>', draw2)

        def draw(_ev=None):
            cv.delete('all')
            W, H = cv.winfo_width(), cv.winfo_height()
            if W < 120 or H < 80:
                return
            ia_s, j_s = q['ia_series'], q['jitter_series']
            if not ia_s:
                cv.create_text(W // 2, H // 2, text="Too few packets for timing analysis")
                return
            L, R, T, B = 58, 16, 26, 30
            pw, ph = W - L - R, H - T - B
            tmax = max(ia_s[-1][0], 1e-9)
            ymax = max(q['ia_max_ms'], q['ia_expected_ms'] * 1.5, q['jitter_ms'], 0.001) * 1.12

            def X(t):
                return L + t / tmax * pw

            def Y(v):
                return T + ph - min(v, ymax) / ymax * ph

            for i in range(6):  # horizontal grid + ms labels
                v = ymax * i / 5
                cv.create_line(L, Y(v), W - R, Y(v), fill='#e8e8e8')
                cv.create_text(L - 6, Y(v), text=f"{v:.2f}", anchor='e',
                               font=('', 9), fill='#666')
            for i in range(7):  # vertical grid + time labels
                t = tmax * i / 6
                cv.create_line(X(t), T, X(t), H - B, fill='#f2f2f2')
                cv.create_text(X(t), H - B + 6, text=f"{t:.1f}s", anchor='n',
                               font=('', 9), fill='#666')
            for _seq, _cnt, tpos, _wall in q['events']:  # loss markers
                x = X(min(tpos, tmax))
                cv.create_line(x, T, x, H - B, fill='#e05050')
            ye = Y(q['ia_expected_ms'])  # nominal packet spacing
            cv.create_line(L, ye, W - R, ye, fill='#999', dash=(4, 3))
            cols = {}  # interarrival: min/max per pixel column
            for t, v in ia_s:
                px = int(X(t))
                lo, hi = cols.get(px, (v, v))
                cols[px] = (min(lo, v), max(hi, v))
            for px, (lo, hi) in cols.items():
                y1, y2 = Y(hi), Y(lo)
                if y2 - y1 < 1:
                    y2 = y1 + 1
                cv.create_line(px, y1, px, y2, fill='#6fa8dc')
            pts, lastpx = [], None  # jitter curve, one point per pixel
            for t, v in j_s:
                px = int(X(t))
                if px != lastpx:
                    pts += [px, Y(v)]
                    lastpx = px
            if len(pts) >= 4:
                cv.create_line(*pts, fill='#e69138', width=2)
            lx = L
            for txt, colr in (("▮ Packet spacing (ms)", '#6fa8dc'),
                              ("▬ Jitter RFC 3550 (ms)", '#e69138'),
                              ("│ Packet loss", '#e05050'),
                              ("┄ Nominal spacing", '#888')):
                item = cv.create_text(lx, 12, anchor='w', font=('', 10), fill=colr, text=txt)
                lx = cv.bbox(item)[2] + 18
        cv.bind('<Configure>', draw)
        return win

    analyze_btn.config(command=open_analysis)

    # --- video preview window -------------------------------------------------
    def open_video():
        vsel = [s for s in selected_streams() if s.kind != 'audio']
        if not vsel:
            messagebox.showinfo("Video", "Select a video stream first.")
            return None
        s = vsel[0]
        frames = s.frames()
        win = tk.Toplevel(root)
        win.title(f"Video – {s.label()}")
        win.geometry("960x700")
        win.minsize(640, 420)

        top = ttk.Frame(win, padding=(10, 8))
        top.pack(fill='x')
        ttk.Label(top, text=f"{s.media_desc()}, {len(frames)} frames").pack(side='left')
        samp_cb = None
        if s.kind == 'video-raw':
            ttk.Label(top, text="  Sampling:").pack(side='left', padx=(10, 2))
            samp_cb = ttk.Combobox(top, values=list(SAMPLINGS), width=17, state='readonly')
            samp_cb.set(DEFAULT_SAMPLING)
            samp_cb.pack(side='left')
        expall_btn = ttk.Button(top, text="Export all frames…")
        expall_btn.pack(side='right')
        exp1_btn = ttk.Button(top, text="Export frame…")
        exp1_btn.pack(side='right', padx=(0, 8))

        cv = tk.Canvas(win, background='#1c1c1c', highlightthickness=0)
        cv.pack(fill='both', expand=True, padx=10)
        bot = ttk.Frame(win, padding=(10, 4))
        bot.pack(fill='x')
        fvar = tk.DoubleVar(value=0)
        fslider = ttk.Scale(bot, from_=0, to=max(len(frames) - 1, 1), variable=fvar)
        fslider.pack(side='left', fill='x', expand=True, padx=(0, 10))
        flabel = ttk.Label(bot, text="", width=26)
        flabel.pack(side='right')
        vstatus = ttk.Label(win, text="", foreground='gray', padding=(10, 2))
        vstatus.pack(fill='x', pady=(0, 6))

        state = {'job': 0, 'orig': None, 'img': None}
        vq = queue.Queue()

        def cur_sampling():
            return samp_cb.get() if samp_cb else DEFAULT_SAMPLING

        def cur_index():
            return max(0, min(len(frames) - 1, int(round(fvar.get()))))

        def frame_codestream(i):
            return b''.join(h['data'] for h in map(parse_jxs_header, frames[i][1]) if h)

        def fit_image():
            img = state['orig']
            if img is None:
                return
            w, h = img.width(), img.height()
            cw, chh = max(cv.winfo_width(), 64), max(cv.winfo_height(), 64)
            if w > cw or h > chh:
                img = img.subsample(max((w + cw - 1) // cw, (h + chh - 1) // chh))
            elif w * 2 <= cw and h * 2 <= chh:
                img = img.zoom(max(1, min(cw // w, chh // h, 8)))
            state['img'] = img
            cv.delete('all')
            cv.create_image(cv.winfo_width() // 2, cv.winfo_height() // 2, image=img)

        def update_flabel():
            i = cur_index()
            t = (frames[i][0] - frames[0][0]) / VIDEO_CLOCK
            flabel.config(text=f"Frame {i + 1}/{len(frames)}   t = {t:.3f} s")

        def render(i):
            state['job'] += 1
            job = state['job']
            update_flabel()
            if s.kind == 'video-raw':
                vstatus.config(text="Decoding frame …")
                samp = cur_sampling()

                def work():
                    try:
                        w, h, rgb = decode_raw_frame(frames[i][1], s.row_bytes,
                                                     s.height, samp)
                        vq.put((job, 'rgb', (w, h, rgb)))
                    except Exception as e:
                        vq.put((job, 'status', f"Decode error: {e}"))
            else:
                vstatus.config(text="Decoding via FFmpeg …")

                def work():
                    import tempfile
                    try:
                        with tempfile.TemporaryDirectory() as td:
                            jp, pp = os.path.join(td, 'f.jxs'), os.path.join(td, 'f.png')
                            with open(jp, 'wb') as f:
                                f.write(frame_codestream(i))
                            if ffmpeg_jxs_to_png(jp, pp):
                                with open(pp, 'rb') as f:
                                    vq.put((job, 'png', f.read()))
                            else:
                                vq.put((job, 'jxshelp',
                                        "No preview possible: no FFmpeg with a "
                                        "JPEG XS decoder found.\n\n" +
                                        jxs_ffmpeg_hint(fps=s.fps)))
                    except Exception as e:
                        vq.put((job, 'status', f"Decode error: {e}"))
            threading.Thread(target=work, daemon=True).start()

        def vpoll():
            try:
                while True:
                    job, k, val = vq.get_nowait()
                    if job not in (-1, state['job']):
                        continue
                    if k == 'rgb':
                        w, h, rgb = val
                        state['orig'] = tk.PhotoImage(
                            data=b'P6 %d %d 255\n' % (w, h) + rgb)
                        fit_image()
                        vstatus.config(text="")
                    elif k == 'png':
                        state['orig'] = tk.PhotoImage(data=val)
                        fit_image()
                        vstatus.config(text="")
                    elif k == 'jxshelp':
                        state['orig'] = None
                        cv.delete('all')
                        cv.create_text(
                            24, 24, anchor='nw', text=val, fill='#ddd',
                            font=('Menlo', 12), justify='left',
                            width=max(cv.winfo_width() - 48, 300))
                        vstatus.config(text="Analysis and .jxs export still work - "
                                            "these instructions are also written as a "
                                            "text file next to every export.")
                    else:
                        vstatus.config(text=val)
            except queue.Empty:
                pass
            if win.winfo_exists():
                win.after(80, vpoll)

        def do_exp1():
            i = cur_index()
            if s.kind == 'video-raw':
                path = filedialog.asksaveasfilename(
                    parent=win, defaultextension='.png',
                    initialfile=f"{s.default_filename()[:-4]}_frame{i:05d}.png",
                    filetypes=[("PNG", "*.png")])
                if not path:
                    return
                w, h, rgb = decode_raw_frame(frames[i][1], s.row_bytes, s.height,
                                             cur_sampling())
                write_png(path, w, h, rgb)
            else:
                path = filedialog.asksaveasfilename(
                    parent=win, defaultextension='.jxs',
                    initialfile=f"{s.default_filename()[:-4]}_frame{i:05d}.jxs",
                    filetypes=[("JPEG XS Codestream", "*.jxs")])
                if not path:
                    return
                with open(path, 'wb') as f:
                    f.write(frame_codestream(i))
                ffmpeg_jxs_to_png(path, path[:-4] + '.png')  # opportunistic
            vstatus.config(text=f"Exported: {os.path.basename(path)}")

        def do_expall():
            d = filedialog.askdirectory(parent=win, title="Destination folder for frames")
            if not d:
                return
            samp = cur_sampling()

            def work():
                try:
                    files = export_video_frames(
                        s, d, samp, progress=lambda t: vq.put((-1, 'status', t)))
                    vq.put((-1, 'status', f"Exported {len(files)} file(s) to {d}"))
                except Exception as e:
                    vq.put((-1, 'status', f"Export failed: {e}"))
            threading.Thread(target=work, daemon=True).start()

        exp1_btn.config(command=do_exp1)
        expall_btn.config(command=do_expall)
        fslider.config(command=lambda _v: update_flabel())
        fslider.bind('<ButtonRelease-1>', lambda _e: render(cur_index()))
        cv.bind('<Configure>', lambda _e: fit_image())
        if samp_cb:
            samp_cb.bind('<<ComboboxSelected>>', lambda _e: render(cur_index()))
        win.after(80, vpoll)
        win.after(60, lambda: render(0))
        return win

    video_btn.config(command=open_video)

    # --- playback -----------------------------------------------------------
    def ensure_loaded():
        sel = selected_streams()
        if not sel:
            return False
        s = sel[0]
        if s.kind != 'audio':
            messagebox.showinfo("Playback", "Video streams: use \"Video…\" for preview.")
            return False
        key = (id(s), fmt_overrides())
        if loaded_key[0] == key and player.pcm:
            return True
        b, c, r = fmt_overrides()
        try:
            pcm, ch, sr, w = render_pcm(s, b, c, r)
            player.load(pcm_to_int16(pcm, w), ch, sr)
        except Exception as e:
            messagebox.showerror("Playback", str(e))
            return False
        loaded_key[0] = key
        slider.config(to=max(player.duration, 0.001), state='normal')
        play_lbl.config(text=f"Loaded: {s.label()}  –  L{w * 8}, {ch} ch, {sr} Hz")
        return True

    def toggle_play():
        if player.playing:
            player.pause()
            play_btn.config(text="▶ Play")
            return
        if not ensure_loaded():
            return
        player.play()
        play_btn.config(text="⏸ Pause")

    def do_stop():
        player.stop()
        play_btn.config(text="▶ Play")

    play_btn.config(command=toggle_play)
    stop_btn.config(command=do_stop)

    def on_select(_ev=None):
        if player.available and selected_streams():
            play_btn.config(state='normal')
            stop_btn.config(state='normal')
    tree.bind('<<TreeviewSelect>>', on_select)
    tree.bind('<Double-1>', lambda e: toggle_play())

    def slider_press(_ev):
        dragging[0] = True

    def slider_release(_ev):
        dragging[0] = False
        if player.pcm:
            player.seek(pos_var.get())
    slider.bind('<ButtonPress-1>', slider_press)
    slider.bind('<ButtonRelease-1>', slider_release)

    def ui_tick():
        if player.pcm:
            if dragging[0]:
                time_lbl.config(text=f"{tfmt(pos_var.get())} / {tfmt(player.duration)}")
            else:
                pos_var.set(player.position)
                time_lbl.config(text=f"{tfmt(player.position)} / {tfmt(player.duration)}")
            if not player.playing and play_btn.cget('text') != "▶ Play":
                play_btn.config(text="▶ Play")
        root.after(100, ui_tick)

    # --- automated screenshots (hidden --screenshots mode) -------------------
    def shots_shoot(win, name):
        import subprocess
        win.update_idletasks()
        x, y = win.winfo_rootx(), win.winfo_rooty() - 30
        w, h = win.winfo_width(), win.winfo_height() + 30
        subprocess.run(['screencapture', '-x', '-R', f'{x},{y},{w},{h}',
                        os.path.join(shots_dir, name)])

    def shots_run():
        shots_shoot(root, 'main.png')
        aw = open_analysis()
        aw.geometry('+120+90')

        def stage2():
            shots_shoot(aw, 'analysis.png')
            aw.destroy()
            vids = [str(i) for i, st in enumerate(streams) if st.kind != 'audio']
            if not vids:
                root.destroy()
                return
            tree.selection_set(vids[0])
            vw = open_video()
            vw.geometry('+120+90')
            root.after(2000, lambda: (shots_shoot(vw, 'video.png'), root.destroy()))
        root.after(1000, stage2)

    root.after(100, poll_queue)
    root.after(100, ui_tick)
    if initial_file:
        root.after(50, lambda: load_file(initial_file))
    if selftest:
        root.after(4000, root.destroy)
    root.protocol("WM_DELETE_WINDOW", lambda: (player.stop_stream(), root.destroy()))
    root.mainloop()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="ST 2110 / AES67 PCAP stream viewer, extractor & analyzer")
    ap.add_argument('pcap', nargs='?', help="pcap/pcapng file")
    ap.add_argument('--list', action='store_true', help="list streams (no GUI)")
    ap.add_argument('--export', nargs=2, metavar=('N', 'OUT'),
                    help="export stream no. N (from --list) as WAV")
    ap.add_argument('--analyze', type=int, metavar='N',
                    help="loss/jitter/PTP analysis for stream no. N")
    ap.add_argument('--export-frames', nargs=2, metavar=('N', 'DIR'),
                    help="video stream N: export frames (2110-20 -> PNG, "
                         "JPEG XS -> .jxs, + .png if FFmpeg can decode JPEG XS)")
    ap.add_argument('--frames', metavar='A-B',
                    help="frame range for --export-frames, e.g. 0-24")
    ap.add_argument('--sampling', choices=tuple(SAMPLING_CLI), default='422-10',
                    help="pixel format for 2110-20 (default: 422-10)")
    ap.add_argument('--bits', type=int, choices=(16, 24))
    ap.add_argument('--channels', type=int)
    ap.add_argument('--rate', type=int)
    ap.add_argument('--gui-selftest', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--screenshots', metavar='DIR', help=argparse.SUPPRESS)
    args = ap.parse_args()

    if not (args.list or args.export or args.export_frames
            or args.analyze is not None):
        if args.screenshots:
            os.makedirs(args.screenshots, exist_ok=True)
        run_gui(args.pcap, selftest=args.gui_selftest, shots_dir=args.screenshots)
        return

    if not args.pcap:
        ap.error("specify a pcap file")
    streams, npkts, ptpc = collect_streams(args.pcap)
    if args.list:
        ptxt = (f", PTP detected ({ptpc.n_points} syncs, domain "
                f"{'/'.join(str(d) for d in sorted(ptpc.domains))})"
                if ptpc else ", no PTP")
        print(f"{npkts:,} packets, {len(streams)} stream(s){ptxt}:")
        for i, s in enumerate(streams, 1):
            mc = '' if s.is_multicast else ' (unicast)'
            print(f"  [{i}] {s.dst_ip}:{s.dst_port}{mc}  from {s.src_desc()}  "
                  f"SSRC 0x{s.ssrc:08X}  PT {s.pt}  "
                  f"{len(s.ordered)} packets ({s.lost} lost)  "
                  f"{s.media_desc()}  {s.duration:.2f}s")
    if args.analyze is not None:
        n = args.analyze
        if not 1 <= n <= len(streams):
            sys.exit(f"Stream {n} does not exist (1..{len(streams)})")
        s = streams[n - 1]
        q = s.quality()
        print(f"Analysis [{n}] {s.label()}  "
              f"(from {s.src_desc()}, PT {s.pt}, {s.media_desc()})")
        print(f"  Packets:  {q['received']:,} received of {q['expected']:,} expected | "
              f"lost: {q['lost']:,} ({q['loss_pct']:.3f} %) | "
              f"duplicates: {q['dups']} | reordered: {q['reordered']}")
        print(f"  Jitter:   {q['jitter_ms']:.3f} ms (RFC 3550) | "
              f"max transit deviation {q['jitter_max_ms']:.3f} ms")
        print(f"  Spacing:  nominal {q['ia_expected_ms']:.3f} ms | mean {q['ia_mean_ms']:.3f} ms | "
              f"min {q['ia_min_ms']:.3f} | max {q['ia_max_ms']:.3f} | σ {q['ia_std_ms']:.3f} ms")
        if ptpc:
            _ser, ps = s.ptp_offsets(ptpc)
            print(f"  PTP:      RTP timestamp offset vs. PTP: median {ps['median']:+.3f} ms | "
                  f"σ {ps['std']:.3f} ms | min {ps['min']:+.3f} | max {ps['max']:+.3f} ms | "
                  f"drift {ps['drift_ppm']:+.2f} ppm")
            print(f"            (GM {ptpc.gm}, {ptpc.n_points} syncs, "
                  f"fit residual ±{ptpc.resid_ms:.2f} ms)")
        else:
            print("  PTP:      no Sync/Follow_Up messages in capture")
        if q['events']:
            print(f"  Loss events ({len(q['events'])}):")
            for seq, cnt, tpos, _wall in q['events'][:20]:
                print(f"    @ {tpos:8.3f}s  from seq {seq & 0xFFFF}: {cnt} packet(s) missing")
            if len(q['events']) > 20:
                print(f"    … and {len(q['events']) - 20} more")
    if args.export:
        n, out = int(args.export[0]), args.export[1]
        if not 1 <= n <= len(streams):
            sys.exit(f"Stream {n} does not exist (1..{len(streams)})")
        frames, ch, sr, w = export_wav(streams[n - 1], out, args.bits, args.channels, args.rate)
        print(f"OK: {out}  {frames:,} frames, {ch} ch, {sr} Hz, {w * 8} bit")
    if args.export_frames:
        n, outdir = int(args.export_frames[0]), args.export_frames[1]
        if not 1 <= n <= len(streams):
            sys.exit(f"Stream {n} does not exist (1..{len(streams)})")
        s = streams[n - 1]
        if s.kind == 'audio':
            sys.exit(f"Stream {n} is audio - use --export instead")
        indices = None
        if args.frames:
            a, _, b = args.frames.partition('-')
            indices = range(int(a), int(b or a) + 1)
        os.makedirs(outdir, exist_ok=True)
        files = export_video_frames(s, outdir, SAMPLING_CLI[args.sampling], indices)
        print(f"OK: {len(files)} file(s) written to {outdir}")
        if s.kind == 'video-jxs' and not any(p.endswith('.png') for p in files):
            print("\n" + jxs_ffmpeg_hint(fps=s.fps))


if __name__ == '__main__':
    main()
