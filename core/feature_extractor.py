import math
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import dpkt
import pandas as pd
from scapy.all import Ether, IP, TCP, UDP
from scapy.error import Scapy_Exception

from .config import FEATURES
from .pcap_reader import CaptureError, decode, open_capture, packets


def scapy_fields(packet):
    flags = int(packet[TCP].flags) if TCP in packet else -1
    source = packet[IP].src if IP in packet else None
    payload = bytes(packet[TCP].payload) if source is not None and TCP in packet else b""
    return flags, source, b"GET" in payload or b"POST" in payload, UDP in packet


def fast_fields(raw):
    # Mirrors the fast Ethernet path in Train_PCAP_Final cell 8.
    try:
        if len(raw) < 34 or raw[12:14] != b"\x08\x00":
            raise ValueError("Non-standard Ethernet/IPv4")
        ip = dpkt.ip.IP(raw[14:])
        if ip.v != 4 or ip.hl != 5 or ip.len != len(raw) - 14 or ip.mf or ip.offset:
            raise ValueError("Options, fragments, padding or truncation")
        source = ".".join(map(str, ip.src))
        if ip.p == 6 and isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            if tcp.off != 5 or len(tcp) != ip.len - 20:
                raise ValueError("TCP options or unusual length")
            payload = bytes(tcp.data)
            return tcp.flags, source, b"GET" in payload or b"POST" in payload, False
        if ip.p == 17 and isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            if udp.ulen != ip.len - 20 or len(udp) != ip.len - 20:
                raise ValueError("Unusual UDP length")
            return -1, source, False, True
    except (dpkt.UnpackError, ValueError, TypeError, IndexError):
        pass
    return scapy_fields(Ether(raw))


@dataclass
class Window:
    total: int = 0
    syn: int = 0
    syn_ack: int = 0
    ips: Counter = field(default_factory=Counter)
    http: Counter = field(default_factory=Counter)
    udp: int = 0

    def add(self, fields):
        flags, source, http, udp = fields
        self.total += 1
        self.syn += flags == 2
        self.syn_ack += flags == 18
        if source is not None:
            self.ips[source] += 1
            if http:
                self.http[source] += 1
        self.udp += int(udp)

    def row(self, index, seconds):
        entropy = -sum((count / self.total) * math.log2(count / self.total) for count in self.ips.values())
        return (index, index * seconds, (index + 1) * seconds, self.total, self.total,
                self.syn / max(self.syn_ack, 1), len(self.ips), max(self.http.values(), default=0),
                entropy, self.udp)


@dataclass(frozen=True)
class CaptureFeatures:
    windows: pd.DataFrame
    packets: int
    start_epoch_s: float
    duration_s: float


def extract_pcap(source, window=5, progress=None):
    if window <= 0:
        raise ValueError("Window phải dương")
    try:
        with open_capture(source) as stream:
            size = stream.seek(0, 2)
            if not size:
                raise CaptureError("Capture rỗng")
            start, end, count = math.inf, -math.inf, 0
            # First pass determines min/max timestamps even for reordered packets.
            for count, (timestamp, *_) in enumerate(packets(stream, size), 1):
                start, end = min(start, timestamp), max(end, timestamp)
                if progress and count % 8192 == 0:
                    progress(.5 * stream.tell() / size)
            if not count:
                raise CaptureError("Capture không có gói tin")
            full = int((end - start) / window)
            buckets = defaultdict(Window)
            if progress:
                progress(.5)
            for number, (timestamp, raw, linktype, classic) in enumerate(packets(stream, size), 1):
                index = int((timestamp - start) / window)
                if index < full:
                    fields = fast_fields(raw) if classic and linktype == 1 else scapy_fields(decode(raw, linktype))
                    buckets[index].add(fields)
                if progress and number % 8192 == 0:
                    progress(.5 + .5 * stream.tell() / size)
            if progress:
                progress(1.)
    except (OSError, Scapy_Exception, struct.error, IndexError, OverflowError) as exc:
        raise CaptureError(f"Không đọc được PCAP/PCAPNG: {exc}") from exc
    columns = ("window_id", "window_start_s", "window_end_s", "packet_count", *FEATURES)
    rows = [buckets[index].row(index, window) for index in sorted(buckets)]
    return CaptureFeatures(pd.DataFrame(rows, columns=columns), count, start, end - start)
