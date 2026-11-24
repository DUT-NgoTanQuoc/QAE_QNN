from contextlib import nullcontext
from decimal import Decimal
from pathlib import Path

from scapy.all import RawPcapReader, conf
from scapy.data import MTU


class CaptureError(ValueError):
    pass


def open_capture(source):
    if isinstance(source, (str, Path)):
        return Path(source).open("rb")
    return nullcontext(source)


class _CaptureStream:
    """Bound Scapy's reads by the actual file size and flag partial reads."""

    def __init__(self, stream, size):
        self.stream = stream
        self.size = size

    def read(self, size):
        remaining = self.size - self.stream.tell()
        if 0 < remaining < size:
            raise CaptureError("Capture bị cắt giữa packet hoặc block")
        return self.stream.read(size) if remaining else b""


def packets(stream, size):
    stream.seek(0)
    reader = RawPcapReader(_CaptureStream(stream, size))
    classic = hasattr(reader, "nano")
    resolution = Decimal(10**9 if reader.nano else 10**6) if classic else None
    for raw, meta in reader:
        if classic:
            if len(raw) != min(meta.caplen, MTU):
                raise CaptureError("Capture bị cắt giữa packet")
            timestamp = Decimal(meta.sec) + Decimal(meta.usec) / resolution
            linktype = reader.linktype
        else:
            if meta.tshigh is None:
                raise CaptureError("PCAPNG chứa packet thiếu timestamp")
            timestamp = Decimal((meta.tshigh << 32) + meta.tslow) / meta.tsresol
            linktype = meta.linktype
        yield float(timestamp), raw, linktype, classic
    if stream.tell() != size:
        raise CaptureError("Capture chứa packet hoặc block lỗi")


def decode(raw, linktype):
    try:
        return conf.l2types.num2layer[linktype](raw)
    except Exception:
        if conf.debug_dissector:
            raise
        return conf.raw_layer(raw)
