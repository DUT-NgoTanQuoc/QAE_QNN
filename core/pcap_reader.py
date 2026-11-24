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
    """Track byte position and require complete reads within the capture."""

    def __init__(self, stream, size):
        self.stream = stream
        self.remaining = size

    def read(self, size):
        if size > self.remaining:
            raise CaptureError("Capture bị cắt giữa packet hoặc block")
        data = self.stream.read(size)
        if len(data) != size:
            raise CaptureError("Capture bị cắt giữa packet hoặc block")
        self.remaining -= size
        return data


def packets(stream, size):
    stream.seek(0)
    bounded = _CaptureStream(stream, size)
    reader = RawPcapReader(bounded)
    classic = hasattr(reader, "nano")
    resolution = Decimal(10**9 if reader.nano else 10**6) if classic else None
    # Scapy's iterator treats some malformed PCAPNG blocks as normal EOF.
    # Stop only at a known file boundary and preserve errors from parsing a record.
    read_record = reader._read_packet if classic else reader._read_block
    while bounded.remaining:
        try:
            record = read_record()
        except EOFError as exc:
            raise CaptureError("Capture chứa packet hoặc block lỗi") from exc
        if record is None:
            continue
        raw, meta = record
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


def decode(raw, linktype):
    try:
        return conf.l2types.num2layer[linktype](raw)
    except Exception:
        if conf.debug_dissector:
            raise
        return conf.raw_layer(raw)
