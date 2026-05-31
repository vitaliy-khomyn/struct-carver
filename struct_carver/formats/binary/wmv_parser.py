import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class WMVParser(BaseFormatParser):
    engine_type = "binary"
    ext = "wmv"

    def __init__(self):
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.header_size = 0
        self.bytes_to_skip = 0

    def clone(self) -> 'WMVParser':
        new_parser = WMVParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.header_size = self.header_size
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.header_size = 0
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.total_size,
            self.header_verified,
            bytes(self.pending_header),
            self.header_size,
            self.bytes_to_skip
        )

    @property
    def header_signatures(self) -> List[bytes]:
        # ASF Header Object GUID
        return [b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            if not self.pending_header:
                start_idx = data.find(b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C')
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 24:
                needed = 24 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 24:
                    return False, False, n, 24 - len(self.pending_header)

            if self.header_size == 0:
                self.header_size = struct.unpack('<Q', self.pending_header[16:24])[0]
                if self.header_size < 30 or self.header_size > 50 * 1024 * 1024:
                    return True, False, 0, 0

            if len(self.pending_header) < self.header_size:
                needed = self.header_size - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < self.header_size:
                    return False, False, n, self.header_size - len(self.pending_header)

            # Accumulate done, verify
            fp_guid = b'\xA1\x5F\xC1\x8C\x4F\x85\xD0\x11\xAC\xB0\x00\xA0\xC9\x03\x49\xBE'
            fp_idx = self.pending_header.find(fp_guid, 24)
            if fp_idx == -1 or fp_idx + 104 > self.header_size:
                return True, False, 0, 0

            # WMV must contain a Video Stream Header GUID.
            # If only an Audio Stream Header GUID is present, this is WMA, not WMV.
            # ASF_Video_Media GUID (little-endian): BC19EFC0-5B4D-11CF-A8FD-00805F5C442B
            video_stream_guid = b'\xC0\xEF\x19\xBC\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B'
            if video_stream_guid not in self.pending_header:
                return True, False, 0, 0

            file_size = struct.unpack('<Q', self.pending_header[fp_idx + 40 : fp_idx + 48])[0]
            self.total_size = file_size
            self.is_open = True
            self.header_verified = True

            if self.total_size < self.header_size or self.total_size > 10 * 1024 * 1024 * 1024:
                return True, False, 0, 0

            self.bytes_to_skip = self.total_size - len(self.pending_header)
            self.pending_header = bytearray()

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
