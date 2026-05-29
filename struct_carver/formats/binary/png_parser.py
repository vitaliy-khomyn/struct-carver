import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class PNGParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.bytes_to_skip = 0

    def clone(self) -> 'PNGParser':
        new_parser = PNGParser()
        new_parser.is_open = self.is_open
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        self.is_open = False
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        return (self.is_open, self.bytes_to_skip)

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'\x89PNG\r\n\x1a\n']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'IEND']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if bytes_remaining > 0:
            if n <= bytes_remaining:
                return False, False, n, bytes_remaining - n
            else:
                idx = bytes_remaining
                bytes_remaining = 0

        if not self.is_open:
            start_idx = data.find(b'\x89PNG\r\n\x1a\n')
            if start_idx != -1:
                self.is_open = True
                idx = start_idx + 8
            else:
                return True, False, 0, 0

        if self.bytes_to_skip > 0:
            if n - idx <= self.bytes_to_skip:
                self.bytes_to_skip -= (n - idx)
                return False, False, n, 0
            else:
                idx += self.bytes_to_skip
                self.bytes_to_skip = 0

        while idx < n:
            # Need at least 8 bytes to parse a PNG chunk header (4-byte length + 4-byte type)
            if n - idx < 8:
                return False, False, idx, 8 - (n - idx)

            chunk_len = struct.unpack('>I', data[idx : idx + 4])[0]
            chunk_type = data[idx + 4 : idx + 8]

            # Standard safety check for chunk length to prevent corrupt buffers
            if chunk_len > 100 * 1024 * 1024:  # 100MB chunk safety limit
                return True, False, 0, 0

            # 8 bytes for length/type, chunk_len for data, 4 bytes for CRC
            total_chunk_len = 8 + chunk_len + 4

            if chunk_type == b'IEND':
                # The PNG ends exactly at the end of the IEND chunk (8 bytes + 0 data + 4 CRC = 12 bytes)
                return False, True, idx + 12, 0

            if n - idx < total_chunk_len:
                self.bytes_to_skip = total_chunk_len - (n - idx)
                return False, False, n, 0

            idx += total_chunk_len

        return False, False, n, 0
