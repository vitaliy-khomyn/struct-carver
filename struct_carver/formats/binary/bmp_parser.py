import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class BMPParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.total_size = 0

    def clone(self) -> 'BMPParser':
        new_parser = BMPParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0

    def state_tuple(self) -> tuple:
        return (self.is_open, self.total_size)

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'BM']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)

        if not self.is_open:
            start_idx = data.find(b'BM')
            if start_idx != -1:
                # Need at least 6 bytes to parse BM + 4-byte size field
                if n - start_idx < 6:
                    return False, False, n, 6 - (n - start_idx)

                self.is_open = True
                self.total_size = struct.unpack('<I', data[start_idx + 2 : start_idx + 6])[0]

                # Safety boundary check for bitmap files (minimum 54 bytes header)
                if self.total_size < 54 or self.total_size > 100 * 1024 * 1024:
                    return True, False, 0, 0

                bytes_remaining = self.total_size - (n - start_idx)
                if bytes_remaining <= 0:
                    return False, True, start_idx + self.total_size, 0
                return False, False, n, bytes_remaining
            else:
                return True, False, 0, 0

        if bytes_remaining > 0:
            if n >= bytes_remaining:
                return False, True, bytes_remaining, 0
            else:
                return False, False, n, bytes_remaining - n

        return False, False, n, 0
