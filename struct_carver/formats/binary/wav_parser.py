import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class WAVParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.total_size = 0

    def clone(self) -> 'WAVParser':
        new_parser = WAVParser()
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
        return [b'RIFF']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)

        if not self.is_open:
            start_idx = data.find(b'RIFF')
            if start_idx != -1:
                # Need at least 12 bytes to read size and 'WAVE'
                if n - start_idx < 12:
                    return False, False, n, 12 - (n - start_idx)

                # Validate format 'WAVE'
                if data[start_idx + 8 : start_idx + 12] != b'WAVE':
                    return True, False, 0, 0

                self.is_open = True
                riff_size = struct.unpack('<I', data[start_idx + 4 : start_idx + 8])[0]
                self.total_size = riff_size + 8

                # Safety check
                if self.total_size < 12 or self.total_size > 1024 * 1024 * 1024: # 1GB safety limit
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
