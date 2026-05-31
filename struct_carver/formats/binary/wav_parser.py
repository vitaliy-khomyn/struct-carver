import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class WAVParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def clone(self) -> 'WAVParser':
        new_parser = WAVParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.total_size,
            self.header_verified,
            bytes(self.pending_header),
            self.bytes_to_skip
        )

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
        idx = 0

        if not self.is_open:
            if not self.pending_header:
                # Search for RIFF followed by WAVE at offset +8 to avoid matching AVI chunks
                start_idx = -1
                search_from = 0
                while True:
                    riff_pos = data.find(b'RIFF', search_from)
                    if riff_pos == -1:
                        break
                    if riff_pos + 12 <= n and data[riff_pos + 8 : riff_pos + 12] == b'WAVE':
                        start_idx = riff_pos
                        break
                    search_from = riff_pos + 1
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 12:
                needed = 12 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 12:
                    return False, False, n, 12 - len(self.pending_header)

            header_block = bytes(self.pending_header[:12])
            if header_block[8:12] != b'WAVE':
                return True, False, 0, 0

            riff_size = struct.unpack('<I', header_block[4:8])[0]
            self.total_size = riff_size + 8

            if self.total_size < 12 or self.total_size > 1024 * 1024 * 1024:
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            self.pending_header = bytearray()
            self.bytes_to_skip = self.total_size - 12

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
