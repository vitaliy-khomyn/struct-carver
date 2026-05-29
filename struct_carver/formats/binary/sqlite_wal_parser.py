import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class SQLiteWALParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.page_size = 0
        self.salt1 = 0
        self.salt2 = 0
        self.endian = '>'

    def clone(self) -> 'SQLiteWALParser':
        new_parser = SQLiteWALParser()
        new_parser.is_open = self.is_open
        new_parser.page_size = self.page_size
        new_parser.salt1 = self.salt1
        new_parser.salt2 = self.salt2
        new_parser.endian = self.endian
        return new_parser

    def reset(self):
        self.is_open = False
        self.page_size = 0
        self.salt1 = 0
        self.salt2 = 0
        self.endian = '>'

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            sig1 = data.find(b'\x37\x7f\x06\x82')
            sig2 = data.find(b'\x37\x7f\x06\x83')

            valid_sigs = [p for p in [sig1, sig2] if p != -1]
            if not valid_sigs:
                return True, False, 0, 0

            start_idx = min(valid_sigs)
            if n - start_idx < 32:
                return False, False, n, 32 - (n - start_idx)

            self.is_open = True
            header_block = data[start_idx:start_idx + 32]

            # magic bytes dictate if integers are packed as little (<) or big (>) endian
            magic = header_block[0:4]
            self.endian = '<' if magic == b'\x37\x7f\x06\x82' else '>'

            self.page_size = struct.unpack(f'{self.endian}I', header_block[8:12])[0]
            self.salt1, self.salt2 = struct.unpack(f'{self.endian}II', header_block[16:24])

            if self.page_size == 0:
                return True, False, 0, 0

            idx = start_idx + 32

        if bytes_remaining > 0:
            if n - idx <= bytes_remaining:
                return False, False, n, bytes_remaining - (n - idx)
            else:
                idx += bytes_remaining
                bytes_remaining = 0

        # continuously validate the frame boundaries using the Salt session IDs
        while idx < n:
            if n - idx < 24:
                # not enough bytes to validate the frame header inline.
                # safely skip the rest of this frame (header + page_size) to re-align on the next frame.
                frame_total_size = 24 + self.page_size
                return False, False, n, frame_total_size - (n - idx)

            frame_header = data[idx:idx + 24]
            frame_salt1, frame_salt2 = struct.unpack(f'{self.endian}II', frame_header[8:16])

            if frame_salt1 != self.salt1 or frame_salt2 != self.salt2:
                # Frame mismatch! In SQLite WAL, a salt mismatch indicates the end of the log session (EOF).
                return False, True, idx, 0

            frame_total_size = 24 + self.page_size
            if n - idx < frame_total_size:
                return False, False, n, frame_total_size - (n - idx)

            idx += frame_total_size

        return False, False, n, 0
