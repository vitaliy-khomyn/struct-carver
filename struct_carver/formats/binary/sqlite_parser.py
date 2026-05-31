import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class SQLiteParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def clone(self) -> 'SQLiteParser':
        new_parser = SQLiteParser()
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
        return [b'SQLite format 3\x00']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []  # SQLite relies entirely on the header-defined length

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            if not self.pending_header:
                start_idx = data.find(b'SQLite format 3\x00')
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 32:
                needed = 32 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 32:
                    return False, False, n, 32 - len(self.pending_header)

            # Process 32-byte header
            header_block = bytes(self.pending_header[:32])
            page_size = struct.unpack('>H', header_block[16:18])[0]
            num_pages = struct.unpack('>I', header_block[28:32])[0]

            if page_size == 1:
                page_size = 65536  # SQLite specifies that a value of 1 means 65536 bytes

            if page_size == 0 or num_pages == 0:
                return True, False, 0, 0  # Header is corrupted

            self.total_size = page_size * num_pages
            
            # Safety check
            if self.total_size > 10 * 1024 * 1024 * 1024:
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            
            self.pending_header = bytearray()
            self.bytes_to_skip = self.total_size - 32

        # Skip bytes
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
