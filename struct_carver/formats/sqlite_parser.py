import struct
from typing import List, Tuple
from .base import BaseFormatParser


class SQLiteParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.total_size = 0

    def clone(self) -> 'SQLiteParser':
        new_parser = SQLiteParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0

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

        if not self.is_open:
            start_idx = data.find(b'SQLite format 3\x00')
            if start_idx != -1:
                # needs at least 32 bytes to safely read the page size and page count
                if n - start_idx < 32:
                    return False, False, n, 32 - (n - start_idx)

                self.is_open = True

                # SQLite uses big-endian (>H for unsigned short, >I for unsigned int)
                header_block = data[start_idx:start_idx + 32]
                page_size = struct.unpack('>H', header_block[16:18])[0]
                num_pages = struct.unpack('>I', header_block[28:32])[0]

                if page_size == 1:
                    page_size = 65536  # SQLite specifies that a value of 1 means 65536 bytes

                if page_size == 0 or num_pages == 0:
                    return True, False, 0, 0  # Header is corrupted

                self.total_size = page_size * num_pages
                bytes_remaining = self.total_size - (n - start_idx)

                if bytes_remaining <= 0:
                    return False, True, start_idx + self.total_size, 0

                return False, False, n, bytes_remaining
            else:
                return True, False, 0, 0

        if bytes_remaining > 0:
            if n >= bytes_remaining:
                # the file is completely finished within this chunk!
                return False, True, bytes_remaining, 0
            else:
                # still need more chunks, subtract what we have
                return False, False, n, bytes_remaining - n

        return False, False, n, 0
