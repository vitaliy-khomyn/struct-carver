import bz2
from typing import List, Tuple
from ..base import BaseFormatParser


class BZ2Parser(BaseFormatParser):
    engine_type = "binary"
    ext = "bz2"

    def __init__(self):
        self.is_open = False
        self.accumulated_data = b""
        self.header_verified = False

    def clone(self) -> 'BZ2Parser':
        new_parser = BZ2Parser()
        new_parser.is_open = self.is_open
        new_parser.accumulated_data = self.accumulated_data
        new_parser.header_verified = self.header_verified
        return new_parser

    def reset(self):
        self.is_open = False
        self.accumulated_data = b""
        self.header_verified = False

    def state_tuple(self) -> tuple:
        return (self.is_open, len(self.accumulated_data), self.header_verified)

    @property
    def header_signatures(self) -> List[bytes]:
        # BZIP2 starts with 'BZh' and a block size ASCII digit '1' to '9'
        return [b'BZh1', b'BZh2', b'BZh3', b'BZh4', b'BZh5', b'BZh6', b'BZh7', b'BZh8', b'BZh9']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            # Find the header signature
            start_idx = -1
            for sig in self.header_signatures:
                pos = data.find(sig)
                if pos != -1:
                    start_idx = pos
                    break

            if start_idx != -1:
                self.is_open = True
                idx = start_idx
            else:
                return True, False, 0, 0

        prev_accum_len = len(self.accumulated_data)
        # Accumulate data
        self.accumulated_data += data[idx:]

        try:
            decompressor = bz2.BZ2Decompressor()
            decompressor.decompress(self.accumulated_data)
            self.header_verified = True
            
            if decompressor.eof:
                unused_len = len(decompressor.unused_data)
                total_size = len(self.accumulated_data) - unused_len
                self.accumulated_data = self.accumulated_data[:total_size]
                return False, True, idx + (total_size - prev_accum_len), 0
            else:
                return False, False, n, 0
        except OSError:
            # BZ2Decompressor raises OSError (or ValueError) on corrupted streams
            return True, False, 0, 0
