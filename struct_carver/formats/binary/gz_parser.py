import zlib
from typing import List, Tuple
from ..base import BaseFormatParser


class GZParser(BaseFormatParser):
    engine_type = "binary"
    ext = "gz"

    def __init__(self):
        self.is_open = False
        self.accumulated_data = b""
        self.header_verified = False

    def clone(self) -> 'GZParser':
        new_parser = GZParser()
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
        # GZIP files start with \x1F\x8B and compression method \x08 (Deflate)
        return [b'\x1F\x8B\x08']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            start_idx = data.find(b'\x1F\x8B\x08')
            if start_idx != -1:
                self.is_open = True
                idx = start_idx
            else:
                return True, False, 0, 0

        prev_accum_len = len(self.accumulated_data)
        # Accumulate data
        self.accumulated_data += data[idx:]

        try:
            # wbits = 16 + MAX_WBITS (15) enables automated GZIP header and footer detection
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decompressor.decompress(self.accumulated_data)
            self.header_verified = True
            
            if decompressor.eof:
                unused_len = len(decompressor.unused_data)
                total_size = len(self.accumulated_data) - unused_len
                # Reset accumulated data to match the exact size
                self.accumulated_data = self.accumulated_data[:total_size]
                return False, True, idx + (total_size - prev_accum_len), 0
            else:
                return False, False, n, 0
        except zlib.error:
            # If the format is corrupted, return corrupted flag
            return True, False, 0, 0
