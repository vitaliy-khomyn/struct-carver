from typing import List, Tuple
from ..base import BaseFormatParser


class TARParser(BaseFormatParser):
    engine_type = "binary"
    ext = "tar"

    def __init__(self):
        self.is_open = False
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.zero_blocks_seen = 0
        self.header_verified = False
        self.pending_header = bytearray()

    def clone(self) -> 'TARParser':
        new_parser = TARParser()
        new_parser.is_open = self.is_open
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.current_offset = self.current_offset
        new_parser.zero_blocks_seen = self.zero_blocks_seen
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        return new_parser

    def reset(self):
        self.is_open = False
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.zero_blocks_seen = 0
        self.header_verified = False
        self.pending_header = bytearray()

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.bytes_to_skip,
            self.current_offset,
            self.zero_blocks_seen,
            self.header_verified,
            bytes(self.pending_header)
        )

    @property
    def header_signatures(self) -> List[bytes]:
        # Commonly, TAR headers have 'ustar' at offset 257, but the header starts at offset 0.
        # However, checking 'ustar' as signature requires finding 'ustar' and stepping back 257 bytes.
        return [b'ustar']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            # Find the 'ustar' signature which is at offset 257
            ustar_idx = data.find(b'ustar')
            if ustar_idx >= 257:
                self.is_open = True
                idx = ustar_idx - 257
                self.current_offset = idx
            else:
                return True, False, 0, 0

        # Skip bytes requested from previous chunk
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            self.current_offset += skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        while idx < n:
            if len(self.pending_header) < 512:
                needed = 512 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 512:
                    return False, False, n, 512 - len(self.pending_header)

            header_block = bytes(self.pending_header)

            # Check if all zeroes
            if all(b == 0 for b in header_block):
                self.zero_blocks_seen += 1
                self.pending_header = bytearray()
                if self.zero_blocks_seen >= 2:
                    return False, True, idx, 0
                continue
            else:
                self.zero_blocks_seen = 0

            # Extract size field (octal size at offset 124, 12 bytes long)
            size_bytes = header_block[124:136].strip(b'\x00\x20')
            try:
                if not size_bytes:
                    file_size = 0
                else:
                    file_size = int(size_bytes, 8)
            except ValueError:
                self.pending_header = bytearray()
                return True, False, 0, 0

            # Sane size boundary checks
            if file_size < 0 or file_size > 50 * 1024 * 1024 * 1024: # 50GB limit
                self.pending_header = bytearray()
                return True, False, 0, 0

            # Content is padded to multiples of 512 bytes
            content_blocks = (file_size + 511) // 512
            total_content_size = content_blocks * 512

            if header_block[257:262] == b'ustar':
                self.header_verified = True

            self.bytes_to_skip = total_content_size
            self.pending_header = bytearray()

            if self.bytes_to_skip > 0:
                skip_amount = min(n - idx, self.bytes_to_skip)
                idx += skip_amount
                self.bytes_to_skip -= skip_amount
                self.current_offset += skip_amount
                if self.bytes_to_skip > 0:
                    return False, False, n, self.bytes_to_skip

        self.current_offset = idx
        return False, False, n, 0
