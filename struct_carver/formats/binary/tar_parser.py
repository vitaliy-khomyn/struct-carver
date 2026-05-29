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

    def clone(self) -> 'TARParser':
        new_parser = TARParser()
        new_parser.is_open = self.is_open
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.current_offset = self.current_offset
        new_parser.zero_blocks_seen = self.zero_blocks_seen
        return new_parser

    def reset(self):
        self.is_open = False
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.zero_blocks_seen = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.bytes_to_skip,
            self.current_offset,
            self.zero_blocks_seen
        )

    @property
    def header_signatures(self) -> List[bytes]:
        # Commonly, TAR headers have 'ustar' at offset 257, but the header starts at offset 0.
        # However, checking 'ustar' as signature requires finding 'ustar' and stepping back 257 bytes.
        # We can register 'ustar' as a header signature to align it.
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
            if n - idx <= self.bytes_to_skip:
                self.bytes_to_skip -= (n - idx)
                self.current_offset += (n - idx)
                return False, False, n, 0
            else:
                idx += self.bytes_to_skip
                self.bytes_to_skip = 0

        while idx < n:
            # We process block by block (512 bytes)
            if n - idx < 512:
                self.current_offset = idx
                return False, False, idx, 512 - (n - idx)

            header_block = data[idx : idx + 512]

            # Check if all zeroes
            if all(b == 0 for b in header_block):
                self.zero_blocks_seen += 1
                idx += 512
                # End of TAR archive is indicated by at least two 512-byte blocks of zeroes
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
                # If size field parsing fails, it's likely corrupt/end of tar
                return True, False, 0, 0

            # Sane size boundary checks
            if file_size < 0 or file_size > 50 * 1024 * 1024 * 1024: # 50GB file limit
                return True, False, 0, 0

            # Content is padded to multiples of 512 bytes
            content_blocks = (file_size + 511) // 512
            total_blocks_size = 512 + (content_blocks * 512)

            if n - idx < total_blocks_size:
                self.bytes_to_skip = total_blocks_size - (n - idx)
                self.current_offset = idx
                return False, False, n, 0

            idx += total_blocks_size

        self.current_offset = idx
        return False, False, n, 0
