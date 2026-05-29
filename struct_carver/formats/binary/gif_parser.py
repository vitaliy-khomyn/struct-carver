from typing import List, Tuple
from ..base import BaseFormatParser


class GIFParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.bytes_to_skip = 0
        self.in_blocks = False
        self.in_subblocks = False

    def clone(self) -> 'GIFParser':
        new_parser = GIFParser()
        new_parser.is_open = self.is_open
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.in_blocks = self.in_blocks
        new_parser.in_subblocks = self.in_subblocks
        return new_parser

    def reset(self):
        self.is_open = False
        self.bytes_to_skip = 0
        self.in_blocks = False
        self.in_subblocks = False

    def state_tuple(self) -> tuple:
        return (self.is_open, self.bytes_to_skip, self.in_blocks, self.in_subblocks)

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'GIF87a', b'GIF89a']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'\x3B']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if bytes_remaining > 0:
            if n <= bytes_remaining:
                return False, False, n, bytes_remaining - n
            else:
                idx = bytes_remaining
                bytes_remaining = 0

        if not self.is_open:
            sig1 = data.find(b'GIF87a')
            sig2 = data.find(b'GIF89a')
            valid_sigs = [p for p in [sig1, sig2] if p != -1]
            if not valid_sigs:
                return True, False, 0, 0
            
            start_idx = min(valid_sigs)
            self.is_open = True
            
            # Need at least 13 bytes for logical screen descriptor
            if n - start_idx < 13:
                return False, False, n, 13 - (n - start_idx)

            flags = data[start_idx + 10]
            has_gct = bool(flags & 0x80)
            gct_size = 0
            if has_gct:
                gct_size = 3 * (2 ** ((flags & 0x07) + 1))
            
            self.bytes_to_skip = 13 + gct_size
            self.in_blocks = True
            idx = start_idx

        while idx < n:
            if self.bytes_to_skip > 0:
                if n - idx <= self.bytes_to_skip:
                    self.bytes_to_skip -= (n - idx)
                    return False, False, n, 0
                idx += self.bytes_to_skip
                self.bytes_to_skip = 0

            if self.in_subblocks:
                if idx >= n:
                    break
                subblock_size = data[idx]
                if subblock_size == 0:
                    self.in_subblocks = False
                    idx += 1
                else:
                    self.bytes_to_skip = subblock_size
                    idx += 1
            else:
                if idx >= n:
                    break
                block_type = data[idx]
                if block_type == 0x3B:
                    # Trailer / End of GIF
                    return False, True, idx + 1, 0
                elif block_type == 0x2C:
                    # Image Descriptor (need 10 bytes)
                    if n - idx < 10:
                        return False, False, idx, 10 - (n - idx)
                    flags = data[idx + 9]
                    has_lct = bool(flags & 0x80)
                    lct_size = 0
                    if has_lct:
                        lct_size = 3 * (2 ** ((flags & 0x07) + 1))
                    # Skip image descriptor (10 bytes) + local color table + 1 byte LZW min code size
                    self.bytes_to_skip = 10 + lct_size + 1
                    self.in_subblocks = True
                    idx += 10 # This skips only the descriptor, table & code size handled by bytes_to_skip
                elif block_type == 0x21:
                    # Extension Block. Skip introducer + label (2 bytes)
                    self.bytes_to_skip = 2
                    self.in_subblocks = True
                    idx += 1
                else:
                    # Unknown byte block. Fallback: skip this byte
                    idx += 1

        return False, False, n, 0
