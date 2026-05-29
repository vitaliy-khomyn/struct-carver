import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class FLVParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.header_length = 0
        self.bytes_to_skip = 0
        self.tags_parsed = 0
        self.current_offset = 0

    def clone(self) -> 'FLVParser':
        new_parser = FLVParser()
        new_parser.is_open = self.is_open
        new_parser.header_length = self.header_length
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.tags_parsed = self.tags_parsed
        new_parser.current_offset = self.current_offset
        return new_parser

    def reset(self):
        self.is_open = False
        self.header_length = 0
        self.bytes_to_skip = 0
        self.tags_parsed = 0
        self.current_offset = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.header_length,
            self.bytes_to_skip,
            self.tags_parsed,
            self.current_offset
        )

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'FLV\x01']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            start_idx = data.find(b'FLV\x01')
            if start_idx != -1:
                # Need at least 9 bytes to read the header size
                if n - start_idx < 9:
                    return False, False, n, 9 - (n - start_idx)

                self.header_length = struct.unpack('>I', data[start_idx + 5 : start_idx + 9])[0]
                if self.header_length < 9 or self.header_length > 1024:
                    return True, False, 0, 0

                self.is_open = True
                # Start parsing tags after the header and PreviousTagSize0 (4 bytes)
                idx = start_idx + self.header_length + 4
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
            # Need at least 11 bytes to parse FLV Tag Header
            if n - idx < 11:
                self.current_offset = idx
                return False, False, idx, 11 - (n - idx)

            tag_type = data[idx]
            # Valid FLV tag types are 8 (audio), 9 (video), 18 (script data)
            if tag_type not in (8, 9, 18):
                if self.tags_parsed > 0:
                    return False, True, idx, 0
                else:
                    return True, False, 0, 0

            # Read 24-bit big-endian data size
            data_size = (data[idx + 1] << 16) | (data[idx + 2] << 8) | data[idx + 3]
            
            # Safety size check
            if data_size > 50 * 1024 * 1024: # 50MB single tag limit
                if self.tags_parsed > 0:
                    return False, True, idx, 0
                else:
                    return True, False, 0, 0

            # Total tag size: 11 bytes tag header + data_size + 4 bytes PreviousTagSize
            total_tag_size = 11 + data_size + 4

            if n - idx < total_tag_size:
                self.bytes_to_skip = total_tag_size - (n - idx)
                self.tags_parsed += 1
                self.current_offset = idx
                return False, False, n, 0

            idx += total_tag_size
            self.tags_parsed += 1

        self.current_offset = idx
        return False, False, n, 0
