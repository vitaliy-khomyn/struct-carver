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
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_tag = bytearray()

    def clone(self) -> 'FLVParser':
        new_parser = FLVParser()
        new_parser.is_open = self.is_open
        new_parser.header_length = self.header_length
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.tags_parsed = self.tags_parsed
        new_parser.current_offset = self.current_offset
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.pending_tag = bytearray(self.pending_tag)
        return new_parser

    def reset(self):
        self.is_open = False
        self.header_length = 0
        self.bytes_to_skip = 0
        self.tags_parsed = 0
        self.current_offset = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_tag = bytearray()

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.header_length,
            self.bytes_to_skip,
            self.tags_parsed,
            self.current_offset,
            self.header_verified,
            bytes(self.pending_header),
            bytes(self.pending_tag)
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
            if not self.pending_header:
                start_idx = data.find(b'FLV\x01')
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 9:
                needed = 9 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 9:
                    return False, False, n, 9 - len(self.pending_header)

            header_block = bytes(self.pending_header)
            self.header_length = struct.unpack('>I', header_block[5:9])[0]
            if self.header_length < 9 or self.header_length > 1024:
                return True, False, 0, 0

            total_start_len = self.header_length + 4
            if len(self.pending_header) < total_start_len:
                needed = total_start_len - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < total_start_len:
                    return False, False, n, total_start_len - len(self.pending_header)

            # Verification of FLV signature and PreviousTagSize0
            header_full = bytes(self.pending_header)
            if not header_full.startswith(b'FLV\x01') or header_full[-4:] != b'\x00\x00\x00\x00':
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            self.pending_header = bytearray()

        # Skip bytes requested from previous chunk
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            self.current_offset += skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        while idx < n:
            if len(self.pending_tag) < 11:
                needed = 11 - len(self.pending_tag)
                take = min(n - idx, needed)
                self.pending_tag.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_tag) >= 1:
                    tag_type = self.pending_tag[0]
                    if tag_type not in (8, 9, 18):
                        write_end = idx - len(self.pending_tag)
                        self.pending_tag = bytearray()
                        if self.tags_parsed > 0:
                            return False, True, write_end, 0
                        else:
                            return True, False, 0, 0
                if len(self.pending_tag) < 11:
                    return False, False, n, 11 - len(self.pending_tag)

            tag_hdr = bytes(self.pending_tag[:11])
            tag_type = tag_hdr[0]
            if tag_type not in (8, 9, 18):
                write_end = idx - len(self.pending_tag)
                self.pending_tag = bytearray()
                if self.tags_parsed > 0:
                    return False, True, write_end, 0
                else:
                    return True, False, 0, 0

            data_size = (tag_hdr[1] << 16) | (tag_hdr[2] << 8) | tag_hdr[3]
            if data_size > 50 * 1024 * 1024:
                write_end = idx - len(self.pending_tag)
                self.pending_tag = bytearray()
                if self.tags_parsed > 0:
                    return False, True, write_end, 0
                else:
                    return True, False, 0, 0

            total_tag_size = 11 + data_size + 4

            self.bytes_to_skip = total_tag_size - len(self.pending_tag)
            self.pending_tag = bytearray()
            self.tags_parsed += 1

            if self.bytes_to_skip > 0:
                skip_amount = min(n - idx, self.bytes_to_skip)
                idx += skip_amount
                self.bytes_to_skip -= skip_amount
                self.current_offset += skip_amount
                if self.bytes_to_skip > 0:
                    return False, False, n, self.bytes_to_skip

        self.current_offset = idx
        return False, False, n, 0
