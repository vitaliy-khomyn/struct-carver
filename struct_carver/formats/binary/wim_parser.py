import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class WIMParser(BaseFormatParser):
    engine_type = "binary"
    ext = "wim"

    def __init__(self):
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.header_size = 0
        self.bytes_to_skip = 0

    def clone(self) -> 'WIMParser':
        new_parser = WIMParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.header_size = self.header_size
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.header_size = 0
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.total_size,
            self.header_verified,
            bytes(self.pending_header),
            self.header_size,
            self.bytes_to_skip
        )

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'MSWIM\x00\x00\x00']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def _parse_descriptor(self, data: bytes, offset: int) -> Tuple[int, int]:
        """Parses a 24-byte WIM Resource Descriptor.
        Returns (offset, size).
        """
        raw_size = struct.unpack('<Q', data[offset : offset + 8])[0]
        size = raw_size & 0x00FFFFFFFFFFFFFF  # Mask out flags in the top byte
        res_offset = struct.unpack('<Q', data[offset + 8 : offset + 16])[0]
        return res_offset, size

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            if not self.pending_header:
                start_idx = data.find(b'MSWIM\x00\x00\x00')
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 120:
                needed = 120 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 120:
                    return False, False, n, 120 - len(self.pending_header)

            if self.header_size == 0:
                self.header_size = struct.unpack('<I', bytes(self.pending_header[8:12]))[0]
                if self.header_size < 120 or self.header_size > 1024:
                    return True, False, 0, 0

            if len(self.pending_header) < self.header_size:
                needed = self.header_size - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < self.header_size:
                    return False, False, n, self.header_size - len(self.pending_header)

            header_block = bytes(self.pending_header[:self.header_size])
            max_offset = self.header_size

            # Offset Table Descriptor (offset 48)
            off, sz = self._parse_descriptor(header_block, 48)
            if sz > 0 and off > 0:
                max_offset = max(max_offset, off + sz)

            # XML Data Descriptor (offset 72)
            off, sz = self._parse_descriptor(header_block, 72)
            if sz > 0 and off > 0:
                max_offset = max(max_offset, off + sz)

            # Boot Metadata Descriptor (offset 96)
            off, sz = self._parse_descriptor(header_block, 96)
            if sz > 0 and off > 0:
                max_offset = max(max_offset, off + sz)

            # Integrity Table Descriptor (offset 120, if header is large enough)
            if self.header_size >= 144:
                off, sz = self._parse_descriptor(header_block, 120)
                if sz > 0 and off > 0:
                    max_offset = max(max_offset, off + sz)

            self.total_size = max_offset
            self.is_open = True
            self.header_verified = True
            self.pending_header = bytearray()
            self.bytes_to_skip = self.total_size - self.header_size

            if self.total_size < self.header_size or self.total_size > 100 * 1024 * 1024 * 1024:
                return True, False, 0, 0

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
