import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class WIMParser(BaseFormatParser):
    engine_type = "binary"
    ext = "wim"

    def __init__(self):
        self.is_open = False
        self.total_size = 0

    def clone(self) -> 'WIMParser':
        new_parser = WIMParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0

    def state_tuple(self) -> tuple:
        return (self.is_open, self.total_size)

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

        if not self.is_open:
            start_idx = data.find(b'MSWIM\x00\x00\x00')
            if start_idx != -1:
                # Need at least 120 bytes for the standard header
                if n - start_idx < 120:
                    return False, False, n, 120 - (n - start_idx)

                header_size = struct.unpack('<I', data[start_idx + 8 : start_idx + 12])[0]
                # Header size is usually 120 or 144 (if integrity table is present)
                if header_size < 120 or header_size > 1024:
                    return True, False, 0, 0

                # Ensure we have the full header size
                if n - start_idx < header_size:
                    return False, False, n, header_size - (n - start_idx)

                # Parse descriptors
                max_offset = header_size

                # Offset Table Descriptor (offset 48)
                off, sz = self._parse_descriptor(data, start_idx + 48)
                if sz > 0 and off > 0:
                    max_offset = max(max_offset, off + sz)

                # XML Data Descriptor (offset 72)
                off, sz = self._parse_descriptor(data, start_idx + 72)
                if sz > 0 and off > 0:
                    max_offset = max(max_offset, off + sz)

                # Boot Metadata Descriptor (offset 96)
                off, sz = self._parse_descriptor(data, start_idx + 96)
                if sz > 0 and off > 0:
                    max_offset = max(max_offset, off + sz)

                # Integrity Table Descriptor (offset 120, if header is large enough)
                if header_size >= 144:
                    off, sz = self._parse_descriptor(data, start_idx + 120)
                    if sz > 0 and off > 0:
                        max_offset = max(max_offset, off + sz)

                self.total_size = max_offset
                self.is_open = True

                # Safety check
                if self.total_size < header_size or self.total_size > 100 * 1024 * 1024 * 1024: # 100GB limit
                    return True, False, 0, 0

                bytes_remaining = self.total_size - (n - start_idx)
                if bytes_remaining <= 0:
                    return False, True, start_idx + self.total_size, 0
                return False, False, n, bytes_remaining
            else:
                return True, False, 0, 0

        if bytes_remaining > 0:
            if n >= bytes_remaining:
                return False, True, bytes_remaining, 0
            else:
                return False, False, n, bytes_remaining - n

        return False, False, n, 0
