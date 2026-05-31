"""BMP format parser for Struct Carver!

This module implements the parser for BMP binary format.
"""
import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class BMPParser(BaseFormatParser):
    """Parser for BMP format files."""
    engine_type = "binary"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def clone(self) -> 'BMPParser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = BMPParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

            Returns:
                tuple: Hashable parser state.
        """
        return (
            self.is_open,
            self.total_size,
            self.header_verified,
            bytes(self.pending_header),
            self.bytes_to_skip
        )

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

            Returns:
                List[bytes]: Header signatures.
        """
        return [b'BM']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the footer signatures for this format.

            Returns:
                List[bytes]: Footer signatures.
        """
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Stub for tag extraction.

            Args:
                data (bytes): Input data block.

            Returns:
                Tuple[List[Tuple[str, bool]], int]: Empty tags list and zero offset.
        """
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        """Analyzes a binary data block to check signature/structure boundaries.

            Args:
                data (bytes): Input data block.
                bytes_remaining (int, optional): Bytes remaining from previous block.

            Returns:
                Tuple[bool, bool, int, int]: is_corrupted, is_complete, bytes_to_advance, bytes_remaining.
        """
        n = len(data)
        idx = 0

        if not self.is_open:
            if not self.pending_header:
                start_idx = data.find(b'BM')
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            # accumulate the full 14-byte BITMAPFILEHEADER before validating.
            # layout: 'BM'(2) | file_size(4) | reserved1(2) | reserved2(2) | pixel_offset(4)
            if len(self.pending_header) < 14:
                needed = 14 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 14:
                    return False, False, n, 14 - len(self.pending_header)

            self.total_size = struct.unpack('<I', bytes(self.pending_header[2:6]))[0]
            reserved1 = struct.unpack('<H', bytes(self.pending_header[6:8]))[0]
            reserved2 = struct.unpack('<H', bytes(self.pending_header[8:10]))[0]
            pixel_offset = struct.unpack('<I', bytes(self.pending_header[10:14]))[0]

            # strict header validation to reject false positives:
            # 1. Reserved fields must be zero in any spec-compliant BMP.
            # 2. total_size must be in a reasonable range.
            # 3. pixel_offset must be >= 54 (minimum header) and < total_size.
            if reserved1 != 0 or reserved2 != 0:
                return True, False, 0, 0
            if self.total_size < 54 or self.total_size > 100 * 1024 * 1024:
                return True, False, 0, 0
            if pixel_offset < 54 or pixel_offset >= self.total_size:
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            self.pending_header = bytearray()
            self.bytes_to_skip = self.total_size - 14

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
