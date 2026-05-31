"""WMA format parser for Struct Carver!

This module implements the parser for WMA binary format.
"""
import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class WMAParser(BaseFormatParser):
    """Parser for WMA format files."""
    engine_type = "binary"
    ext = "wma"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.header_size = 0
        self.bytes_to_skip = 0

    def clone(self) -> 'WMAParser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = WMAParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.header_size = self.header_size
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.header_size = 0
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
            self.header_size,
            self.bytes_to_skip
        )

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

            Returns:
                List[bytes]: Header signatures.
        """
        # ASF Header Object GUID
        return [b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C']

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
                start_idx = data.find(b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C')
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 24:
                needed = 24 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 24:
                    return False, False, n, 24 - len(self.pending_header)

            if self.header_size == 0:
                self.header_size = struct.unpack('<Q', self.pending_header[16:24])[0]
                if self.header_size < 30 or self.header_size > 50 * 1024 * 1024:
                    return True, False, 0, 0

            if len(self.pending_header) < self.header_size:
                needed = self.header_size - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < self.header_size:
                    return False, False, n, self.header_size - len(self.pending_header)

            # accumulate done, verify
            fp_guid = b'\xA1\x5F\xC1\x8C\x4F\x85\xD0\x11\xAC\xB0\x00\xA0\xC9\x03\x49\xBE'
            fp_idx = self.pending_header.find(fp_guid, 24)
            if fp_idx == -1 or fp_idx + 104 > self.header_size:
                return True, False, 0, 0

            file_size = struct.unpack('<Q', self.pending_header[fp_idx + 40 : fp_idx + 48])[0]
            self.total_size = file_size
            self.is_open = True
            self.header_verified = True

            if self.total_size < self.header_size or self.total_size > 10 * 1024 * 1024 * 1024:
                return True, False, 0, 0

            self.bytes_to_skip = self.total_size - len(self.pending_header)
            self.pending_header = bytearray()

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
