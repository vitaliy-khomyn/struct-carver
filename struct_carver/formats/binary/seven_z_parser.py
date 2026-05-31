"""SEVEN_Z format parser for Struct Carver!

This module implements the parser for SEVEN_Z binary format.
"""
import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class SevenZParser(BaseFormatParser):
    """Parser for SEVEN_Z format files."""
    engine_type = "binary"
    ext = "7z"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def clone(self) -> 'SevenZParser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = SevenZParser()
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
        return [b'7z\xBC\xAF\x27\x1C']

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
                start_idx = data.find(b'7z\xBC\xAF\x27\x1C')
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 32:
                needed = 32 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 32:
                    return False, False, n, 32 - len(self.pending_header)

            # process 32-byte header
            header_block = bytes(self.pending_header[:32])
            next_header_offset, next_header_size = struct.unpack('<QQ', header_block[12:28])
            self.total_size = 32 + next_header_offset + next_header_size

            if self.total_size < 32 or self.total_size > 10 * 1024 * 1024 * 1024:
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            
            self.pending_header = bytearray()
            self.bytes_to_skip = self.total_size - 32

        # skip bytes
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
