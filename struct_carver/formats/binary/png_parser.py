"""PNG format parser for Struct Carver!

This module implements the parser for PNG binary format.
"""
import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class PNGParser(BaseFormatParser):
    """Parser for PNG format files."""
    engine_type = "binary"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.bytes_to_skip = 0
        self.header_verified = False
        self.pending_chunk = bytearray()

    def clone(self) -> 'PNGParser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = PNGParser()
        new_parser.is_open = self.is_open
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.header_verified = self.header_verified
        new_parser.pending_chunk = bytearray(self.pending_chunk)
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.bytes_to_skip = 0
        self.header_verified = False
        self.pending_chunk = bytearray()

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

            Returns:
                tuple: Hashable parser state.
        """
        return (self.is_open, self.bytes_to_skip, self.header_verified, bytes(self.pending_chunk))

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

            Returns:
                List[bytes]: Header signatures.
        """
        return [b'\x89PNG\r\n\x1a\n']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the footer signatures for this format.

            Returns:
                List[bytes]: Footer signatures.
        """
        return [b'IEND']

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
            start_idx = data.find(b'\x89PNG\r\n\x1a\n')
            if start_idx != -1:
                self.is_open = True
                idx = start_idx + 8
            else:
                return True, False, 0, 0

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        while idx < n:
            if len(self.pending_chunk) < 8:
                needed = 8 - len(self.pending_chunk)
                take = min(n - idx, needed)
                self.pending_chunk.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_chunk) < 8:
                    return False, False, n, 8 - len(self.pending_chunk)

            chunk_hdr = bytes(self.pending_chunk)
            chunk_len = struct.unpack('>I', chunk_hdr[0:4])[0]
            chunk_type = chunk_hdr[4:8]

            if chunk_type == b'IHDR' and chunk_len == 13:
                self.header_verified = True

            # standard safety check for chunk length to prevent corrupt buffers
            if chunk_len > 100 * 1024 * 1024:  # 100MB chunk safety limit
                return True, False, 0, 0

            if chunk_type == b'IEND':
                self.pending_chunk = bytearray()
                return False, True, idx + 4, 0

            self.bytes_to_skip = chunk_len + 4
            self.pending_chunk = bytearray()

            if self.bytes_to_skip > 0:
                skip_amount = min(n - idx, self.bytes_to_skip)
                idx += skip_amount
                self.bytes_to_skip -= skip_amount
                if self.bytes_to_skip > 0:
                    return False, False, n, self.bytes_to_skip

        return False, False, n, 0
