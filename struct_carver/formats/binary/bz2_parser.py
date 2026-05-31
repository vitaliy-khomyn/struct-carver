"""BZ2 format parser for Struct Carver!

This module implements the parser for BZ2 binary format.
"""
import bz2
from typing import List, Tuple
from ..base import BaseFormatParser


class BZ2Parser(BaseFormatParser):
    """Parser for BZ2 format files."""
    engine_type = "binary"
    ext = "bz2"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.accumulated_data = b""
        self.header_verified = False

    def clone(self) -> 'BZ2Parser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = BZ2Parser()
        new_parser.is_open = self.is_open
        new_parser.accumulated_data = self.accumulated_data
        new_parser.header_verified = self.header_verified
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.accumulated_data = b""
        self.header_verified = False

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

            Returns:
                tuple: Hashable parser state.
        """
        return (self.is_open, len(self.accumulated_data), self.header_verified)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

            Returns:
                List[bytes]: Header signatures.
        """
        # BZIP2 starts with 'BZh' and a block size ASCII digit '1' to '9'
        return [b'BZh1', b'BZh2', b'BZh3', b'BZh4', b'BZh5', b'BZh6', b'BZh7', b'BZh8', b'BZh9']

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
            # find the header signature
            start_idx = -1
            for sig in self.header_signatures:
                pos = data.find(sig)
                if pos != -1:
                    start_idx = pos
                    break

            if start_idx != -1:
                self.is_open = True
                idx = start_idx
            else:
                return True, False, 0, 0

        prev_accum_len = len(self.accumulated_data)
        # accumulate data
        self.accumulated_data += data[idx:]

        try:
            decompressor = bz2.BZ2Decompressor()
            decompressor.decompress(self.accumulated_data)
            self.header_verified = True
            
            if decompressor.eof:
                unused_len = len(decompressor.unused_data)
                total_size = len(self.accumulated_data) - unused_len
                self.accumulated_data = self.accumulated_data[:total_size]
                return False, True, idx + (total_size - prev_accum_len), 0
            else:
                return False, False, n, 0
        except OSError:
            # BZ2Decompressor raises OSError (or ValueError) on corrupted streams
            return True, False, 0, 0
