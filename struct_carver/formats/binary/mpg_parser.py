"""MPG format parser for Struct Carver!

This module implements the parser for MPG binary format.
"""
from typing import List, Tuple
from ..base import BaseFormatParser


class MPGParser(BaseFormatParser):
    """Parser for MPG format files."""
    engine_type = "binary"
    ext = "mpg"

    # maximum MPEG file size before we stop and emit what we have
    MAX_SIZE = 500 * 1024 * 1024  # 500 MB

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.header_verified = False
        self.bytes_consumed = 0

    def clone(self) -> 'MPGParser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = MPGParser()
        new_parser.is_open = self.is_open
        new_parser.header_verified = self.header_verified
        new_parser.bytes_consumed = self.bytes_consumed
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.header_verified = False
        self.bytes_consumed = 0

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

            Returns:
                tuple: Hashable parser state.
        """
        return (self.is_open, self.header_verified, self.bytes_consumed)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

            Returns:
                List[bytes]: Header signatures.
        """
        # MPEG sequence or pack headers
        return [b'\x00\x00\x01\xBA', b'\x00\x00\x01\xB3']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the footer signatures for this format.

            Returns:
                List[bytes]: Footer signatures.
        """
        # MPEG End Code
        return [b'\x00\x00\x01\xB9']

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
            # find sequence header or pack header
            sig_ba = data.find(b'\x00\x00\x01\xBA')
            sig_b3 = data.find(b'\x00\x00\x01\xB3')
            valid_indices = [p for p in [sig_ba, sig_b3] if p != -1]
            if not valid_indices:
                return True, False, 0, 0

            start_idx = min(valid_indices)

            self.is_open = True
            self.header_verified = True
            idx = start_idx

        # hard size cap: emit as complete if we've processed too many bytes
        self.bytes_consumed += n - idx
        if self.bytes_consumed > self.MAX_SIZE:
            return False, True, n, 0

        # search for MPEG End Code (b'\x00\x00\x01\xB9')
        end_idx = data.find(b'\x00\x00\x01\xB9', idx)
        if end_idx != -1:
            return False, True, end_idx + 4, 0

        # wait for more data
        return False, False, n, 0

