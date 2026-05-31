"""RTF format parser for Struct Carver!

This module provides the RTFParser class, which parses Rich Text Format (RTF)
streams by checking opening and closing brace structures while handling escaped characters.
"""

from typing import List, Tuple
from ..base import BaseFormatParser


class RTFParser(BaseFormatParser):
    """Parser for RTF documents that tracks brace balancing.

    Attributes:
        escape (bool): True if the previous character was an escaping backslash.
        is_corrupted (bool): True if illegal control bytes are detected.
    """

    def __init__(self):
        """Initializes the RTF parser state."""
        self.escape = False
        self.is_corrupted = False

    def clone(self) -> 'RTFParser':
        """Creates a clone of the parser with the current state.

        Returns:
            RTFParser: The cloned parser instance.
        """
        new_parser = RTFParser()
        new_parser.escape = self.escape
        new_parser.is_corrupted = self.is_corrupted
        return new_parser

    def reset(self):
        """Resets the parser state back to initial default values."""
        self.escape = False
        self.is_corrupted = False

    def state_tuple(self) -> tuple:
        """Returns a hashable representing the internal parser state.

        Returns:
            tuple: representation of parser state.
        """
        return (self.escape, self.is_corrupted)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the list of header signature bytes.

        Returns:
            List[bytes]: Header signature list.
        """
        return [b'{\\rtf1']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the list of footer signature bytes.

        Returns:
            List[bytes]: Footer signature list.
        """
        return [b'}']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Extracts brace structural tags, skipping escaped braces and control codes.

        Args:
            data (bytes): Input data block cluster to parse.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: List of parsed braces and the
                last processed byte offset.
        """
        tags = []
        
        # check for binary control bytes (strictly illegal in RTF)
        for b in data:
            if b < 32 and b not in (9, 10, 13):
                self.is_corrupted = True
                return [], 0
        last_offset = 0
        for i, byte_val in enumerate(data):
            if self.escape:
                self.escape = False
                continue
            if byte_val == ord('\\'):
                self.escape = True
            elif byte_val == ord('{'):
                tags.append(('{', False))
                last_offset = i + 1
            elif byte_val == ord('}'):
                tags.append(('{', True))
                last_offset = i + 1
        return tags, last_offset
