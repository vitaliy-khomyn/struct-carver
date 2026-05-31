"""Dynamic binary format parser for Struct Carver!

This module provides the DynamicBinaryParser class, which allows defining linear
binary file formats dynamically using specified header and footer signatures.
"""

from typing import List, Tuple
from .base import BaseFormatParser


class DynamicBinaryParser(BaseFormatParser):
    """A parser for simple linear binary formats defined dynamically.

    Attributes:
        ext (str): The file extension for this format.
        is_open (bool): True if the parser has detected a valid header.
    """

    engine_type = "binary"

    def __init__(self, ext: str, header: bytes, footer: bytes):
        """Initializes the dynamic parser with extension and signature boundaries.

        Args:
            ext (str): File extension.
            header (bytes): Hex-decoded header signature bytes.
            footer (bytes): Hex-decoded footer signature bytes.
        """
        self.ext = ext
        self._header = header
        self._footer = footer
        self.is_open = False

    def clone(self) -> 'DynamicBinaryParser':
        """Creates a clone of the parser with the current state.

        Returns:
            DynamicBinaryParser: The cloned parser instance.
        """
        new_parser = DynamicBinaryParser(self.ext, self._header, self._footer)
        new_parser.is_open = self.is_open
        return new_parser

    def reset(self):
        """Resets the parser state back to closed."""
        self.is_open = False

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the list of header signature bytes.

        Returns:
            List[bytes]: Header signature list.
        """
        return [self._header]

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the list of footer signature bytes.

        Returns:
            List[bytes]: Footer signature list.
        """
        return [self._footer]

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Stub implementation for tag extraction (not used by binary formats).

        Args:
            data (bytes): Data chunk.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: Empty tags list and zero offset.
        """
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        """Scans binary data for header/footer signatures to verify boundaries.

        Args:
            data (bytes): Data block cluster.
            bytes_remaining (int, optional): Bytes remaining (unused here).

        Returns:
            Tuple[bool, bool, int, int]: A tuple containing:
                - is_corrupted (bool): True if parsing fails.
                - is_complete (bool): True if footer was found.
                - bytes_to_advance (int): Position cursor movement offset.
                - bytes_remaining (int): Next remaining bytes expectation.
        """
        if not self.is_open:
            start_idx = data.find(self._header)
            if start_idx != -1:
                self.is_open = True
                data = data[start_idx:]
            else:
                return True, False, 0, 0

        end_idx = data.find(self._footer)
        if end_idx != -1:
            return False, True, end_idx + len(self._footer), 0

        return False, False, len(data), 0
