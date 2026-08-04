"""MOV format parser.

This module implements the parser for MOV binary format.
"""

from typing import List
from .box_parser import BaseBoxParser


class MOVParser(BaseBoxParser):
    """Parser for MOV format files."""

    ext = "mov"
    header_offset = 4
    initial_box_types = (b'ftyp', b'moov', b'free', b'wide')

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

        Returns:
            List[bytes]: Header signatures.
        """
        return [b'ftyp', b'moov', b'wide', b'free']

    def validate_header(self, data: bytes, offset: int = 0) -> bool:
        """Validates candidate QuickTime MOV file header.

        Args:
            data (bytes): Buffer containing candidate header.
            offset (int, optional): Starting offset of the file in data (default: 0).

        Returns:
            bool: True if valid QuickTime MOV container, False otherwise.
        """
        if not super().validate_header(data, offset):
            return False
        # if ftyp box, major brand must be QuickTime ('qt  ')
        if offset + 12 <= len(data) and data[offset + 4 : offset + 8] == b'ftyp':
            major_brand = data[offset + 8 : offset + 12]
            return major_brand == b'qt  '
        return True

