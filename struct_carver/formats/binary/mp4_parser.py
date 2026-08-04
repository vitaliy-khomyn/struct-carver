"""MP4 format parser.

This module implements the parser for MP4 binary format.
"""

from typing import List
from .box_parser import BaseBoxParser


class MP4Parser(BaseBoxParser):
    """Parser for MP4 format files."""

    ext = "mp4"
    header_offset = 4
    initial_box_types = (b'ftyp',)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

        Returns:
            List[bytes]: Header signatures.
        """
        return [b'ftyp']

    def validate_header(self, data: bytes, offset: int = 0) -> bool:
        """Validates candidate MP4 file header.

        Args:
            data (bytes): Buffer containing candidate header.
            offset (int, optional): Starting offset of the file in data (default: 0).

        Returns:
            bool: True if valid MP4 container and not QuickTime brand, False otherwise.
        """
        if not super().validate_header(data, offset):
            return False
        # if ftyp box, verify major brand is not QuickTime ('qt  ')
        if offset + 12 <= len(data) and data[offset + 4 : offset + 8] == b'ftyp':
            major_brand = data[offset + 8 : offset + 12]
            if major_brand == b'qt  ':
                return False
        return True

