"""MP4 format parser for Struct Carver!

This module implements the parser for MP4 binary format.
"""

from typing import List
from .box_parser import BaseBoxParser


class MP4Parser(BaseBoxParser):
    """Parser for MP4 format files."""

    ext = "mp4"
    initial_box_types = (b'ftyp', b'moov')

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

        Returns:
            List[bytes]: Header signatures.
        """
        return [
            b'\x00\x00\x00\x18ftyp',
            b'\x00\x00\x00\x1Cftyp',
            b'\x00\x00\x00\x14ftyp',
            b'\x00\x00\x00\x20ftyp',
            b'\x00\x00\x00\x10ftyp',
            b'\x00\x00\x00\x24ftyp',
        ]
