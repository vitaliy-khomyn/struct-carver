"""MOV format parser.

This module implements the parser for MOV binary format.
"""

from typing import List
from .box_parser import BaseBoxParser


class MOVParser(BaseBoxParser):
    """Parser for MOV format files."""

    ext = "mov"
    initial_box_types = (b'ftyp', b'moov', b'free', b'wide')

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
            b'\x00\x00\x00\x08free',
            b'\x00\x00\x00\x08wide',
        ]
