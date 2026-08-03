"""AVI format parser for Struct Carver!

This module implements the parser for AVI binary format.
"""

from .riff_parser import BaseRIFFParser


class AVIParser(BaseRIFFParser):
    """Parser for AVI format files."""

    riff_tag = b'AVI '
    max_container_size = 10 * 1024 * 1024 * 1024
    ext = "avi"
