"""WAV format parser for Struct Carver!

This module implements the parser for WAV binary format.
"""

from .riff_parser import BaseRIFFParser


class WAVParser(BaseRIFFParser):
    """Parser for WAV format files."""

    riff_tag = b'WAVE'
    max_container_size = 1024 * 1024 * 1024
    ext = "wav"
