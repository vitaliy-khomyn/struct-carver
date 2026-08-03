"""WMA format parser.

This module implements the parser for WMA binary format.
"""

from .asf_parser import BaseASFParser


class WMAParser(BaseASFParser):
    """Parser for WMA format files."""

    ext = "wma"
