"""BZ2 format parser.

This module implements the parser for BZ2 binary format.
"""

import bz2
from typing import List, Any
from .stream_decompressor_parser import BaseStreamingDecompressorParser


class BZ2Parser(BaseStreamingDecompressorParser):
    """Parser for BZ2 format files."""

    ext = "bz2"
    decompression_error_types = (OSError, ValueError)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

        Returns:
            List[bytes]: Header signatures.
        """
        # BZIP2 starts with 'BZh' and a block size ASCII digit '1' to '9'
        return [b'BZh1', b'BZh2', b'BZh3', b'BZh4', b'BZh5', b'BZh6', b'BZh7', b'BZh8', b'BZh9']

    def create_decompressor(self) -> Any:
        """Instantiates a streaming BZ2 decompressor.

        Returns:
            Any: A BZ2Decompressor instance.
        """
        return bz2.BZ2Decompressor()
