"""GZ format parser for Struct Carver!

This module implements the parser for GZ binary format.
"""

import zlib
from typing import List, Any
from .stream_decompressor_parser import BaseStreamingDecompressorParser


class GZParser(BaseStreamingDecompressorParser):
    """Parser for GZ format files."""

    ext = "gz"
    decompression_error_types = (zlib.error,)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

        Returns:
            List[bytes]: Header signatures.
        """
        # GZIP files start with \x1F\x8B and compression method \x08 (Deflate)
        return [b'\x1F\x8B\x08']

    def create_decompressor(self) -> Any:
        """Instantiates a streaming zlib decompressor with gzip header support.

        Returns:
            Any: A zlib decompressobj instance.
        """
        return zlib.decompressobj(16 + zlib.MAX_WBITS)
