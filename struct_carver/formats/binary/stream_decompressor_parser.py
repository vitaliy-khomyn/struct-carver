"""Base streaming decompression parser for Struct Carver!

This module provides the BaseStreamingDecompressorParser class, which unifies
decompression accumulation, EOF detection, and chunk advancement for formats
like GZ and BZ2.
"""

from typing import List, Tuple, Type, Any
from ..base import BaseBinaryParser


class BaseStreamingDecompressorParser(BaseBinaryParser):
    """Abstract parser for streaming compressed file formats.

    Attributes:
        ext (str): Format extension string.
        decompression_error_types (Tuple[Type[Exception], ...]): Exception types raised on stream corruption.
        is_open (bool): True if currently processing an active file stream.
        accumulated_data (bytes): Running accumulated compressed stream bytes.
        header_verified (bool): True if decompression begins cleanly.
    """

    ext: str = ""
    decompression_error_types: Tuple[Type[Exception], ...] = (Exception,)

    def __init__(self):
        """Initializes the streaming decompressor parser state."""
        self.is_open = False
        self.accumulated_data = b""
        self.header_verified = False

    def clone(self) -> 'BaseStreamingDecompressorParser':
        """Creates a clone of this parser with its current state.

        Returns:
            BaseStreamingDecompressorParser: Cloned parser instance.
        """
        new_parser = self.__class__()
        new_parser.is_open = self.is_open
        new_parser.accumulated_data = self.accumulated_data
        new_parser.header_verified = self.header_verified
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.accumulated_data = b""
        self.header_verified = False

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

        Returns:
            tuple: Hashable parser state.
        """
        return (self.is_open, len(self.accumulated_data), self.header_verified)

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the footer signatures for this format.

        Returns:
            List[bytes]: Footer signatures.
        """
        return []

    def create_decompressor(self) -> Any:
        """Subclass factory to instantiate a new stream decompressor instance.

        Returns:
            Any: A stream decompressor object with decompress(), eof, and unused_data.
        """
        raise NotImplementedError

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        """Analyzes a binary data block to check stream decompression boundaries.

        Args:
            data (bytes): Input data block.
            bytes_remaining (int, optional): Bytes remaining from previous block.

        Returns:
            Tuple[bool, bool, int, int]: is_corrupted, is_complete, bytes_to_advance, bytes_remaining.
        """
        n = len(data)
        idx = 0

        if not self.is_open:
            start_idx = -1
            for sig in self.header_signatures:
                pos = data.find(sig)
                if pos != -1:
                    start_idx = pos
                    break

            if start_idx != -1:
                self.is_open = True
                idx = start_idx
            else:
                return True, False, 0, 0

        prev_accum_len = len(self.accumulated_data)
        self.accumulated_data += data[idx:]

        try:
            decompressor = self.create_decompressor()
            decompressor.decompress(self.accumulated_data)
            self.header_verified = True

            if decompressor.eof:
                unused_len = len(decompressor.unused_data)
                total_size = len(self.accumulated_data) - unused_len
                self.accumulated_data = self.accumulated_data[:total_size]
                return False, True, idx + (total_size - prev_accum_len), 0
            else:
                return False, False, n, 0
        except self.decompression_error_types:
            return True, False, 0, 0
