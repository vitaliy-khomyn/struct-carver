"""Base RIFF container format parser for Struct Carver!

This module provides the BaseRIFFParser class, which unifies common parsing logic
for RIFF-based container multimedia files such as WAV audio and AVI video.
"""

import struct
from typing import List, Tuple
from ..base import BaseBinaryParser


class BaseRIFFParser(BaseBinaryParser):
    """Abstract parser for RIFF container formats (e.g. WAV, AVI).

    Attributes:
        riff_tag (bytes): FourCC tag located at offset +8 (e.g. b'WAVE', b'AVI ').
        max_container_size (int): Upper bound container file size safety threshold.
        is_open (bool): True if currently processing an active file stream.
        total_size (int): Total expected file size in bytes from container header.
        header_verified (bool): True if header and FourCC signatures match.
        pending_header (bytearray): Transient buffer for accumulating 12-byte header.
        bytes_to_skip (int): Remaining payload bytes to consume before EOF.
    """

    riff_tag: bytes = b''
    max_container_size: int = 10 * 1024 * 1024 * 1024

    def __init__(self):
        """Initializes the RIFF parser state."""
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def clone(self) -> 'BaseRIFFParser':
        """Creates a clone of this parser with its current state.

        Returns:
            BaseRIFFParser: Cloned parser instance.
        """
        new_parser = self.__class__()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

        Returns:
            tuple: Hashable parser state.
        """
        return (
            self.is_open,
            self.total_size,
            self.header_verified,
            bytes(self.pending_header),
            self.bytes_to_skip
        )

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

        Returns:
            List[bytes]: Header signatures.
        """
        return [b'RIFF']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the footer signatures for this format.

        Returns:
            List[bytes]: Footer signatures.
        """
        return []

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        """Analyzes a binary data block to check RIFF container boundaries.

        Args:
            data (bytes): Input data block.
            bytes_remaining (int, optional): Bytes remaining from previous block.

        Returns:
            Tuple[bool, bool, int, int]: is_corrupted, is_complete, bytes_to_advance, bytes_remaining.
        """
        n = len(data)
        idx = 0

        if not self.is_open:
            if not self.pending_header:
                # search for RIFF followed by specific riff_tag at offset +8
                start_idx = -1
                search_from = 0
                while True:
                    riff_pos = data.find(b'RIFF', search_from)
                    if riff_pos == -1:
                        break
                    if riff_pos + 12 <= n and data[riff_pos + 8:riff_pos + 12] == self.riff_tag:
                        start_idx = riff_pos
                        break
                    search_from = riff_pos + 1
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 12:
                needed = 12 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx:idx + take])
                idx += take
                if len(self.pending_header) < 12:
                    return False, False, n, 12 - len(self.pending_header)

            header_block = bytes(self.pending_header[:12])
            if header_block[8:12] != self.riff_tag:
                return True, False, 0, 0

            riff_size = struct.unpack('<I', header_block[4:8])[0]
            self.total_size = riff_size + 8

            if self.total_size < 12 or self.total_size > self.max_container_size:
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            self.pending_header = bytearray()
            self.bytes_to_skip = self.total_size - 12

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
