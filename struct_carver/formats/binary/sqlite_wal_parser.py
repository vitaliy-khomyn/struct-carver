"""SQLITE_WAL format parser for Struct Carver!

This module implements the parser for SQLITE_WAL binary format.
"""
import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class SQLiteWALParser(BaseFormatParser):
    """Parser for SQLITE_WAL format files."""
    engine_type = "binary"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.page_size = 0
        self.salt1 = 0
        self.salt2 = 0
        self.endian = '>'
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_frame = bytearray()
        self.bytes_to_skip = 0

    def clone(self) -> 'SQLiteWALParser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = SQLiteWALParser()
        new_parser.is_open = self.is_open
        new_parser.page_size = self.page_size
        new_parser.salt1 = self.salt1
        new_parser.salt2 = self.salt2
        new_parser.endian = self.endian
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.pending_frame = bytearray(self.pending_frame)
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.page_size = 0
        self.salt1 = 0
        self.salt2 = 0
        self.endian = '>'
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_frame = bytearray()
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

            Returns:
                tuple: Hashable parser state.
        """
        return (
            self.is_open,
            self.page_size,
            self.salt1,
            self.salt2,
            self.endian,
            self.header_verified,
            bytes(self.pending_header),
            bytes(self.pending_frame),
            self.bytes_to_skip
        )

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

            Returns:
                List[bytes]: Header signatures.
        """
        return [b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the footer signatures for this format.

            Returns:
                List[bytes]: Footer signatures.
        """
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Stub for tag extraction.

            Args:
                data (bytes): Input data block.

            Returns:
                Tuple[List[Tuple[str, bool]], int]: Empty tags list and zero offset.
        """
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        """Analyzes a binary data block to check signature/structure boundaries.

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
                sig1 = data.find(b'\x37\x7f\x06\x82')
                sig2 = data.find(b'\x37\x7f\x06\x83')
                valid_sigs = [p for p in [sig1, sig2] if p != -1]
                if not valid_sigs:
                    return True, False, 0, 0
                idx = min(valid_sigs)

            if len(self.pending_header) < 32:
                needed = 32 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 32:
                    return False, False, n, 32 - len(self.pending_header)

            # process 32-byte header
            header_block = bytes(self.pending_header[:32])
            magic = header_block[0:4]
            self.endian = '<' if magic == b'\x37\x7f\x06\x82' else '>'
            self.page_size = struct.unpack(f'{self.endian}I', header_block[8:12])[0]
            self.salt1, self.salt2 = struct.unpack(f'{self.endian}II', header_block[16:24])

            if self.page_size == 0 or self.page_size > 65536:
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            self.pending_header = bytearray()

        # skip bytes
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        while idx < n:
            if len(self.pending_frame) < 24:
                needed = 24 - len(self.pending_frame)
                take = min(n - idx, needed)
                self.pending_frame.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_frame) < 24:
                    return False, False, n, 24 - len(self.pending_frame)

            frame_header = bytes(self.pending_frame)
            frame_salt1, frame_salt2 = struct.unpack(f'{self.endian}II', frame_header[8:16])

            if frame_salt1 != self.salt1 or frame_salt2 != self.salt2:
                # frame mismatch! WAL session ended.
                write_end = idx - len(self.pending_frame)
                self.pending_frame = bytearray()
                return False, True, write_end, 0

            self.pending_frame = bytearray()
            self.bytes_to_skip = self.page_size
            
            if idx < n:
                skip_amount = min(n - idx, self.bytes_to_skip)
                idx += skip_amount
                self.bytes_to_skip -= skip_amount
                if self.bytes_to_skip > 0:
                    return False, False, n, self.bytes_to_skip

        return False, False, n, 0
