"""PCX format parser for Struct Carver!

This module implements the parser for PCX binary format.
"""
import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class PCXParser(BaseFormatParser):
    """Parser for PCX format files."""
    engine_type = "binary"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.header_parsed = False
        # header fields
        self.version = 0
        self.bits_per_pixel = 0
        self.width = 0
        self.height = 0
        self.n_planes = 0
        self.bytes_per_line = 0
        # parsing state
        self.current_line = 0
        self.current_plane = 0
        self.decoded_bytes_in_current_line = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_run_count = 0
        self.bytes_to_skip = 0

    def clone(self) -> 'PCXParser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = PCXParser()
        new_parser.is_open = self.is_open
        new_parser.header_parsed = self.header_parsed
        new_parser.version = self.version
        new_parser.bits_per_pixel = self.bits_per_pixel
        new_parser.width = self.width
        new_parser.height = self.height
        new_parser.n_planes = self.n_planes
        new_parser.bytes_per_line = self.bytes_per_line
        new_parser.current_line = self.current_line
        new_parser.current_plane = self.current_plane
        new_parser.decoded_bytes_in_current_line = self.decoded_bytes_in_current_line
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.pending_run_count = self.pending_run_count
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.header_parsed = False
        self.current_line = 0
        self.current_plane = 0
        self.decoded_bytes_in_current_line = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_run_count = 0
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

            Returns:
                tuple: Hashable parser state.
        """
        return (
            self.is_open,
            self.header_parsed,
            self.current_line,
            self.current_plane,
            self.decoded_bytes_in_current_line,
            self.header_verified,
            bytes(self.pending_header),
            self.pending_run_count,
            self.bytes_to_skip
        )

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

            Returns:
                List[bytes]: Header signatures.
        """
        # PCX header starts with 0x0A (Manufacturer) + Version + 0x01 (Encoding)
        # valid versions: 0, 2, 3, 4, 5
        return [
            b'\x0A\x00\x01',
            b'\x0A\x02\x01',
            b'\x0A\x03\x01',
            b'\x0A\x04\x01',
            b'\x0A\x05\x01'
        ]

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
                start_idx = -1
                for sig in self.header_signatures:
                    pos = data.find(sig)
                    if pos != -1:
                        start_idx = pos
                        break
                if start_idx == -1:
                    return True, False, 0, 0
                idx = start_idx

            if len(self.pending_header) < 128:
                needed = 128 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 128:
                    return False, False, n, 128 - len(self.pending_header)

            header = bytes(self.pending_header)
            manufacturer = header[0]
            self.version = header[1]
            encoding = header[2]
            self.bits_per_pixel = header[3]
            xmin, ymin, xmax, ymax = struct.unpack('<hhhh', header[4:12])
            self.n_planes = header[65]
            self.bytes_per_line = struct.unpack('<H', header[66:68])[0]

            self.width = xmax - xmin + 1
            self.height = ymax - ymin + 1

            if (manufacturer != 0x0A or
                self.version not in [0, 2, 3, 4, 5] or
                encoding != 1 or
                self.bits_per_pixel not in [1, 2, 4, 8] or
                self.width <= 0 or self.height <= 0 or
                self.n_planes not in [1, 2, 3, 4] or
                self.bytes_per_line <= 0 or
                self.width > 32768 or self.height > 32768):
                return True, False, 0, 0

            self.is_open = True
            self.header_parsed = True
            self.header_verified = True
            self.current_line = 0
            self.current_plane = 0
            self.decoded_bytes_in_current_line = 0
            self.pending_header = bytearray()

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        total_needed_planes = self.height * self.n_planes

        while (self.current_line * self.n_planes + self.current_plane) < total_needed_planes:
            if idx >= n:
                return False, False, n, 0

            if self.pending_run_count > 0:
                run_count = self.pending_run_count
                self.pending_run_count = 0
                idx += 1  # skip the value byte (which is at data[idx])
            else:
                b = data[idx]
                if (b & 0xC0) == 0xC0:
                    run_count = b & 0x3F
                    if idx + 1 >= n:
                        self.pending_run_count = run_count
                        idx += 1
                        return False, False, n, 1
                    idx += 2
                else:
                    run_count = 1
                    idx += 1

            self.decoded_bytes_in_current_line += run_count

            while self.decoded_bytes_in_current_line >= self.bytes_per_line:
                self.decoded_bytes_in_current_line -= self.bytes_per_line
                self.current_plane += 1
                if self.current_plane >= self.n_planes:
                    self.current_plane = 0
                    self.current_line += 1

                if (self.current_line * self.n_planes + self.current_plane) >= total_needed_planes:
                    break

        if self.version == 5 and self.bits_per_pixel == 8 and self.n_planes == 1:
            if idx >= n:
                return False, False, n, 769

            if data[idx] == 0x0C:
                if n - idx < 769:
                    self.bytes_to_skip = 769 - (n - idx)
                    return False, False, n, self.bytes_to_skip
                idx += 769

        return False, True, idx, 0
