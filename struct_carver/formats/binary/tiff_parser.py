"""TIFF format parser for Struct Carver!

This module implements the parser for TIFF binary format.
"""
import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class TIFFParser(BaseFormatParser):
    """Parser for TIFF format files."""
    engine_type = "binary"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.total_size = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.bytes_to_skip = 0

    def clone(self) -> 'TIFFParser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = TIFFParser()
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
        return [b'II*\x00', b'MM\x00*']

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
            sig_ii = data.find(b'II*\x00')
            sig_mm = data.find(b'MM\x00*')
            valid_sigs = [p for p in [sig_ii, sig_mm] if p != -1]
            if not valid_sigs:
                return True, False, 0, 0
            idx = min(valid_sigs)
            self.is_open = True

        if not self.header_verified:
            take = n - idx
            self.pending_header.extend(data[idx : idx + take])
            idx += take

            buf = bytes(self.pending_header)
            buf_len = len(buf)

            if buf_len < 8:
                return False, False, n, 8 - buf_len

            endian = '<' if buf[0:2] == b'II' else '>'
            first_ifd = struct.unpack(f'{endian}I', buf[4:8])[0]

            max_offset = first_ifd
            current_ifd = first_ifd
            type_sizes = {1:1, 2:1, 3:2, 4:4, 5:8, 7:1, 8:2, 9:4, 10:8, 11:4, 12:8}

            visited_ifds = set()
            try:
                while current_ifd > 0 and current_ifd < 50 * 1024 * 1024:
                    if current_ifd in visited_ifds:
                        break
                    visited_ifds.add(current_ifd)

                    if buf_len < current_ifd + 2:
                        return False, False, n, (current_ifd + 2) - buf_len

                    num_entries = struct.unpack(f'{endian}H', buf[current_ifd : current_ifd + 2])[0]
                    ifd_size = 2 + num_entries * 12 + 4

                    if buf_len < current_ifd + ifd_size:
                        return False, False, n, (current_ifd + ifd_size) - buf_len

                    strip_offsets = []
                    strip_counts = []

                    for i in range(num_entries):
                        entry_offset = current_ifd + 2 + i * 12
                        entry_data = buf[entry_offset : entry_offset + 12]
                        tag, tag_type, count = struct.unpack(f'{endian}HHI', entry_data[0:8])
                        val_offset = struct.unpack(f'{endian}I', entry_data[8:12])[0]

                        type_sz = type_sizes.get(tag_type, 1)
                        total_sz = count * type_sz

                        if total_sz > 4:
                            max_offset = max(max_offset, val_offset + total_sz)
                            if tag in (273, 324):
                                if val_offset + total_sz <= buf_len:
                                    for j in range(count):
                                        off = struct.unpack(f'{endian}I', buf[val_offset + j*4 : val_offset + j*4 + 4])[0]
                                        strip_offsets.append(off)
                                else:
                                    return False, False, n, (val_offset + total_sz) - buf_len
                            elif tag in (279, 325):
                                if val_offset + total_sz <= buf_len:
                                    for j in range(count):
                                        if tag_type == 3:
                                            sz = struct.unpack(f'{endian}H', buf[val_offset + j*2 : val_offset + j*2 + 2])[0]
                                        else:
                                            sz = struct.unpack(f'{endian}I', buf[val_offset + j*4 : val_offset + j*4 + 4])[0]
                                        strip_counts.append(sz)
                                else:
                                    return False, False, n, (val_offset + total_sz) - buf_len
                        else:
                            if tag in (273, 324):
                                strip_offsets.append(val_offset)
                            elif tag in (279, 325):
                                strip_counts.append(val_offset)

                    for off, sz in zip(strip_offsets, strip_counts):
                        max_offset = max(max_offset, off + sz)

                    next_ifd_offset = current_ifd + 2 + num_entries * 12
                    next_ifd = struct.unpack(f'{endian}I', buf[next_ifd_offset : next_ifd_offset + 4])[0]
                    max_offset = max(max_offset, next_ifd_offset + 4)
                    current_ifd = next_ifd

            except Exception:
                return True, False, 0, 0

            # if we successfully parsed all IFDs:
            self.total_size = max_offset
            if self.total_size < 8 or self.total_size > 10 * 1024 * 1024 * 1024:
                return True, False, 0, 0

            self.header_verified = True
            self.bytes_to_skip = self.total_size - len(self.pending_header)
            self.pending_header = bytearray()

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        return False, True, idx, 0
