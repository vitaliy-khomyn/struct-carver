"""MP3 format parser for Struct Carver!

This module implements the parser for MP3 binary format.
"""
import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class MP3Parser(BaseFormatParser):
    """Parser for MP3 format files."""
    engine_type = "binary"

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.id3_parsed = False
        self.id3_size = 0
        self.bytes_to_skip = 0
        self.frames_parsed = 0
        self.current_offset = 0
        self.header_verified = False
        self.pending_header = bytearray()

    def clone(self) -> 'MP3Parser':
        """Creates a clone of this parser with its current state.

            Returns:
                BaseFormatParser: Cloned parser instance.
        """
        new_parser = MP3Parser()
        new_parser.is_open = self.is_open
        new_parser.id3_parsed = self.id3_parsed
        new_parser.id3_size = self.id3_size
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.frames_parsed = self.frames_parsed
        new_parser.current_offset = self.current_offset
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.id3_parsed = False
        self.id3_size = 0
        self.bytes_to_skip = 0
        self.frames_parsed = 0
        self.current_offset = 0
        self.header_verified = False
        self.pending_header = bytearray()

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

            Returns:
                tuple: Hashable parser state.
        """
        return (
            self.is_open,
            self.id3_parsed,
            self.id3_size,
            self.bytes_to_skip,
            self.frames_parsed,
            self.current_offset,
            self.header_verified,
            bytes(self.pending_header)
        )

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

            Returns:
                List[bytes]: Header signatures.
        """
        # commonly starts with 'ID3' or a frame sync (0xFF + high bits)
        return [b'ID3', b'\xFF\xFB', b'\xFF\xF3', b'\xFF\xF2', b'\xFF\xFA']

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

    def _parse_frame_size(self, header: bytes) -> int:
        """Parses the MP3 frame header (4 bytes) and returns the frame size in bytes, or -1 if invalid."""
        if len(header) < 4:
            return -1

        b0 = header[0]
        b1 = header[1]
        b2 = header[2]
        b3 = header[3]

        # frame sync must be 11 bits (0xFF and 0xE0)
        if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
            return -1

        # extract MPEG version, Layer, Bitrate, Sample Rate, and Padding
        version = (b1 & 0x18) >> 3
        layer = (b1 & 0x06) >> 1
        bitrate_idx = (b2 & 0xF0) >> 4
        sample_rate_idx = (b2 & 0x0C) >> 2
        padding = (b2 & 0x02) >> 1

        if version == 1: # reserved
            return -1
        if layer == 0: # reserved
            return -1
        if bitrate_idx == 0 or bitrate_idx == 15: # Free/Invalid bitrate
            return -1
        if sample_rate_idx == 3: # reserved sample rate
            return -1

        # bitrate table (kbps)
        # columns: Layer I, Layer II, Layer III
        # rows: 1 to 14
        bitrate_table_v1 = {
            3: [32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448], # L1
            2: [32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],    # L2
            1: [32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],     # L3
        }
        bitrate_table_v2 = {
            3: [32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],    # L1
            2: [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],         # L2/L3
            1: [8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
        }

        # sampling rate table (Hz)
        sample_rate_table = {
            3: [44100, 48000, 32000], # MPEG Version 1
            2: [22050, 24000, 16000], # MPEG Version 2
            0: [11025, 12000, 8000],  # MPEG Version 2.5
        }

        if version == 3: # MPEG Version 1
            bitrates = bitrate_table_v1.get(layer)
            sample_rates = sample_rate_table.get(3)
        else: # MPEG Version 2 or 2.5
            bitrates = bitrate_table_v2.get(layer)
            sample_rates = sample_rate_table.get(version)

        if not bitrates or not sample_rates:
            return -1

        bitrate = bitrates[bitrate_idx - 1] * 1000
        sample_rate = sample_rates[sample_rate_idx]

        if layer == 3: # layer I
            return ((12 * bitrate) // sample_rate + padding) * 4
        elif layer == 2: # layer II
            return (144 * bitrate) // sample_rate + padding
        elif layer == 1: # layer III
            # for MPEG 1 Layer III, coefficient is 144. For MPEG 2/2.5 Layer III, coefficient is 72.
            coeff = 144 if version == 3 else 72
            return (coeff * bitrate) // sample_rate + padding

        return -1

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
                if data.startswith(b'ID3'):
                    self.id3_parsed = False
                elif len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0:
                    self.id3_parsed = True
                else:
                    return True, False, 0, 0
                idx = 0
            self.is_open = True

        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            self.current_offset += skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        if not self.id3_parsed:
            if len(self.pending_header) < 10:
                needed = 10 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 10:
                    return False, False, n, 10 - len(self.pending_header)

            size_bytes = self.pending_header[6:10]
            if (size_bytes[0] & 0x80) or (size_bytes[1] & 0x80) or (size_bytes[2] & 0x80) or (size_bytes[3] & 0x80):
                return True, False, 0, 0

            self.id3_size = (
                (size_bytes[0] & 0x7F) << 21 |
                (size_bytes[1] & 0x7F) << 14 |
                (size_bytes[2] & 0x7F) << 7 |
                (size_bytes[3] & 0x7F)
            )
            self.bytes_to_skip = self.id3_size
            self.id3_parsed = True
            self.pending_header = bytearray()

            if self.bytes_to_skip > 0:
                skip_amount = min(n - idx, self.bytes_to_skip)
                idx += skip_amount
                self.bytes_to_skip -= skip_amount
                if self.bytes_to_skip > 0:
                    return False, False, n, self.bytes_to_skip

        while idx < n:
            if data[idx : idx + 3] == b'TAG':
                if n - idx < 128:
                    return False, False, idx, 128 - (n - idx)
                idx += 128
                if self.frames_parsed >= 4 or self.header_verified:
                    return False, True, idx, 0
                else:
                    return True, False, 0, 0

            if n - idx < 4:
                return False, False, idx, 4 - (n - idx)

            frame_size = self._parse_frame_size(data[idx : idx + 4])
            if frame_size <= 0:
                if self.frames_parsed >= 4 or self.header_verified:
                    return False, True, idx, 0
                else:
                    return True, False, 0, 0

            if n - idx < frame_size:
                self.bytes_to_skip = frame_size - (n - idx)
                self.frames_parsed += 1
                if self.frames_parsed >= 4:
                    self.header_verified = True
                return False, False, n, self.bytes_to_skip

            idx += frame_size
            self.frames_parsed += 1
            if self.frames_parsed >= 4:
                self.header_verified = True

        self.current_offset = idx
        return False, False, n, 0
