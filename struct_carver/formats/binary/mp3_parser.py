import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class MP3Parser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.id3_parsed = False
        self.id3_size = 0
        self.bytes_to_skip = 0
        self.frames_parsed = 0
        self.current_offset = 0

    def clone(self) -> 'MP3Parser':
        new_parser = MP3Parser()
        new_parser.is_open = self.is_open
        new_parser.id3_parsed = self.id3_parsed
        new_parser.id3_size = self.id3_size
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.frames_parsed = self.frames_parsed
        new_parser.current_offset = self.current_offset
        return new_parser

    def reset(self):
        self.is_open = False
        self.id3_parsed = False
        self.id3_size = 0
        self.bytes_to_skip = 0
        self.frames_parsed = 0
        self.current_offset = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.id3_parsed,
            self.id3_size,
            self.bytes_to_skip,
            self.frames_parsed,
            self.current_offset
        )

    @property
    def header_signatures(self) -> List[bytes]:
        # Commonly starts with 'ID3' or a frame sync (0xFF + high bits)
        return [b'ID3', b'\xFF\xFB', b'\xFF\xF3', b'\xFF\xF2', b'\xFF\xFA']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def _parse_frame_size(self, header: bytes) -> int:
        """Parses the MP3 frame header (4 bytes) and returns the frame size in bytes, or -1 if invalid."""
        if len(header) < 4:
            return -1

        b0 = header[0]
        b1 = header[1]
        b2 = header[2]
        b3 = header[3]

        # Frame sync must be 11 bits (0xFF and 0xE0)
        if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
            return -1

        # Extract MPEG version, Layer, Bitrate, Sample Rate, and Padding
        version = (b1 & 0x18) >> 3
        layer = (b1 & 0x06) >> 1
        bitrate_idx = (b2 & 0xF0) >> 4
        sample_rate_idx = (b2 & 0x0C) >> 2
        padding = (b2 & 0x02) >> 1

        if version == 1: # Reserved
            return -1
        if layer == 0: # Reserved
            return -1
        if bitrate_idx == 0 or bitrate_idx == 15: # Free/Invalid bitrate
            return -1
        if sample_rate_idx == 3: # Reserved sample rate
            return -1

        # Bitrate table (kbps)
        # Columns: Layer I, Layer II, Layer III
        # Rows: 1 to 14
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

        # Sampling rate table (Hz)
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

        if layer == 3: # Layer I
            return ((12 * bitrate) // sample_rate + padding) * 4
        elif layer == 2: # Layer II
            return (144 * bitrate) // sample_rate + padding
        elif layer == 1: # Layer III
            # For MPEG 1 Layer III, coefficient is 144. For MPEG 2/2.5 Layer III, coefficient is 72.
            coeff = 144 if version == 3 else 72
            return (coeff * bitrate) // sample_rate + padding

        return -1

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            # Find ID3 or frame sync
            id3_idx = data.find(b'ID3')
            sync_idx = -1
            for offset in range(n - 1):
                if data[offset] == 0xFF and (data[offset+1] & 0xE0) == 0xE0:
                    sync_idx = offset
                    break

            valid_indices = [p for p in [id3_idx, sync_idx] if p != -1]
            if not valid_indices:
                return True, False, 0, 0

            start_idx = min(valid_indices)
            self.is_open = True
            idx = start_idx
            self.current_offset = start_idx

        # Skip bytes requested from previous chunk
        if self.bytes_to_skip > 0:
            if n - idx <= self.bytes_to_skip:
                self.bytes_to_skip -= (n - idx)
                self.current_offset += (n - idx)
                return False, False, n, 0
            else:
                idx += self.bytes_to_skip
                self.bytes_to_skip = 0

        # Handle ID3 tag if not parsed yet
        if data[idx : idx + 3] == b'ID3' and not self.id3_parsed:
            if n - idx < 10:
                self.current_offset = idx
                return False, False, idx, 10 - (n - idx)

            # Read ID3v2 tag size (synchsafe integer at offset 6)
            size_bytes = data[idx + 6 : idx + 10]
            self.id3_size = (
                (size_bytes[0] & 0x7F) << 21 |
                (size_bytes[1] & 0x7F) << 14 |
                (size_bytes[2] & 0x7F) << 7 |
                (size_bytes[3] & 0x7F)
            )
            # The total tag size is header (10 bytes) + size
            total_tag_size = 10 + self.id3_size
            self.id3_parsed = True

            if n - idx < total_tag_size:
                self.bytes_to_skip = total_tag_size - (n - idx)
                self.current_offset = idx
                return False, False, n, 0

            idx += total_tag_size

        # Parse audio frames
        while idx < n:
            # Check for ID3v1 tag at the end of file (128 bytes starting with 'TAG')
            if data[idx : idx + 3] == b'TAG':
                if n - idx < 128:
                    self.current_offset = idx
                    return False, False, idx, 128 - (n - idx)
                idx += 128
                return False, True, idx, 0

            # Must be a frame header
            if n - idx < 4:
                self.current_offset = idx
                return False, False, idx, 4 - (n - idx)

            frame_size = self._parse_frame_size(data[idx : idx + 4])
            if frame_size <= 0:
                # If we parsed frames already and then found invalid sync bytes,
                # we have successfully carved a complete MP3 file!
                if self.frames_parsed > 0:
                    return False, True, idx, 0
                else:
                    # Let's see if we can find the next sync byte or if we should fail
                    next_sync = -1
                    for offset in range(idx + 1, n - 1):
                        if data[offset] == 0xFF and (data[offset+1] & 0xE0) == 0xE0:
                            next_sync = offset
                            break
                    if next_sync != -1:
                        idx = next_sync
                        continue
                    else:
                        return True, False, 0, 0

            if n - idx < frame_size:
                self.bytes_to_skip = frame_size - (n - idx)
                self.frames_parsed += 1
                self.current_offset = idx
                return False, False, n, 0

            idx += frame_size
            self.frames_parsed += 1

        self.current_offset = idx
        return False, False, n, 0
