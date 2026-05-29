import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class PCXParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.header_parsed = False
        # Header fields
        self.version = 0
        self.bits_per_pixel = 0
        self.width = 0
        self.height = 0
        self.n_planes = 0
        self.bytes_per_line = 0
        # Parsing state
        self.current_line = 0
        self.current_plane = 0
        self.decoded_bytes_in_current_line = 0
        self.rle_offset = 128

    def clone(self) -> 'PCXParser':
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
        new_parser.rle_offset = self.rle_offset
        return new_parser

    def reset(self):
        self.is_open = False
        self.header_parsed = False
        self.current_line = 0
        self.current_plane = 0
        self.decoded_bytes_in_current_line = 0
        self.rle_offset = 128

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.header_parsed,
            self.current_line,
            self.current_plane,
            self.decoded_bytes_in_current_line,
            self.rle_offset
        )

    @property
    def header_signatures(self) -> List[bytes]:
        # PCX header starts with 0x0A (Manufacturer)
        return [b'\x0A']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        # PCX parser handles scanning internally rather than using engine bytes_remaining
        if not self.is_open:
            start_idx = data.find(b'\x0A')
            if start_idx != -1:
                self.is_open = True
                idx = start_idx
            else:
                return True, False, 0, 0

        # Parse PCX Header (128 bytes)
        if not self.header_parsed:
            if n - idx < 128:
                return False, False, idx, 128 - (n - idx)

            header = data[idx : idx + 128]
            manufacturer = header[0]
            self.version = header[1]
            encoding = header[2]
            self.bits_per_pixel = header[3]
            xmin, ymin, xmax, ymax = struct.unpack('<hhhh', header[4:12])
            self.n_planes = header[65]
            self.bytes_per_line = struct.unpack('<H', header[66:68])[0]

            # Validation checks
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

            self.header_parsed = True
            self.current_line = 0
            self.current_plane = 0
            self.decoded_bytes_in_current_line = 0
            self.rle_offset = idx + 128

        # RLE decoding loop
        idx = self.rle_offset
        total_needed_planes = self.height * self.n_planes

        while (self.current_line * self.n_planes + self.current_plane) < total_needed_planes:
            if idx >= n:
                self.rle_offset = idx
                return False, False, n, 0

            b = data[idx]
            if (b & 0xC0) == 0xC0:
                # Run count
                if idx + 1 >= n:
                    # Need the value byte in the next chunk
                    self.rle_offset = idx
                    return False, False, idx, 2
                run_count = b & 0x3F
                idx += 2
            else:
                run_count = 1
                idx += 1

            self.decoded_bytes_in_current_line += run_count

            # If we completed or overflowed the line width
            while self.decoded_bytes_in_current_line >= self.bytes_per_line:
                # Move to next plane/line
                self.decoded_bytes_in_current_line -= self.bytes_per_line
                self.current_plane += 1
                if self.current_plane >= self.n_planes:
                    self.current_plane = 0
                    self.current_line += 1

                if (self.current_line * self.n_planes + self.current_plane) >= total_needed_planes:
                    break

        # Check for optional 256-color palette (version 5, 8 bits per pixel)
        if self.version == 5 and self.bits_per_pixel == 8 and self.n_planes == 1:
            if idx >= n:
                self.rle_offset = idx
                return False, False, n, 769  # Palette needs 1 byte marker + 768 bytes

            # The palette is preceded by a 0x0C byte
            if data[idx] == 0x0C:
                if n - idx < 769:
                    self.rle_offset = idx
                    return False, False, idx, 769 - (n - idx)
                idx += 769
            # If the 0x0C is missing, then there is no palette, we finish at idx

        return False, True, idx, 0
