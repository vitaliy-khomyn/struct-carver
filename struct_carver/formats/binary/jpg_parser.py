import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class JPGParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.in_scan_data = False
        self.bytes_to_skip = 0
        self.header_verified = False

    def clone(self) -> 'JPGParser':
        new_parser = JPGParser()
        new_parser.is_open = self.is_open
        new_parser.in_scan_data = self.in_scan_data
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.header_verified = self.header_verified
        return new_parser

    def reset(self):
        self.is_open = False
        self.in_scan_data = False
        self.bytes_to_skip = 0
        self.header_verified = False

    def state_tuple(self) -> tuple:
        return (self.is_open, self.in_scan_data, self.bytes_to_skip, self.header_verified)

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'\xFF\xD8']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'\xFF\xD9']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            start_idx = data.find(b'\xFF\xD8')
            if start_idx != -1:
                self.is_open = True
                self.header_verified = False
                idx = start_idx + 2
            else:
                return True, False, 0, 0

        if not self.header_verified:
            if idx < n:
                if data[idx] != 0xFF:
                    return True, False, 0, 0
                if idx + 1 < n:
                    marker = data[idx + 1]
                    if marker < 0xC0 or marker == 0xFF:
                        return True, False, 0, 0
                    # Read the 2-byte marker length to validate it further.
                    # Valid segment lengths are 2..65535.  We need bytes at idx+2 and idx+3.
                    if idx + 3 < n:
                        seg_len = struct.unpack('>H', data[idx + 2 : idx + 4])[0]
                        if seg_len < 2:
                            return True, False, 0, 0
                        self.header_verified = True
                    else:
                        # Not enough bytes yet; wait for the next chunk.
                        return False, False, n, (idx + 4) - n
                else:
                    return False, False, n, 2
            else:
                return False, False, n, 2

        # Skip bytes requested from previous block skip
        if self.bytes_to_skip > 0:
            if n - idx <= self.bytes_to_skip:
                self.bytes_to_skip -= (n - idx)
                return False, False, n, 0
            else:
                idx += self.bytes_to_skip
                self.bytes_to_skip = 0

        while idx < n:
            if self.in_scan_data:
                # Inside entropy coded scan data. Scan for \xFF
                next_ff = data.find(b'\xFF', idx)
                if next_ff == -1:
                    break

                if next_ff + 1 >= n:
                    # Split marker at chunk boundary. Wait for next chunk
                    return False, False, next_ff, 0

                marker = data[next_ff + 1]
                if marker == 0x00:
                    # Escaped \xFF (byte stuffed). Skip both bytes
                    idx = next_ff + 2
                elif 0xD0 <= marker <= 0xD7:
                    # Restart marker. Skip both bytes
                    idx = next_ff + 2
                elif marker == 0xD9:
                    # End of Image!
                    return False, True, next_ff + 2, 0
                else:
                    # Any other marker terminates scan data (e.g. DNL, next scan, etc.)
                    self.in_scan_data = False
                    idx = next_ff
            else:
                # Outside scan data. We are looking for markers.
                next_ff = data.find(b'\xFF', idx)
                if next_ff == -1:
                    break

                if next_ff + 1 >= n:
                    return False, False, next_ff, 0

                marker = data[next_ff + 1]
                if marker == 0x00:
                    # Stray stuffed byte outside scan data? Treat as garbage
                    idx = next_ff + 2
                elif marker == 0xD9:
                    # End of Image
                    return False, True, next_ff + 2, 0
                elif marker == 0xD8:
                    # Nested SOI or restart? Skip
                    idx = next_ff + 2
                elif 0xD0 <= marker <= 0xD7:
                    # Restart marker
                    idx = next_ff + 2
                else:
                    # Marker with size. Need at least 4 bytes to parse size
                    if n - next_ff < 4:
                        return False, False, next_ff, 0
                    
                    marker_len = struct.unpack('>H', data[next_ff + 2 : next_ff + 4])[0]
                    total_marker_len = 2 + marker_len  # 2 bytes for \xFF + marker code, plus length field
                    
                    if marker == 0xDA:
                        # Start of Scan (SOS). Enter scan data mode after the SOS header
                        self.in_scan_data = True
                        idx = next_ff + total_marker_len
                    else:
                        # Standard marker block. Skip it
                        if n - next_ff < total_marker_len:
                            self.bytes_to_skip = total_marker_len - (n - next_ff)
                            return False, False, n, 0
                        idx = next_ff + total_marker_len

        return False, False, n, 0
