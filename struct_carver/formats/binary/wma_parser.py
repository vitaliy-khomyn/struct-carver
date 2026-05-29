import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class WMAParser(BaseFormatParser):
    engine_type = "binary"
    ext = "wma"

    def __init__(self):
        self.is_open = False
        self.total_size = 0

    def clone(self) -> 'WMAParser':
        new_parser = WMAParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0

    def state_tuple(self) -> tuple:
        return (self.is_open, self.total_size)

    @property
    def header_signatures(self) -> List[bytes]:
        # ASF Header Object GUID
        return [b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)

        if not self.is_open:
            start_idx = data.find(b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C')
            if start_idx != -1:
                # Need at least 24 bytes to read Header Object size
                if n - start_idx < 24:
                    return False, False, n, 24 - (n - start_idx)

                header_size = struct.unpack('<Q', data[start_idx + 16 : start_idx + 24])[0]
                if header_size < 30 or header_size > 50 * 1024 * 1024: # 50MB header sanity limit
                    return True, False, 0, 0

                # Need the whole header to parse sub-objects
                if n - start_idx < header_size:
                    return False, False, n, header_size - (n - start_idx)

                # Look for the File Properties Object GUID inside the header
                # GUID: A1 5F C1 8C 85 4F D0 11 AC B0 00 A0 C9 03 49 BE (in file representation)
                # First 3 parts are little-endian: A15FC18C -> 8CC15FA1, 4F85 -> 854F, D011 -> 11D0
                fp_guid = b'\xA1\x5F\xC1\x8C\x4F\x85\xD0\x11\xAC\xB0\x00\xA0\xC9\x03\x49\xBE'
                fp_idx = data.find(fp_guid, start_idx + 24, start_idx + header_size)

                if fp_idx == -1:
                    # File Properties Object must be present in header
                    return True, False, 0, 0

                # File Properties Object size is 104 bytes. Check if it fits
                if fp_idx + 104 > start_idx + header_size:
                    return True, False, 0, 0

                # File Size is at offset 40 from the start of the File Properties Object (8 bytes uint64)
                file_size = struct.unpack('<Q', data[fp_idx + 40 : fp_idx + 48])[0]
                self.total_size = file_size
                self.is_open = True

                # Safety check
                if self.total_size < header_size or self.total_size > 10 * 1024 * 1024 * 1024: # 10GB limit
                    return True, False, 0, 0

                bytes_remaining = self.total_size - (n - start_idx)
                if bytes_remaining <= 0:
                    return False, True, start_idx + self.total_size, 0
                return False, False, n, bytes_remaining
            else:
                return True, False, 0, 0

        if bytes_remaining > 0:
            if n >= bytes_remaining:
                return False, True, bytes_remaining, 0
            else:
                return False, False, n, bytes_remaining - n

        return False, False, n, 0
