import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class AUParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.total_size = 0
        self.unspecified_size = False

    def clone(self) -> 'AUParser':
        new_parser = AUParser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.unspecified_size = self.unspecified_size
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0
        self.unspecified_size = False

    def state_tuple(self) -> tuple:
        return (self.is_open, self.total_size, self.unspecified_size)

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'.snd']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)

        if not self.is_open:
            start_idx = data.find(b'.snd')
            if start_idx != -1:
                # Need at least 12 bytes to extract data_offset and data_size
                if n - start_idx < 12:
                    return False, False, n, 12 - (n - start_idx)

                self.is_open = True
                data_offset, data_size = struct.unpack('>II', data[start_idx + 4 : start_idx + 12])

                # Safety checks
                if data_offset < 24 or data_offset > 1024 * 1024:
                    return True, False, 0, 0

                if data_size == 0xFFFFFFFF:
                    self.unspecified_size = True
                    # Let the carver run until EOF / next file signature
                    # In this case, we return False, False but consume all current bytes
                    return False, False, n, 0
                else:
                    self.total_size = data_offset + data_size
                    bytes_remaining = self.total_size - (n - start_idx)
                    if bytes_remaining <= 0:
                        return False, True, start_idx + self.total_size, 0
                    return False, False, n, bytes_remaining
            else:
                return True, False, 0, 0

        if self.unspecified_size:
            # We are consuming the remaining stream
            return False, False, n, 0

        if bytes_remaining > 0:
            if n >= bytes_remaining:
                return False, True, bytes_remaining, 0
            else:
                return False, False, n, bytes_remaining - n

        return False, False, n, 0
