import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class MP4Parser(BaseFormatParser):
    engine_type = "binary"
    ext = "mp4"

    def __init__(self):
        self.is_open = False
        self.total_size = 0
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.valid_boxes_count = 0

    def clone(self) -> 'MP4Parser':
        new_parser = MP4Parser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.current_offset = self.current_offset
        new_parser.valid_boxes_count = self.valid_boxes_count
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.valid_boxes_count = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.total_size,
            self.bytes_to_skip,
            self.current_offset,
            self.valid_boxes_count
        )

    @property
    def header_signatures(self) -> List[bytes]:
        # MP4 files start with an ftyp box or moov box or similar
        return [b'ftyp', b'moov']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def _is_valid_box_type(self, box_type: bytes) -> bool:
        """Returns True if the box type consists of 4 printable alphanumeric ASCII characters or spaces."""
        if len(box_type) != 4:
            return False
        for b in box_type:
            if not (ord('a') <= b <= ord('z') or
                    ord('A') <= b <= ord('Z') or
                    ord('0') <= b <= ord('9') or
                    b == ord(' ') or b == ord('_')):
                return False
        return True

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            # Look for ftyp or moov at box boundary (which starts 4 bytes earlier as size)
            ftyp_idx = data.find(b'ftyp')
            moov_idx = data.find(b'moov')
            valid_indices = [p for p in [ftyp_idx, moov_idx] if p >= 4]
            if not valid_indices:
                return True, False, 0, 0

            start_idx = min(valid_indices) - 4
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

        while idx < n:
            # Need at least 8 bytes to parse box header (4-byte size + 4-byte type)
            if n - idx < 8:
                self.current_offset = idx
                return False, False, idx, 8 - (n - idx)

            box_size = struct.unpack('>I', data[idx : idx + 4])[0]
            box_type = data[idx + 4 : idx + 8]

            # If type is not valid, we stop here. If we have already parsed some valid boxes,
            # then the file ends exactly at the start of this invalid box.
            if not self._is_valid_box_type(box_type):
                if self.valid_boxes_count > 0:
                    return False, True, idx, 0
                else:
                    return True, False, 0, 0

            header_len = 8
            actual_size = box_size

            # If box_size is 1, a 64-bit size follows the type
            if box_size == 1:
                if n - idx < 16:
                    self.current_offset = idx
                    return False, False, idx, 16 - (n - idx)
                actual_size = struct.unpack('>Q', data[idx + 8 : idx + 16])[0]
                header_len = 16

            # Safety check
            if actual_size < header_len or actual_size > 10 * 1024 * 1024 * 1024: # 10GB limit
                # If we already have some valid boxes, we can finish, else it's corrupt
                if self.valid_boxes_count > 0:
                    return False, True, idx, 0
                else:
                    return True, False, 0, 0

            # Skip the box content
            if n - idx < actual_size:
                self.bytes_to_skip = actual_size - (n - idx)
                self.valid_boxes_count += 1
                self.current_offset = idx
                return False, False, n, 0

            idx += actual_size
            self.valid_boxes_count += 1

        self.current_offset = idx
        return False, False, n, 0
