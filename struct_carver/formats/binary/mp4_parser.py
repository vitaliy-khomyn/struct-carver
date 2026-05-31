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
        self.header_verified = False
        self.pending_box = bytearray()

    def clone(self) -> 'MP4Parser':
        new_parser = MP4Parser()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.current_offset = self.current_offset
        new_parser.valid_boxes_count = self.valid_boxes_count
        new_parser.header_verified = self.header_verified
        new_parser.pending_box = bytearray(self.pending_box)
        return new_parser

    def reset(self):
        self.is_open = False
        self.total_size = 0
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.valid_boxes_count = 0
        self.header_verified = False
        self.pending_box = bytearray()

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.total_size,
            self.bytes_to_skip,
            self.current_offset,
            self.valid_boxes_count,
            self.header_verified,
            bytes(self.pending_box)
        )

    @property
    def header_signatures(self) -> List[bytes]:
        # Use 8-byte patterns: [size_be:4][type:4].  The size of an ftyp box is
        # typically 20-32 bytes (0x00000014..0x00000020).  Matching the full 8
        # bytes avoids the need to subtract 4 bytes in analyze_binary and
        # eliminates the false-positive risk of bare 'ftyp'/'moov' strings.
        # We list common ftyp sizes and also the moov box header pattern.
        return [
            b'\x00\x00\x00\x18ftyp',  # 24-byte ftyp (very common: isom/mp42)
            b'\x00\x00\x00\x1Cftyp',  # 28-byte ftyp
            b'\x00\x00\x00\x14ftyp',  # 20-byte ftyp
            b'\x00\x00\x00\x20ftyp',  # 32-byte ftyp
            b'\x00\x00\x00\x10ftyp',  # 16-byte ftyp (minimal)
            b'\x00\x00\x00\x24ftyp',  # 36-byte ftyp
        ]

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
            # Signatures are 8-byte [size:4][type:4] patterns starting at box boundary.
            # The data received starts directly at the signature match, so idx=0 is
            # already the beginning of the box.
            ftyp_idx = data.find(b'ftyp', 4)  # look for type field (after size)
            moov_idx = data.find(b'moov', 4)
            # Also check at position 4 (the signature starts at offset 0)
            if len(data) >= 8 and data[4:8] in (b'ftyp', b'moov'):
                start_idx = 0
            else:
                valid_indices = [p - 4 for p in [ftyp_idx, moov_idx] if p >= 4]
                if not valid_indices:
                    return True, False, 0, 0
                start_idx = min(p for p in valid_indices if p >= 0)
            self.is_open = True
            idx = start_idx
            self.current_offset = start_idx

        # Skip bytes requested from previous chunk
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            self.current_offset += skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        # Check for trailing zero padding / terminator
        if self.valid_boxes_count > 0:
            remaining_bytes = bytes(self.pending_box) + data[idx:]
            if remaining_bytes and all(b == 0 for b in remaining_bytes):
                write_end = idx - len(self.pending_box)
                self.pending_box = bytearray()
                return False, True, write_end, 0

        while idx < n:
            if len(self.pending_box) < 8:
                needed = 8 - len(self.pending_box)
                take = min(n - idx, needed)
                self.pending_box.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_box) < 8:
                    if self.valid_boxes_count > 0 and all(b == 0 for b in self.pending_box):
                        write_end = idx - len(self.pending_box)
                        self.pending_box = bytearray()
                        return False, True, write_end, 0
                    return False, False, n, 8 - len(self.pending_box)

            box_hdr = bytes(self.pending_box[:8])
            box_size = struct.unpack('>I', box_hdr[0:4])[0]
            box_type = box_hdr[4:8]

            if not self._is_valid_box_type(box_type):
                write_end = idx - len(self.pending_box)
                self.pending_box = bytearray()
                if self.valid_boxes_count > 0:
                    return False, True, write_end, 0
                else:
                    return True, False, 0, 0

            header_len = 8
            actual_size = box_size

            if box_size == 1:
                if len(self.pending_box) < 16:
                    needed = 16 - len(self.pending_box)
                    take = min(n - idx, needed)
                    self.pending_box.extend(data[idx : idx + take])
                    idx += take
                    if len(self.pending_box) < 16:
                        if self.valid_boxes_count > 0 and all(b == 0 for b in self.pending_box):
                            write_end = idx - len(self.pending_box)
                            self.pending_box = bytearray()
                            return False, True, write_end, 0
                        return False, False, n, 16 - len(self.pending_box)
                actual_size = struct.unpack('>Q', bytes(self.pending_box[8:16]))[0]
                header_len = 16

            if actual_size < header_len or actual_size > 10 * 1024 * 1024 * 1024:
                write_end = idx - len(self.pending_box)
                self.pending_box = bytearray()
                if self.valid_boxes_count > 0:
                    return False, True, write_end, 0
                else:
                    return True, False, 0, 0

            self.bytes_to_skip = actual_size - len(self.pending_box)
            self.pending_box = bytearray()
            self.valid_boxes_count += 1
            self.header_verified = True

            if self.bytes_to_skip > 0:
                skip_amount = min(n - idx, self.bytes_to_skip)
                idx += skip_amount
                self.bytes_to_skip -= skip_amount
                self.current_offset += skip_amount
                if self.bytes_to_skip > 0:
                    return False, False, n, self.bytes_to_skip

        self.current_offset = idx
        return False, False, n, 0
