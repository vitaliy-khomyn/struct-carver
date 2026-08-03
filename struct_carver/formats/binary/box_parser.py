"""Base ISO Base Media / QuickTime Box format parser for Struct Carver!

This module provides the BaseBoxParser class, which unifies atom and box parsing logic
for container multimedia formats such as MP4 and QuickTime MOV.
"""

import struct
from typing import List, Tuple
from ..base import BaseBinaryParser


class BaseBoxParser(BaseBinaryParser):
    """Abstract parser for ISO BMFF / QuickTime atom-based binary formats.

    Attributes:
        ext (str): Format extension string.
        initial_box_types (Tuple[bytes, ...]): Accepted FourCC box types at file start.
        is_open (bool): True if currently processing an active file stream.
        total_size (int): Running accumulated total size.
        bytes_to_skip (int): Remaining payload bytes to consume in current box.
        current_offset (int): Current byte offset in file.
        valid_boxes_count (int): Number of validated boxes parsed so far.
        header_verified (bool): True if at least one valid box header was verified.
        pending_box (bytearray): Transient buffer for accumulating 8/16-byte box headers.
    """

    ext: str = ""
    initial_box_types: Tuple[bytes, ...] = (b'ftyp', b'moov')

    def __init__(self):
        """Initializes the box parser state."""
        self.is_open = False
        self.total_size = 0
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.valid_boxes_count = 0
        self.header_verified = False
        self.pending_box = bytearray()

    def clone(self) -> 'BaseBoxParser':
        """Creates a clone of this parser with its current state.

        Returns:
            BaseBoxParser: Cloned parser instance.
        """
        new_parser = self.__class__()
        new_parser.is_open = self.is_open
        new_parser.total_size = self.total_size
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.current_offset = self.current_offset
        new_parser.valid_boxes_count = self.valid_boxes_count
        new_parser.header_verified = self.header_verified
        new_parser.pending_box = bytearray(self.pending_box)
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.total_size = 0
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.valid_boxes_count = 0
        self.header_verified = False
        self.pending_box = bytearray()

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

        Returns:
            tuple: Hashable parser state.
        """
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
    def footer_signatures(self) -> List[bytes]:
        """Gets the footer signatures for this format.

        Returns:
            List[bytes]: Footer signatures.
        """
        return []

    def _is_valid_box_type(self, box_type: bytes) -> bool:
        """Checks if the box type consists of 4 printable alphanumeric ASCII characters or spaces.

        Args:
            box_type (bytes): 4-byte box type tag.

        Returns:
            bool: True if box type tag is printable ASCII.
        """
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
        """Analyzes a binary data block to check box boundaries.

        Args:
            data (bytes): Input data block.
            bytes_remaining (int, optional): Bytes remaining from previous block.

        Returns:
            Tuple[bool, bool, int, int]: is_corrupted, is_complete, bytes_to_advance, bytes_remaining.
        """
        n = len(data)
        idx = 0

        if not self.is_open:
            if len(data) >= 8 and data[4:8] in self.initial_box_types:
                start_idx = 0
            else:
                indices = [data.find(box_tag, 4) for box_tag in self.initial_box_types]
                valid_indices = [p - 4 for p in indices if p >= 4]
                if not valid_indices:
                    return True, False, 0, 0
                start_idx = min(p for p in valid_indices if p >= 0)
            self.is_open = True
            idx = start_idx
            self.current_offset = start_idx

        # skip bytes requested from previous chunk
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            self.current_offset += skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        # check for trailing zero padding / terminator
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
                self.pending_box.extend(data[idx:idx + take])
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
                    self.pending_box.extend(data[idx:idx + take])
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
