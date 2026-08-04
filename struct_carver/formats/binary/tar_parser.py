"""TAR format parser.

This module implements the parser for TAR binary format.
"""
from typing import List, Tuple
from ..base import BaseBinaryParser


class TARParser(BaseBinaryParser):
    """Parser for TAR format files."""
    ext = "tar"
    header_offset = 257

    def __init__(self):
        """Initializes the parser state."""
        self.is_open = False
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.zero_blocks_seen = 0
        self.header_verified = False
        self.pending_header = bytearray()

    def clone(self) -> 'TARParser':
        """Creates a clone of this parser with its current state.

        Returns:
            BaseFormatParser: Cloned parser instance.
        """
        new_parser = TARParser()
        new_parser.is_open = self.is_open
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.current_offset = self.current_offset
        new_parser.zero_blocks_seen = self.zero_blocks_seen
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.zero_blocks_seen = 0
        self.header_verified = False
        self.pending_header = bytearray()

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

        Returns:
            tuple: Hashable parser state.
        """
        return (
            self.is_open,
            self.bytes_to_skip,
            self.current_offset,
            self.zero_blocks_seen,
            self.header_verified,
            bytes(self.pending_header)
        )

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the header signatures for this format.

        Returns:
            List[bytes]: Header signatures.
        """
        # ustar indicator is at offset 257 of standard 512-byte TAR header blocks.
        return [b'ustar\x00', b'ustar ', b'ustar']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the footer signatures for this format.

        Returns:
            List[bytes]: Footer signatures.
        """
        return []

    def validate_header(self, data: bytes, offset: int = 0) -> bool:
        """Validates candidate TAR header block at given offset in buffer.

        Args:
            data (bytes): Buffer containing candidate header.
            offset (int, optional): Starting offset of the 512-byte header block (default: 0).

        Returns:
            bool: True if block contains valid TAR header metadata, False otherwise.
        """
        if offset < 0 or offset + 262 > len(data):
            return False

        # verify ustar signature at offset + 257
        if data[offset + 257 : offset + 262] != b'ustar':
            return False

        # if full 512-byte header block is available, validate checksum and octal size
        if offset + 512 <= len(data):
            block = data[offset : offset + 512]

            # validate checksum field if present
            chksum_bytes = block[148:156].strip(b'\x00\x20')
            if chksum_bytes:
                try:
                    expected_chksum = int(chksum_bytes, 8)
                    unsigned_sum = sum(block[:148]) + (8 * 32) + sum(block[156:512])
                    signed_sum = sum((b if b < 128 else b - 256) for b in block[:148]) + (8 * 32) + sum((b if b < 128 else b - 256) for b in block[156:512])
                    if expected_chksum != unsigned_sum and expected_chksum != signed_sum:
                        return False
                except ValueError:
                    return False

            # validate octal size field
            size_bytes = block[124:136].strip(b'\x00\x20')
            if size_bytes:
                try:
                    file_size = int(size_bytes, 8)
                    if file_size < 0 or file_size > 50 * 1024 * 1024 * 1024:
                        return False
                except ValueError:
                    return False

        return True

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
            # check if data begins at offset 0 of TAR block (with ustar at offset 257)
            if len(data) >= 262 and data[257:262] == b'ustar':
                self.is_open = True
                idx = 0
                self.current_offset = 0
            else:
                found = False
                search_pos = 257
                while search_pos + 5 <= n:
                    pos = data.find(b'ustar', search_pos)
                    if pos == -1:
                        break
                    start_candidate = pos - 257
                    if self.validate_header(data, start_candidate):
                        self.is_open = True
                        idx = start_candidate
                        self.current_offset = idx
                        found = True
                        break
                    search_pos = pos + 1
                if not found:
                    return True, False, 0, 0

        # skip bytes requested from previous chunk
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            self.current_offset += skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        while idx < n:
            if len(self.pending_header) < 512:
                needed = 512 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 512:
                    return False, False, n, 512 - len(self.pending_header)

            header_block = bytes(self.pending_header)

            # check if all zeroes
            if all(b == 0 for b in header_block):
                self.zero_blocks_seen += 1
                self.pending_header = bytearray()
                if self.zero_blocks_seen >= 2:
                    return False, True, idx, 0
                continue
            else:
                self.zero_blocks_seen = 0

            # validate checksum field if populated
            chksum_bytes = header_block[148:156].strip(b'\x00\x20')
            if chksum_bytes:
                try:
                    expected_chksum = int(chksum_bytes, 8)
                    unsigned_sum = sum(header_block[:148]) + (8 * 32) + sum(header_block[156:512])
                    signed_sum = sum((b if b < 128 else b - 256) for b in header_block[:148]) + (8 * 32) + sum((b if b < 128 else b - 256) for b in header_block[156:512])
                    if expected_chksum != unsigned_sum and expected_chksum != signed_sum:
                        self.pending_header = bytearray()
                        return True, False, 0, 0
                except ValueError:
                    self.pending_header = bytearray()
                    return True, False, 0, 0

            # extract size field (octal size at offset 124, 12 bytes long)
            size_bytes = header_block[124:136].strip(b'\x00\x20')
            try:
                if not size_bytes:
                    file_size = 0
                else:
                    file_size = int(size_bytes, 8)
            except ValueError:
                self.pending_header = bytearray()
                return True, False, 0, 0

            # sane size boundary checks
            if file_size < 0 or file_size > 50 * 1024 * 1024 * 1024:  # 50gb limit
                self.pending_header = bytearray()
                return True, False, 0, 0

            # content is padded to multiples of 512 bytes
            content_blocks = (file_size + 511) // 512
            total_content_size = content_blocks * 512

            if header_block[257:262] == b'ustar':
                self.header_verified = True

            self.bytes_to_skip = total_content_size
            self.pending_header = bytearray()

            if self.bytes_to_skip > 0:
                skip_amount = min(n - idx, self.bytes_to_skip)
                idx += skip_amount
                self.bytes_to_skip -= skip_amount
                self.current_offset += skip_amount
                if self.bytes_to_skip > 0:
                    return False, False, n, self.bytes_to_skip

        self.current_offset = idx
        return False, False, n, 0

