import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class RARParser(BaseFormatParser):
    engine_type = "binary"
    ext = "rar"

    def __init__(self):
        self.is_open = False
        self.rar_version = 0
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.blocks_parsed = 0

    def clone(self) -> 'RARParser':
        new_parser = RARParser()
        new_parser.is_open = self.is_open
        new_parser.rar_version = self.rar_version
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.current_offset = self.current_offset
        new_parser.blocks_parsed = self.blocks_parsed
        return new_parser

    def reset(self):
        self.is_open = False
        self.rar_version = 0
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.blocks_parsed = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.rar_version,
            self.bytes_to_skip,
            self.current_offset,
            self.blocks_parsed
        )

    @property
    def header_signatures(self) -> List[bytes]:
        # RAR4: Rar!\x1A\x07\x00
        # RAR5: Rar!\x1A\x07\x01\x00
        return [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01\x00']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def _read_vint(self, data: bytes, offset: int) -> Tuple[int, int]:
        """Reads a Variable Length Integer (VINT) from data starting at offset.
        Returns (value, bytes_consumed). If incomplete or invalid, returns (-1, 0).
        """
        val = 0
        shift = 0
        idx = offset
        n = len(data)
        while idx < n:
            b = data[idx]
            val |= (b & 0x7F) << shift
            idx += 1
            if not (b & 0x80):
                return val, idx - offset
            shift += 7
            if shift >= 64:
                return -1, 0
        return -1, 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            # Find signature
            sig4 = data.find(b'Rar!\x1a\x07\x00')
            sig5 = data.find(b'Rar!\x1a\x07\x01\x00')
            
            valid_sigs = [p for p in [sig4, sig5] if p != -1]
            if not valid_sigs:
                return True, False, 0, 0

            start_idx = min(valid_sigs)
            self.is_open = True
            if start_idx == sig5:
                self.rar_version = 5
                idx = start_idx + 8
            else:
                self.rar_version = 4
                idx = start_idx + 7
            self.current_offset = idx

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
            if self.rar_version == 4:
                # RAR4 Block Parser
                # Need at least 7 bytes for block header:
                # CRC (2), Type (1), Flags (2), Header Size (2)
                if n - idx < 7:
                    self.current_offset = idx
                    return False, False, idx, 7 - (n - idx)

                h_crc, h_type, h_flags, h_size = struct.unpack('<HBBH', data[idx : idx + 7])

                if h_size < 7 or h_size > 1024 * 1024:
                    if self.blocks_parsed > 0:
                        return False, True, idx, 0
                    else:
                        return True, False, 0, 0

                total_block_size = h_size
                if h_flags & 0x8000:
                    # ADD_SIZE field is present (4 bytes)
                    if n - idx < 11:
                        self.current_offset = idx
                        return False, False, idx, 11 - (n - idx)
                    add_size = struct.unpack('<I', data[idx + 7 : idx + 11])[0]
                    total_block_size += add_size

                # Terminate on terminator block
                if h_type == 0x7B: # Terminator block
                    if n - idx < h_size:
                        self.bytes_to_skip = h_size - (n - idx)
                        self.blocks_parsed += 1
                        self.current_offset = idx
                        return False, False, n, 0
                    idx += h_size
                    return False, True, idx, 0

                # Skip the block content
                if n - idx < total_block_size:
                    self.bytes_to_skip = total_block_size - (n - idx)
                    self.blocks_parsed += 1
                    self.current_offset = idx
                    return False, False, n, 0

                idx += total_block_size
                self.blocks_parsed += 1

            else:
                # RAR5 Block Parser
                # Need at least 4 bytes for CRC
                if n - idx < 4:
                    self.current_offset = idx
                    return False, False, idx, 4 - (n - idx)

                # Parse header size VINT starting at offset 4
                h_size, h_size_len = self._read_vint(data, idx + 4)
                if h_size_len == 0 or h_size < 0:
                    self.current_offset = idx
                    return False, False, idx, 10  # Wait for VINT bytes

                total_header_size = 4 + h_size_len + h_size
                if n - idx < total_header_size:
                    self.current_offset = idx
                    return False, False, idx, total_header_size - (n - idx)

                # Parse Header Type and Header Flags inside the header block
                vint_offset = idx + 4 + h_size_len
                h_type, h_type_len = self._read_vint(data, vint_offset)
                if h_type_len == 0:
                    if self.blocks_parsed > 0:
                        return False, True, idx, 0
                    return True, False, 0, 0
                vint_offset += h_type_len

                h_flags, h_flags_len = self._read_vint(data, vint_offset)
                if h_flags_len == 0:
                    if self.blocks_parsed > 0:
                        return False, True, idx, 0
                    return True, False, 0, 0
                vint_offset += h_flags_len

                extra_size = 0
                if h_flags & 0x0001:
                    extra_size, extra_size_len = self._read_vint(data, vint_offset)
                    if extra_size_len == 0:
                        return True, False, 0, 0
                    vint_offset += extra_size_len

                data_size = 0
                if h_flags & 0x0002:
                    data_size, data_size_len = self._read_vint(data, vint_offset)
                    if data_size_len == 0:
                        return True, False, 0, 0
                    vint_offset += data_size_len

                total_block_size = total_header_size + data_size

                # Terminate on End of Archive block (type 5)
                if h_type == 5:
                    if n - idx < total_block_size:
                        self.bytes_to_skip = total_block_size - (n - idx)
                        self.blocks_parsed += 1
                        self.current_offset = idx
                        return False, False, n, 0
                    idx += total_block_size
                    return False, True, idx, 0

                # Skip block content
                if n - idx < total_block_size:
                    self.bytes_to_skip = total_block_size - (n - idx)
                    self.blocks_parsed += 1
                    self.current_offset = idx
                    return False, False, n, 0

                idx += total_block_size
                self.blocks_parsed += 1

        self.current_offset = idx
        return False, False, n, 0
