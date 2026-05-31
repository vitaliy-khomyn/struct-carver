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
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_block = bytearray()

    def clone(self) -> 'RARParser':
        new_parser = RARParser()
        new_parser.is_open = self.is_open
        new_parser.rar_version = self.rar_version
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.current_offset = self.current_offset
        new_parser.blocks_parsed = self.blocks_parsed
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.pending_block = bytearray(self.pending_block)
        return new_parser

    def reset(self):
        self.is_open = False
        self.rar_version = 0
        self.bytes_to_skip = 0
        self.current_offset = 0
        self.blocks_parsed = 0
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_block = bytearray()

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.rar_version,
            self.bytes_to_skip,
            self.current_offset,
            self.blocks_parsed,
            self.header_verified,
            bytes(self.pending_header),
            bytes(self.pending_block)
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
            if not self.pending_header:
                sig4 = data.find(b'Rar!\x1a\x07\x00')
                sig5 = data.find(b'Rar!\x1a\x07\x01\x00')
                valid_sigs = [p for p in [sig4, sig5] if p != -1]
                if not valid_sigs:
                    return True, False, 0, 0
                idx = min(valid_sigs)

            if len(self.pending_header) < 7:
                needed = 7 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 7:
                    return False, False, n, 7 - len(self.pending_header)

            if bytes(self.pending_header).startswith(b'Rar!\x1a\x07\x00'):
                self.rar_version = 4
                header_len = 7
            elif bytes(self.pending_header).startswith(b'Rar!\x1a\x07\x01'):
                self.rar_version = 5
                header_len = 8
                if len(self.pending_header) < 8:
                    needed = 8 - len(self.pending_header)
                    take = min(n - idx, needed)
                    self.pending_header.extend(data[idx : idx + take])
                    idx += take
                    if len(self.pending_header) < 8:
                        return False, False, n, 8 - len(self.pending_header)
            else:
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            self.pending_header = bytearray()

        # Skip bytes requested from previous chunk
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            self.current_offset += skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        while idx < n:
            if self.rar_version == 4:
                # RAR4 Block Parser
                # We need to accumulate at least 7 bytes for the basic header
                if len(self.pending_block) < 7:
                    needed = 7 - len(self.pending_block)
                    take = min(n - idx, needed)
                    self.pending_block.extend(data[idx : idx + take])
                    idx += take
                    if len(self.pending_block) < 7:
                        return False, False, n, 7 - len(self.pending_block)

                # Unpack basic header fields
                h_crc, h_type, h_flags, h_size = struct.unpack('<HBHH', bytes(self.pending_block[:7]))

                header_len = 7
                if h_flags & 0x8000:
                    header_len = 11
                    if len(self.pending_block) < 11:
                        needed = 11 - len(self.pending_block)
                        take = min(n - idx, needed)
                        self.pending_block.extend(data[idx : idx + take])
                        idx += take
                        if len(self.pending_block) < 11:
                            return False, False, n, 11 - len(self.pending_block)

                block_hdr_bytes = bytes(self.pending_block[:header_len])
                if h_flags & 0x8000:
                    add_size = struct.unpack('<I', block_hdr_bytes[7:11])[0]
                else:
                    add_size = 0

                total_block_size = h_size + add_size

                if h_size < 7 or h_size > 1024 * 1024:
                    if self.blocks_parsed > 0:
                        return False, True, idx - len(self.pending_block), 0
                    else:
                        return True, False, 0, 0

                # Terminate on terminator block
                if h_type == 0x7B:
                    term_size = h_size
                    if len(self.pending_block) < term_size:
                        needed = term_size - len(self.pending_block)
                        take = min(n - idx, needed)
                        self.pending_block.extend(data[idx : idx + take])
                        idx += take
                        if len(self.pending_block) < term_size:
                            return False, False, n, term_size - len(self.pending_block)
                    
                    write_end = idx - len(self.pending_block) + term_size
                    self.pending_block = bytearray()
                    return False, True, write_end, 0

                # Skip the block content
                self.bytes_to_skip = total_block_size - len(self.pending_block)
                self.pending_block = bytearray()
                self.blocks_parsed += 1

                if self.bytes_to_skip > 0:
                    skip_amount = min(n - idx, self.bytes_to_skip)
                    idx += skip_amount
                    self.bytes_to_skip -= skip_amount
                    if self.bytes_to_skip > 0:
                        return False, False, n, self.bytes_to_skip

            else:
                # RAR5 Block Parser
                # We need at least 4 bytes for CRC
                if len(self.pending_block) < 4:
                    needed = 4 - len(self.pending_block)
                    take = min(n - idx, needed)
                    self.pending_block.extend(data[idx : idx + take])
                    idx += take
                    if len(self.pending_block) < 4:
                        return False, False, n, 4 - len(self.pending_block)

                # Now read the header size VINT (starting at offset 4 of block header)
                h_size, h_size_len = self._read_vint(bytes(self.pending_block), 4)
                while h_size_len == 0 or h_size < 0:
                    if idx >= n:
                        return False, False, n, 1
                    self.pending_block.append(data[idx])
                    idx += 1
                    h_size, h_size_len = self._read_vint(bytes(self.pending_block), 4)

                total_header_size = 4 + h_size_len + h_size
                if len(self.pending_block) < total_header_size:
                    needed = total_header_size - len(self.pending_block)
                    take = min(n - idx, needed)
                    self.pending_block.extend(data[idx : idx + take])
                    idx += take
                    if len(self.pending_block) < total_header_size:
                        return False, False, n, total_header_size - len(self.pending_block)

                hdr_bytes = bytes(self.pending_block[:total_header_size])
                vint_offset = 4 + h_size_len
                h_type, h_type_len = self._read_vint(hdr_bytes, vint_offset)
                if h_type_len == 0:
                    if self.blocks_parsed > 0:
                        return False, True, idx - len(self.pending_block), 0
                    return True, False, 0, 0
                vint_offset += h_type_len

                h_flags, h_flags_len = self._read_vint(hdr_bytes, vint_offset)
                if h_flags_len == 0:
                    if self.blocks_parsed > 0:
                        return False, True, idx - len(self.pending_block), 0
                    return True, False, 0, 0
                vint_offset += h_flags_len

                extra_size = 0
                if h_flags & 0x0001:
                    extra_size, extra_size_len = self._read_vint(hdr_bytes, vint_offset)
                    if extra_size_len == 0:
                        return True, False, 0, 0
                    vint_offset += extra_size_len

                data_size = 0
                if h_flags & 0x0002:
                    data_size, data_size_len = self._read_vint(hdr_bytes, vint_offset)
                    if data_size_len == 0:
                        return True, False, 0, 0
                    vint_offset += data_size_len

                total_block_size = total_header_size + data_size

                # Terminate on End of Archive block (type 5)
                if h_type == 5:
                    if len(self.pending_block) < total_block_size:
                        needed = total_block_size - len(self.pending_block)
                        take = min(n - idx, needed)
                        self.pending_block.extend(data[idx : idx + take])
                        idx += take
                        if len(self.pending_block) < total_block_size:
                            return False, False, n, total_block_size - len(self.pending_block)
                    
                    write_end = idx - len(self.pending_block) + total_block_size
                    self.pending_block = bytearray()
                    return False, True, write_end, 0

                # Skip block content
                self.bytes_to_skip = total_block_size - len(self.pending_block)
                self.pending_block = bytearray()
                self.blocks_parsed += 1

                if self.bytes_to_skip > 0:
                    skip_amount = min(n - idx, self.bytes_to_skip)
                    idx += skip_amount
                    self.bytes_to_skip -= skip_amount
                    if self.bytes_to_skip > 0:
                        return False, False, n, self.bytes_to_skip

        self.current_offset = idx
        return False, False, n, 0
