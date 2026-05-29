import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class TIFFParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.total_size = 0

    def clone(self) -> 'TIFFParser':
        new_parser = TIFFParser()
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
        return [b'II*\x00', b'MM\x00*']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)

        if not self.is_open:
            sig_ii = data.find(b'II*\x00')
            sig_mm = data.find(b'MM\x00*')
            valid_sigs = [p for p in [sig_ii, sig_mm] if p != -1]
            if not valid_sigs:
                return True, False, 0, 0

            start_idx = min(valid_sigs)
            self.is_open = True
            
            # Read first IFD offset (offset 4)
            if n - start_idx < 8:
                return False, False, n, 8 - (n - start_idx)

            endian = '<' if data[start_idx : start_idx + 2] == b'II' else '>'
            first_ifd = struct.unpack(f'{endian}I', data[start_idx + 4 : start_idx + 8])[0]

            # Parse IFDs recursively to find the maximum offset
            max_offset = first_ifd
            current_ifd = first_ifd

            type_sizes = {1:1, 2:1, 3:2, 4:4, 5:8, 7:1, 8:2, 9:4, 10:8, 11:4, 12:8}

            # Loop through IFD chains
            visited_ifds = set()
            while current_ifd > 0 and current_ifd < 50 * 1024 * 1024:  # 50MB safety limit
                if current_ifd in visited_ifds:
                    break
                visited_ifds.add(current_ifd)

                if n - start_idx < current_ifd + 2:
                    # Need more data for entry count
                    return False, False, n, (current_ifd + 2) - (n - start_idx)

                num_entries = struct.unpack(f'{endian}H', data[start_idx + current_ifd : start_idx + current_ifd + 2])[0]
                ifd_size = 2 + num_entries * 12 + 4

                if n - start_idx < current_ifd + ifd_size:
                    return False, False, n, (current_ifd + ifd_size) - (n - start_idx)

                # Track StripOffsets and StripByteCounts to calculate image data boundary
                strip_offsets = []
                strip_counts = []

                for i in range(num_entries):
                    entry_offset = current_ifd + 2 + i * 12
                    entry_data = data[start_idx + entry_offset : start_idx + entry_offset + 12]
                    tag, tag_type, count = struct.unpack(f'{endian}HHI', entry_data[0:8])
                    val_offset = struct.unpack(f'{endian}I', entry_data[8:12])[0]

                    type_sz = type_sizes.get(tag_type, 1)
                    total_sz = count * type_sz

                    # If values do not fit in 4 bytes, the value offset points to the value array
                    if total_sz > 4:
                        max_offset = max(max_offset, val_offset + total_sz)
                        
                        # Parse strip offsets/counts to find the maximum image boundary
                        if tag == 273 or tag == 324: # StripOffsets or TileOffsets
                            # Read array of offsets
                            if val_offset + total_sz <= n - start_idx:
                                for j in range(count):
                                    off = struct.unpack(f'{endian}I', data[start_idx + val_offset + j*4 : start_idx + val_offset + j*4 + 4])[0]
                                    strip_offsets.append(off)
                        elif tag == 279 or tag == 325: # StripByteCounts or TileByteCounts
                            if val_offset + total_sz <= n - start_idx:
                                for j in range(count):
                                    # size type can be short(3) or long(4)
                                    if tag_type == 3:
                                        sz = struct.unpack(f'{endian}H', data[start_idx + val_offset + j*2 : start_idx + val_offset + j*2 + 2])[0]
                                    else:
                                        sz = struct.unpack(f'{endian}I', data[start_idx + val_offset + j*4 : start_idx + val_offset + j*4 + 4])[0]
                                    strip_counts.append(sz)
                    else:
                        if tag == 273 or tag == 324: # StripOffsets or TileOffsets
                            strip_offsets.append(val_offset)
                        elif tag == 279 or tag == 325: # StripByteCounts or TileByteCounts
                            strip_counts.append(val_offset)

                # Compute maximum offset of image data strips
                for off, sz in zip(strip_offsets, strip_counts):
                    max_offset = max(max_offset, off + sz)

                # Next IFD offset is the last 4 bytes of the IFD block
                next_ifd_offset = current_ifd + 2 + num_entries * 12
                next_ifd = struct.unpack(f'{endian}I', data[start_idx + next_ifd_offset : start_idx + next_ifd_offset + 4])[0]
                
                max_offset = max(max_offset, next_ifd_offset + 4)
                current_ifd = next_ifd

            self.total_size = max_offset

            bytes_remaining = self.total_size - (n - start_idx)
            if bytes_remaining <= 0:
                return False, True, start_idx + self.total_size, 0
            return False, False, n, bytes_remaining

        if bytes_remaining > 0:
            if n >= bytes_remaining:
                return False, True, bytes_remaining, 0
            else:
                return False, False, n, bytes_remaining - n

        return False, False, n, 0
