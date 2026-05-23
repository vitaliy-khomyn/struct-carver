import struct
from typing import List, Tuple
from .base import BaseFormatParser


class ZIPParser(BaseFormatParser):
    """
    Phase 3 Parser: Handles hierarchical binary ZIP formats (and DOCX/XLSX).
    ZIP files contain multiple Local File Headers ('PK\\x03\\x04').
    To remain compatible with the StackEngine, this parser tracks an internal
    state and only pushes an opening tag on the first Local File Header,
    and closes it when it encounters the End of Central Directory ('PK\\x05\\x06').
    """
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.in_data_descriptor = False
        self.compressed_bytes_processed = 0

    def clone(self) -> 'ZIPParser':
        new_parser = ZIPParser()
        new_parser.is_open = self.is_open
        new_parser.in_data_descriptor = self.in_data_descriptor
        new_parser.compressed_bytes_processed = self.compressed_bytes_processed
        return new_parser

    def reset(self):
        self.is_open = False
        self.in_data_descriptor = False
        self.compressed_bytes_processed = 0

    def state_tuple(self) -> tuple:
        return (self.is_open, self.in_data_descriptor, self.compressed_bytes_processed)

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'PK\x03\x04']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'PK\x05\x06']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        if not self.is_open:
            start_idx = data.find(b'PK\x03\x04')
            if start_idx != -1:
                self.is_open = True
                # align parsing to start exactly at the first header
                data = data[start_idx:]
            else:
                # if not opened and no header found in the first chunk, corrupt
                return True, False, 0, 0

        idx = 0
        n = len(data)

        # skip remaining bytes from a previously parsed, spanning chunk
        if bytes_remaining > 0:
            if n <= bytes_remaining:
                return False, False, n, bytes_remaining - n
            else:
                idx = bytes_remaining
                bytes_remaining = 0

        # If we are in the middle of scanning for a data descriptor from a previous chunk
        if self.in_data_descriptor:
            desc_idx = data.find(b'PK\x07\x08', idx)
            found_valid = False
            while desc_idx != -1:
                if n - desc_idx >= 16:
                    comp_size_from_desc = struct.unpack('<I', data[desc_idx + 8 : desc_idx + 12])[0]
                    calculated_comp_size = self.compressed_bytes_processed + (desc_idx - idx)
                    if comp_size_from_desc == calculated_comp_size:
                        idx = desc_idx + 16
                        self.in_data_descriptor = False
                        self.compressed_bytes_processed = 0
                        found_valid = True
                        break
                else:
                    # Need more bytes to validate the descriptor
                    return False, False, n, 16 - (n - desc_idx)
                desc_idx = data.find(b'PK\x07\x08', desc_idx + 1)

            if not found_valid:
                # We haven't found the descriptor in this chunk.
                # All bytes in this chunk after 'idx' are part of the compressed data.
                self.compressed_bytes_processed += (n - idx)
                return False, False, n, 0

        while idx < n:
            # find the next relevant ZIP signature
            next_local = data.find(b'PK\x03\x04', idx)
            next_central = data.find(b'PK\x01\x02', idx)
            next_end = data.find(b'PK\x05\x06', idx)

            valid_sigs = [p for p in [next_local, next_central, next_end] if p != -1]
            if not valid_sigs:
                break  # waiting for more data to complete the block

            next_sig = min(valid_sigs)

            if next_sig == next_end:
                if n - next_sig >= 22:
                    # 22 bytes is the minimum size of the End of Central Directory
                    return False, True, next_sig + 22, 0
                else:
                    return False, False, n, 22 - (n - next_sig)

            elif next_sig == next_central:
                if n - next_sig < 46:
                    return False, False, n, 46 - (n - next_sig)

                # unpack Central Directory File Header lengths
                fn_len, ef_len, fc_len = struct.unpack('<HHH', data[next_sig+28:next_sig+34])
                total_size = 46 + fn_len + ef_len + fc_len

                if n - next_sig < total_size:
                    return False, False, n, total_size - (n - next_sig)
                idx = next_sig + total_size

            elif next_sig == next_local:
                if n - next_sig < 30:
                    return False, False, n, 30 - (n - next_sig)

                # check general purpose bit flag (offset 6) for data descriptor presence
                flags = struct.unpack('<H', data[next_sig+6:next_sig+8])[0]
                has_data_descriptor = bool(flags & 0x0008)

                # unpack Local File Header lengths to accurately skip compressed data
                comp_size = struct.unpack('<I', data[next_sig+18:next_sig+22])[0]
                fn_len, ef_len = struct.unpack('<HH', data[next_sig+26:next_sig+30])

                if has_data_descriptor:
                    header_end = next_sig + 30 + fn_len + ef_len
                    # Look for the descriptor in the remaining part of this chunk
                    desc_idx = data.find(b'PK\x07\x08', header_end)
                    found_valid = False
                    while desc_idx != -1:
                        if n - desc_idx >= 16:
                            comp_size_from_desc = struct.unpack('<I', data[desc_idx + 8 : desc_idx + 12])[0]
                            calculated_comp_size = desc_idx - header_end
                            if comp_size_from_desc == calculated_comp_size:
                                idx = desc_idx + 16
                                found_valid = True
                                break
                        else:
                            return False, False, n, 16 - (n - desc_idx)
                        desc_idx = data.find(b'PK\x07\x08', desc_idx + 1)

                    if not found_valid:
                        self.in_data_descriptor = True
                        self.compressed_bytes_processed = n - header_end
                        return False, False, n, 0
                    continue

                total_size = 30 + fn_len + ef_len + comp_size

                if n - next_sig < total_size:
                    return False, False, n, total_size - (n - next_sig)
                idx = next_sig + total_size

        return False, False, n, 0
