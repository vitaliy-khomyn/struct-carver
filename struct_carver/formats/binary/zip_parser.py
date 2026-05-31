"""ZIP format parser for Struct Carver!

This module provides the ZIPParser class, which parses ZIP archives (including office
docx/xlsx formats) by tracking local file headers, data descriptors, and directory markers.
"""

import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class ZIPParser(BaseFormatParser):
    """Parser for hierarchical binary ZIP formats (and DOCX/XLSX).

    ZIP files contain multiple Local File Headers ('PK\\x03\\x04').
    This parser tracks an internal state and only pushes an opening tag on the
    first Local File Header, and closes it when it encounters the End of Central
    Directory ('PK\\x05\\x06').

    Attributes:
        is_open (bool): True if the parser has successfully matched the ZIP header.
        header_verified (bool): True if the header structure has been verified.
        in_data_descriptor (bool): True if currently scanning for a data descriptor.
        compressed_bytes_processed (int): Total compressed payload bytes processed.
        pending_type (str): Type of structural block currently split across chunks.
        pending_bytes (bytearray): Buffered bytes of a split block.
        bytes_to_skip (int): Bytes of payload/directory data to bypass.
        pending_var_len (int): Full size of a variable-length split block.
        lookbehind (bytes): Cached bytes from the end of the previous chunk.
    """

    engine_type = "binary"

    def __init__(self):
        """Initializes the ZIP parser state."""
        self.is_open = False
        self.header_verified = False
        self.in_data_descriptor = False
        self.compressed_bytes_processed = 0
        
        # state for handling split structures
        self.pending_type = None
        self.pending_bytes = bytearray()
        self.bytes_to_skip = 0
        self.pending_var_len = 0
        self.lookbehind = b""

    def clone(self) -> 'ZIPParser':
        """Creates a clone of the parser with the current state.

        Returns:
            ZIPParser: The cloned parser instance.
        """
        new_parser = ZIPParser()
        new_parser.is_open = self.is_open
        new_parser.header_verified = self.header_verified
        new_parser.in_data_descriptor = self.in_data_descriptor
        new_parser.compressed_bytes_processed = self.compressed_bytes_processed
        
        new_parser.pending_type = self.pending_type
        new_parser.pending_bytes = bytearray(self.pending_bytes)
        new_parser.bytes_to_skip = self.bytes_to_skip
        new_parser.pending_var_len = self.pending_var_len
        new_parser.lookbehind = self.lookbehind
        return new_parser

    def reset(self):
        """Resets the parser state back to initial values."""
        self.is_open = False
        self.header_verified = False
        self.in_data_descriptor = False
        self.compressed_bytes_processed = 0
        
        self.pending_type = None
        self.pending_bytes = bytearray()
        self.bytes_to_skip = 0
        self.pending_var_len = 0
        self.lookbehind = b""

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

        Returns:
            tuple: representation of parser state.
        """
        return (
            self.is_open,
            self.header_verified,
            self.in_data_descriptor,
            self.compressed_bytes_processed,
            self.pending_type,
            bytes(self.pending_bytes),
            self.bytes_to_skip,
            self.pending_var_len,
            self.lookbehind
        )

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the list of header signature bytes.

        Returns:
            List[bytes]: Header signature list.
        """
        return [b'PK\x03\x04']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the list of footer signature bytes.

        Returns:
            List[bytes]: Footer signature list.
        """
        return [b'PK\x05\x06']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Stub implementation for tag extraction (unused for binary formats).

        Args:
            data (bytes): Data block.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: Empty tag list and zero offset.
        """
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        """Analyzes a binary data chunk, preserving lookbehind bytes for the next check.

        Args:
            data (bytes): Input data block cluster.
            bytes_remaining (int): Expected remaining payload/stream bytes.

        Returns:
            Tuple[bool, bool, int, int]: A tuple of:
                - is_corrupted (bool): True if ZIP structure is malformed.
                - is_complete (bool): True if EOF footer signature is reached.
                - bytes_to_advance (int): Position cursor movement offset.
                - bytes_remaining (int): Next remaining bytes expectation.
        """
        result = self._analyze_binary_impl(data, bytes_remaining)
        self.lookbehind = data[-3:] if len(data) >= 3 else data
        return result

    def _analyze_binary_impl(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        """Internal binary analysis logic handling split header boundaries.

        Args:
            data (bytes): Input data block cluster.
            bytes_remaining (int): Expected remaining payload/stream bytes.

        Returns:
            Tuple[bool, bool, int, int]: Same parser status tuple.
        """
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

        # skip remaining bytes of payload/directory data
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        L = len(self.lookbehind)
        search_data = self.lookbehind + data

        # process any pending split structures
        if self.pending_type is not None:
            if self.pending_type == 'local_header':
                target_len = 30
            elif self.pending_type == 'local_header_full':
                target_len = self.pending_var_len
            elif self.pending_type == 'central_fixed':
                target_len = 46
            elif self.pending_type == 'central_var':
                target_len = self.pending_var_len
            elif self.pending_type == 'end_of_central':
                target_len = 22
            elif self.pending_type == 'data_descriptor':
                target_len = 16
            else:
                target_len = 0

            needed = target_len - len(self.pending_bytes)
            if needed > 0:
                take = min(n - idx, needed)
                self.pending_bytes.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_bytes) < target_len:
                    return False, False, n, target_len - len(self.pending_bytes)

            accumulated_bytes = bytes(self.pending_bytes)
            current_type = self.pending_type
            self.pending_type = None
            self.pending_bytes = bytearray()

            if current_type == 'local_header':
                flags = struct.unpack('<H', accumulated_bytes[6:8])[0]
                has_data_descriptor = bool(flags & 0x0008)
                comp_size = struct.unpack('<I', accumulated_bytes[18:22])[0]
                fn_len, ef_len = struct.unpack('<HH', accumulated_bytes[26:30])

                self.header_verified = True
                total_header_len = 30 + fn_len + ef_len

                if n - idx < fn_len + ef_len:
                    self.pending_type = 'local_header_full'
                    self.pending_bytes = bytearray(accumulated_bytes)
                    self.pending_bytes.extend(data[idx:])
                    self.pending_var_len = total_header_len
                    idx = n
                    return False, False, n, total_header_len - len(self.pending_bytes)
                else:
                    idx += fn_len + ef_len
                    if has_data_descriptor:
                        self.in_data_descriptor = True
                        self.compressed_bytes_processed = 0
                    else:
                        self.bytes_to_skip = comp_size
                        if idx < n:
                            skip_amount = min(n - idx, self.bytes_to_skip)
                            idx += skip_amount
                            self.bytes_to_skip -= skip_amount

            elif current_type == 'local_header_full':
                flags = struct.unpack('<H', accumulated_bytes[6:8])[0]
                has_data_descriptor = bool(flags & 0x0008)
                comp_size = struct.unpack('<I', accumulated_bytes[18:22])[0]
                fn_len, ef_len = struct.unpack('<HH', accumulated_bytes[26:30])

                self.header_verified = True

                if has_data_descriptor:
                    self.in_data_descriptor = True
                    self.compressed_bytes_processed = 0
                else:
                    self.bytes_to_skip = comp_size
                    if idx < n:
                        skip_amount = min(n - idx, self.bytes_to_skip)
                        idx += skip_amount
                        self.bytes_to_skip -= skip_amount

            elif current_type == 'central_fixed':
                fn_len, ef_len, fc_len = struct.unpack('<HHH', accumulated_bytes[28:34])
                var_len = fn_len + ef_len + fc_len
                self.bytes_to_skip = var_len
                if idx < n:
                    skip_amount = min(n - idx, self.bytes_to_skip)
                    idx += skip_amount
                    self.bytes_to_skip -= skip_amount

            elif current_type == 'central_var':
                pass

            elif current_type == 'end_of_central':
                return False, True, idx, 0

            elif current_type == 'data_descriptor':
                comp_size_from_desc = struct.unpack('<I', accumulated_bytes[8:12])[0]
                if comp_size_from_desc == self.compressed_bytes_processed:
                    self.in_data_descriptor = False
                    self.compressed_bytes_processed = 0
                else:
                    self.compressed_bytes_processed += len(accumulated_bytes)

        # if we are in the middle of scanning for a data descriptor
        if self.in_data_descriptor:
            start_search_from = idx + L if idx > 0 else 0
            desc_idx_search = search_data.find(b'PK\x07\x08', start_search_from)
            found_valid = False
            while desc_idx_search != -1:
                desc_idx = desc_idx_search - L
                if len(search_data) - desc_idx_search >= 16:
                    comp_size_from_desc = struct.unpack('<I', search_data[desc_idx_search + 8 : desc_idx_search + 12])[0]
                    calculated_comp_size = self.compressed_bytes_processed + desc_idx
                    if comp_size_from_desc == calculated_comp_size:
                        idx = desc_idx + 16
                        self.in_data_descriptor = False
                        self.compressed_bytes_processed = 0
                        found_valid = True
                        break
                else:
                    self.pending_type = 'data_descriptor'
                    self.pending_bytes = bytearray(search_data[desc_idx_search:])
                    self.compressed_bytes_processed += desc_idx
                    idx = n
                    return False, False, n, 16 - len(self.pending_bytes)
                desc_idx_search = search_data.find(b'PK\x07\x08', desc_idx_search + 1)

            if not found_valid:
                self.compressed_bytes_processed += (n - idx)
                return False, False, n, 0

        while idx < n:
            start_search_from = idx + L if idx > 0 else 0
            next_local = search_data.find(b'PK\x03\x04', start_search_from)
            next_central = search_data.find(b'PK\x01\x02', start_search_from)
            next_end = search_data.find(b'PK\x05\x06', start_search_from)

            valid_sigs_search = [p for p in [next_local, next_central, next_end] if p != -1]
            if not valid_sigs_search:
                if self.in_data_descriptor:
                    self.compressed_bytes_processed += (n - idx)
                    return False, False, n, 0
                else:
                    if n - idx >= 4:
                        return True, False, idx, 0
                    break

            next_sig_search = min(valid_sigs_search)
            next_sig = next_sig_search - L
            if next_sig > idx:
                if self.in_data_descriptor:
                    self.compressed_bytes_processed += (next_sig - idx)
                    idx = next_sig
                else:
                    return True, False, idx, 0

            if next_sig_search == next_end:
                if len(search_data) - next_sig_search >= 22:
                    return False, True, next_sig + 22, 0
                else:
                    self.pending_type = 'end_of_central'
                    self.pending_bytes = bytearray(search_data[next_sig_search:])
                    idx = n
                    return False, False, n, 22 - len(self.pending_bytes)

            elif next_sig_search == next_central:
                if len(search_data) - next_sig_search < 46:
                    self.pending_type = 'central_fixed'
                    self.pending_bytes = bytearray(search_data[next_sig_search:])
                    idx = n
                    return False, False, n, 46 - len(self.pending_bytes)

                fn_len, ef_len, fc_len = struct.unpack('<HHH', search_data[next_sig_search + 28 : next_sig_search + 34])
                total_size = 46 + fn_len + ef_len + fc_len

                if len(search_data) - next_sig_search < total_size:
                    self.pending_type = 'central_var'
                    self.pending_bytes = bytearray(search_data[next_sig_search:])
                    self.pending_var_len = total_size
                    idx = n
                    return False, False, n, total_size - len(self.pending_bytes)
                idx = next_sig + total_size

            elif next_sig_search == next_local:
                if len(search_data) - next_sig_search < 30:
                    self.pending_type = 'local_header'
                    self.pending_bytes = bytearray(search_data[next_sig_search:])
                    idx = n
                    return False, False, n, 30 - len(self.pending_bytes)

                flags = struct.unpack('<H', search_data[next_sig_search + 6 : next_sig_search + 8])[0]
                has_data_descriptor = bool(flags & 0x0008)
                comp_size = struct.unpack('<I', search_data[next_sig_search + 18 : next_sig_search + 22])[0]
                fn_len, ef_len = struct.unpack('<HH', search_data[next_sig_search + 26 : next_sig_search + 30])

                self.header_verified = True
                total_header_len = 30 + fn_len + ef_len
                if len(search_data) - next_sig_search < total_header_len:
                    self.pending_type = 'local_header_full'
                    self.pending_bytes = bytearray(search_data[next_sig_search:])
                    self.pending_var_len = total_header_len
                    idx = n
                    return False, False, n, total_header_len - len(self.pending_bytes)

                idx = next_sig + total_header_len
                if has_data_descriptor:
                    self.in_data_descriptor = True
                    self.compressed_bytes_processed = 0
                else:
                    self.bytes_to_skip = comp_size
                    if idx < n:
                        skip_amount = min(n - idx, self.bytes_to_skip)
                        idx += skip_amount
                        self.bytes_to_skip -= skip_amount

        return False, False, n, self.bytes_to_skip
