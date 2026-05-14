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

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'PK\x03\x04']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'PK\x05\x06']

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

                # unpack Local File Header lengths to accurately skip compressed data
                comp_size = struct.unpack('<I', data[next_sig+18:next_sig+22])[0]
                fn_len, ef_len = struct.unpack('<HH', data[next_sig+26:next_sig+30])

                total_size = 30 + fn_len + ef_len + comp_size

                if n - next_sig < total_size:
                    return False, False, n, total_size - (n - next_sig)
                idx = next_sig + total_size

        return False, False, n, 0
