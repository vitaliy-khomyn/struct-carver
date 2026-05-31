import struct
from typing import List, Tuple
from ..base import BaseFormatParser


class SQLiteWALParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.page_size = 0
        self.salt1 = 0
        self.salt2 = 0
        self.endian = '>'
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_frame = bytearray()
        self.bytes_to_skip = 0

    def clone(self) -> 'SQLiteWALParser':
        new_parser = SQLiteWALParser()
        new_parser.is_open = self.is_open
        new_parser.page_size = self.page_size
        new_parser.salt1 = self.salt1
        new_parser.salt2 = self.salt2
        new_parser.endian = self.endian
        new_parser.header_verified = self.header_verified
        new_parser.pending_header = bytearray(self.pending_header)
        new_parser.pending_frame = bytearray(self.pending_frame)
        new_parser.bytes_to_skip = self.bytes_to_skip
        return new_parser

    def reset(self):
        self.is_open = False
        self.page_size = 0
        self.salt1 = 0
        self.salt2 = 0
        self.endian = '>'
        self.header_verified = False
        self.pending_header = bytearray()
        self.pending_frame = bytearray()
        self.bytes_to_skip = 0

    def state_tuple(self) -> tuple:
        return (
            self.is_open,
            self.page_size,
            self.salt1,
            self.salt2,
            self.endian,
            self.header_verified,
            bytes(self.pending_header),
            bytes(self.pending_frame),
            self.bytes_to_skip
        )

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'\x37\x7f\x06\x82', b'\x37\x7f\x06\x83']

    @property
    def footer_signatures(self) -> List[bytes]:
        return []

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        n = len(data)
        idx = 0

        if not self.is_open:
            if not self.pending_header:
                sig1 = data.find(b'\x37\x7f\x06\x82')
                sig2 = data.find(b'\x37\x7f\x06\x83')
                valid_sigs = [p for p in [sig1, sig2] if p != -1]
                if not valid_sigs:
                    return True, False, 0, 0
                idx = min(valid_sigs)

            if len(self.pending_header) < 32:
                needed = 32 - len(self.pending_header)
                take = min(n - idx, needed)
                self.pending_header.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_header) < 32:
                    return False, False, n, 32 - len(self.pending_header)

            # Process 32-byte header
            header_block = bytes(self.pending_header[:32])
            magic = header_block[0:4]
            self.endian = '<' if magic == b'\x37\x7f\x06\x82' else '>'
            self.page_size = struct.unpack(f'{self.endian}I', header_block[8:12])[0]
            self.salt1, self.salt2 = struct.unpack(f'{self.endian}II', header_block[16:24])

            if self.page_size == 0 or self.page_size > 65536:
                return True, False, 0, 0

            self.is_open = True
            self.header_verified = True
            self.pending_header = bytearray()

        # Skip bytes
        if self.bytes_to_skip > 0:
            skip_amount = min(n - idx, self.bytes_to_skip)
            idx += skip_amount
            self.bytes_to_skip -= skip_amount
            if self.bytes_to_skip > 0:
                return False, False, n, self.bytes_to_skip

        while idx < n:
            if len(self.pending_frame) < 24:
                needed = 24 - len(self.pending_frame)
                take = min(n - idx, needed)
                self.pending_frame.extend(data[idx : idx + take])
                idx += take
                if len(self.pending_frame) < 24:
                    return False, False, n, 24 - len(self.pending_frame)

            frame_header = bytes(self.pending_frame)
            frame_salt1, frame_salt2 = struct.unpack(f'{self.endian}II', frame_header[8:16])

            if frame_salt1 != self.salt1 or frame_salt2 != self.salt2:
                # Frame mismatch! WAL session ended.
                write_end = idx - len(self.pending_frame)
                self.pending_frame = bytearray()
                return False, True, write_end, 0

            self.pending_frame = bytearray()
            self.bytes_to_skip = self.page_size
            
            if idx < n:
                skip_amount = min(n - idx, self.bytes_to_skip)
                idx += skip_amount
                self.bytes_to_skip -= skip_amount
                if self.bytes_to_skip > 0:
                    return False, False, n, self.bytes_to_skip

        return False, False, n, 0
