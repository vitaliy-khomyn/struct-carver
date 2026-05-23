import re
from typing import List, Tuple
from .base import BaseFormatParser


class PDFParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.length_pattern = re.compile(rb'/Length\s+(\d+)')
        self.pending_endstream = False
        self.pending_bytes_needed = 0

    def clone(self) -> 'PDFParser':
        new_parser = PDFParser()
        new_parser.is_open = self.is_open
        new_parser.pending_endstream = self.pending_endstream
        new_parser.pending_bytes_needed = self.pending_bytes_needed
        return new_parser

    def reset(self):
        self.is_open = False
        self.pending_endstream = False
        self.pending_bytes_needed = 0

    def state_tuple(self) -> tuple:
        return (self.is_open, self.pending_endstream, self.pending_bytes_needed)

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'%pdf-']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'%%eof']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def _validate_endstream(self, data_to_parse: bytes) -> Tuple[bool, bytes]:
        """
        Validates that data_to_parse starts with 'endstream'.
        Returns (is_corrupted, remaining_data).
        """
        stripped = data_to_parse.lstrip(b'\r\n')
        if not stripped:
            self.pending_endstream = True
            self.pending_bytes_needed = 9
            return False, b""

        if len(stripped) >= 9:
            if not stripped.startswith(b'endstream'):
                return True, b""
            return False, stripped[9:]
        else:
            if not b'endstream'.startswith(stripped):
                return True, b""
            self.pending_endstream = True
            self.pending_bytes_needed = 9 - len(stripped)
            return False, b""

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
        if self.pending_endstream:
            self.pending_endstream = False
            needed = getattr(self, 'pending_bytes_needed', 9)
            if needed == 9:
                data = data.lstrip(b'\r\n')
            suffix = b'endstream'[-needed:]
            if not data.startswith(suffix):
                return True, False, 0, 0
            data = data[needed:]

        if not self.is_open:
            if b'%pdf-' in data.lower():
                self.is_open = True
            else:
                return True, False, 0, 0

        if bytes_remaining > 0:
            if len(data) < bytes_remaining:
                return False, False, len(data), bytes_remaining - len(data)
            else:
                # Stream finished in this chunk, validate that 'endstream' follows
                data_to_parse = data[bytes_remaining:]
                bytes_remaining = 0
                is_corr, remaining_data = self._validate_endstream(data_to_parse)
                if is_corr:
                    return True, False, 0, 0
                data_to_parse = remaining_data
        else:
            data_to_parse = data

        # find streams and calculate future byte offsets
        for match in re.finditer(rb'stream[\r\n]', data_to_parse):
            stream_idx = match.start()
            pre_stream = data_to_parse[:stream_idx]
            lengths = list(self.length_pattern.finditer(pre_stream))
            if lengths:
                length_val = int(lengths[-1].group(1))
                stream_start = match.end()
                data_after_stream = len(data_to_parse) - stream_start

                if data_after_stream < length_val:
                    bytes_remaining = length_val - data_after_stream
                    break  # stream spills over to next chunk
                else:
                    after_stream = data_to_parse[stream_start + length_val:]
                    is_corr, remaining_data = self._validate_endstream(after_stream)
                    if is_corr:
                        return True, False, 0, 0

        if bytes_remaining == 0 and not self.pending_endstream:
            end_idx = data_to_parse.lower().find(b'%%eof')
            if end_idx != -1:
                advance = len(data) - len(data_to_parse) + end_idx + 5
                return False, True, advance, 0

        return False, False, len(data), bytes_remaining
