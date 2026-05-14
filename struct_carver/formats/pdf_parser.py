import re
from typing import List, Tuple
from .base import BaseFormatParser


class PDFParser(BaseFormatParser):
    engine_type = "binary"

    def __init__(self):
        self.is_open = False
        self.length_pattern = re.compile(rb'/Length\s+(\d+)')

    def clone(self) -> 'PDFParser':
        new_parser = PDFParser()
        new_parser.is_open = self.is_open
        return new_parser

    def reset(self):
        self.is_open = False

    @property
    def header_signatures(self) -> List[bytes]:
        return [b'%pdf-']

    @property
    def footer_signatures(self) -> List[bytes]:
        return [b'%%eof']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        return [], 0

    def analyze_binary(self, data: bytes, bytes_remaining: int = 0) -> Tuple[bool, bool, int, int]:
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
                if len(data_to_parse.lstrip(b'\r\n')) >= 9 and not data_to_parse.lstrip(b'\r\n').startswith(b'endstream'):
                    return True, False, 0, 0  # Validation failed, cluster is corrupted!
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
                    if len(after_stream.lstrip(b'\r\n')) >= 9 and not after_stream.lstrip(b'\r\n').startswith(b'endstream'):
                        return True, False, 0, 0  # inline validation failed

        if bytes_remaining == 0:
            end_idx = data_to_parse.lower().find(b'%%eof')
            if end_idx != -1:
                advance = len(data) - len(data_to_parse) + end_idx + 5
                return False, True, advance, 0

        return False, False, len(data), bytes_remaining
