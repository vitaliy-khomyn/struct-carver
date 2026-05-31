"""PDF format parser for Struct Carver!

This module provides the PDFParser class, which validates PDF stream syntax,
length tags, and object delimiters, supporting gap-jumping over non-PDF clusters.
"""

import re
from typing import List, Tuple
from ..base import BaseFormatParser


class PDFParser(BaseFormatParser):
    """Parser for PDF documents that tracks stream lengths and PDF markers.

    Attributes:
        is_open (bool): True if the parser has successfully matched a PDF header.
        pending_endstream (bool): True if looking for 'endstream' token in next chunk.
        pending_bytes_needed (int): Number of bytes needed to finish matching 'endstream'.
        header_verified (bool): True if the header was verified.
    """

    engine_type = "binary"
    # pdfs can be heavily fragmented across large images; allow searching the
    # full image (10000 clusters = 40 MB) before giving up on a fragment.
    max_gap_clusters = 10000

    def __init__(self):
        """Initializes the PDF parser state and length regex."""
        self.is_open = False
        self.length_pattern = re.compile(rb'/Length\s+(\d+)')
        self.pending_endstream = False
        self.pending_bytes_needed = 0
        self.header_verified = False

    def clone(self) -> 'PDFParser':
        """Creates a clone of the parser with the current state.

        Returns:
            PDFParser: The cloned parser instance.
        """
        new_parser = PDFParser()
        new_parser.is_open = self.is_open
        new_parser.pending_endstream = self.pending_endstream
        new_parser.pending_bytes_needed = self.pending_bytes_needed
        new_parser.header_verified = self.header_verified
        return new_parser

    def reset(self):
        """Resets the parser state back to initial default values."""
        self.is_open = False
        self.pending_endstream = False
        self.pending_bytes_needed = 0
        self.header_verified = False

    def state_tuple(self) -> tuple:
        """Returns a representation of the parser state for caching.

        Returns:
            tuple: representation of parser state.
        """
        return (self.is_open, self.pending_endstream, self.pending_bytes_needed, self.header_verified)

    @property
    def header_signatures(self) -> List[bytes]:
        """Gets the list of header signature bytes.

        Returns:
            List[bytes]: Header signature list.
        """
        return [b'%PDF-', b'%pdf-']

    @property
    def footer_signatures(self) -> List[bytes]:
        """Gets the list of footer signature bytes.

        Returns:
            List[bytes]: Footer signature list.
        """
        return [b'%%eof']

    def extract_tags(self, data: bytes) -> Tuple[List[Tuple[str, bool]], int]:
        """Stub implementation for tag extraction (unused for binary formats).

        Args:
            data (bytes): Data block.

        Returns:
            Tuple[List[Tuple[str, bool]], int]: Empty tag list and zero offset.
        """
        return [], 0

    def gap_jump_verify(self, data: bytes) -> bool:
        """Verifies if the candidate cluster looks like valid continuation data.

        Args:
            data (bytes): Candidate cluster data block.

        Returns:
            bool: True if the cluster should be accepted as continuation,
                False if it starts with a known conflicting binary signature.
        """
        if len(data) < 4:
            return True
        # reject clusters that start with a definite non-PDF file signature
        non_pdf_signatures = [
            b'\xFF\xD8\xFF',           # JPEG
            b'\x89PNG',                # PNG
            b'PK\x03\x04',            # ZIP / DOCX / XLSX
            b'PK\x05\x06',            # ZIP empty
            b'Rar!',                   # RAR
            b'RIFF',                   # WAV / AVI
            b'\x1F\x8B',              # GZIP
            b'BM',                     # BMP
            b'\xFF\xFB', b'\xFF\xF3',  # MP3
            b'ID3',                    # MP3 ID3
            b'OggS',                   # OGG
            b'\x00\x00\x00\x18ftyp',  # MP4
            b'FLV',                    # FLV
            b'GIF8',                   # GIF
            b'II*\x00', b'MM\x00*',   # TIFF
        ]
        for sig in non_pdf_signatures:
            if data.startswith(sig):
                return False
        return True

    def _validate_endstream(self, data_to_parse: bytes) -> Tuple[bool, bytes]:
        """Validates that the given data block starts with the endstream keyword.

        Args:
            data_to_parse (bytes): Segment following a stream payload.

        Returns:
            Tuple[bool, bytes]: A tuple of:
                - is_corrupted (bool): True if validation failed.
                - remaining_data (bytes): Sliced bytes after 'endstream'.
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
        """Analyzes a binary cluster to locate PDF elements and stream offsets.

        Args:
            data (bytes): Input data block cluster.
            bytes_remaining (int): Expected remaining stream bytes (if in mid-stream).

        Returns:
            Tuple[bool, bool, int, int]: A tuple of:
                - is_corrupted (bool): True if structure is malformed.
                - is_complete (bool): True if %%eof footer is reached.
                - bytes_to_advance (int): Position cursor movement offset.
                - bytes_remaining (int): Next remaining bytes expectation.
        """
        if self.pending_endstream:
            self.pending_endstream = False
            needed = getattr(self, 'pending_bytes_needed', 9)
            if needed == 9:
                data = data.lstrip(b'\r\n')
            suffix = b'endstream'[-needed:]
            if data.startswith(suffix):
                data = data[needed:]
                data_to_parse = data
                if bytes_remaining == -1:
                    bytes_remaining = 0
            else:
                if bytes_remaining == -1:
                    data_to_parse = data
                else:
                    return True, False, 0, 0
        else:
            data_to_parse = data

        if not self.is_open:
            if b'%pdf-' in data.lower():
                self.is_open = True
                self.header_verified = True
            else:
                return True, False, 0, 0

        if bytes_remaining > 0:
            if len(data) < bytes_remaining:
                return False, False, len(data), bytes_remaining - len(data)
            else:
                # stream finished in this chunk, validate that 'endstream' follows
                data_to_parse = data[bytes_remaining:]
                bytes_remaining = 0
                is_corr, remaining_data = self._validate_endstream(data_to_parse)
                if is_corr:
                    return True, False, 0, 0
                data_to_parse = remaining_data
        elif bytes_remaining == -1:
            end_stream_idx = data.find(b'endstream')
            if end_stream_idx != -1:
                data_to_parse = data[end_stream_idx + 9:]
                bytes_remaining = 0
            else:
                # check for split endstream at the end of the chunk
                found_split = False
                for length in range(8, 0, -1):
                    suffix = data[-length:]
                    if b'endstream'.startswith(suffix):
                        self.pending_endstream = True
                        self.pending_bytes_needed = 9 - length
                        found_split = True
                        break
                return False, False, len(data), -1

        # find streams and calculate future byte offsets
        idx_stream = 0
        while idx_stream < len(data_to_parse):
            match = re.search(rb'stream[\r\n]', data_to_parse[idx_stream:])
            if not match:
                break

            stream_idx = idx_stream + match.start()
            stream_start = idx_stream + match.end()
            pre_stream = data_to_parse[:stream_idx]
            lengths = list(self.length_pattern.finditer(pre_stream))

            if lengths:
                length_val = int(lengths[-1].group(1))
                data_after_stream = len(data_to_parse) - stream_start

                if data_after_stream < length_val:
                    bytes_remaining = length_val - data_after_stream
                    break  # stream spills over to next chunk
                else:
                    after_stream = data_to_parse[stream_start + length_val:]
                    is_corr, remaining_data = self._validate_endstream(after_stream)
                    if is_corr:
                        return True, False, 0, 0
                    idx_stream = len(data_to_parse) - len(remaining_data)
            else:
                # unknown length stream (indirect reference)
                end_stream_idx = data_to_parse.find(b'endstream', stream_start)
                if end_stream_idx != -1:
                    idx_stream = end_stream_idx + 9
                else:
                    bytes_remaining = -1
                    break

        if bytes_remaining == 0 and not self.pending_endstream:
            end_idx = data_to_parse.lower().find(b'%%eof', idx_stream)
            if end_idx != -1:
                advance = len(data) - len(data_to_parse) + end_idx + 5
                return False, True, advance, 0

        return False, False, len(data), bytes_remaining
