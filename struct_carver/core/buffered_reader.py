"""Buffered disk cluster reader.

This module provides the BufferedClusterReader class, which pulls large chunks
of raw disk image data into memory buffers to reduce I/O system calls during scanning.
"""

import os
import re
from typing import List, Tuple, Optional, Any


def discover_segments(file_path: str) -> List[str]:
    """Discovers all chronological part files for a segmented raw disk image.

    Detects common forensic split naming schemes such as:
    - image.001, image.002, image.003
    - image.raw.01, image.raw.02
    - image.dd.001, image.dd.002
    - image.part01.raw, image.part02.raw

    Args:
        file_path (str): Initial image path provided by user.

    Returns:
        List[str]: List of existing contiguous segment file paths in order.
    """
    if not os.path.exists(file_path):
        return []

    dir_name = os.path.dirname(file_path) or "."
    base_name = os.path.basename(file_path)

    # pattern A: extension is digits, e.g. .001, .002
    match_ext = re.match(r'^(.*)\.(\d+)$', base_name)
    if match_ext:
        stem, num_str = match_ext.groups()
        width = len(num_str)
        start_num = int(num_str)
        if start_num in (0, 1):
            segments = []
            curr = start_num
            while True:
                cand_name = f"{stem}.{curr:0{width}d}"
                cand_path = os.path.join(dir_name, cand_name)
                if os.path.exists(cand_path):
                    segments.append(cand_path)
                    curr += 1
                else:
                    break
            if len(segments) > 1:
                return segments

    # pattern B: digits before extension, e.g. .part01.raw or .raw.01
    match_mid = re.match(r'^(.*?)(\d+)(\.[^.]+)$', base_name)
    if match_mid:
        prefix, num_str, ext = match_mid.groups()
        width = len(num_str)
        start_num = int(num_str)
        if start_num in (0, 1):
            segments = []
            curr = start_num
            while True:
                cand_name = f"{prefix}{curr:0{width}d}{ext}"
                cand_path = os.path.join(dir_name, cand_name)
                if os.path.exists(cand_path):
                    segments.append(cand_path)
                    curr += 1
                else:
                    break
            if len(segments) > 1:
                return segments

    return [file_path]


def get_image_size(file_path: str) -> int:
    """Calculates total byte size across all segments of an evidence image.

    Args:
        file_path (str): Path to image file or first segment.

    Returns:
        int: Total size in bytes.
    """
    segments = discover_segments(file_path)
    if not segments:
        return os.path.getsize(file_path) if os.path.exists(file_path) else 0
    return sum(os.path.getsize(s) for s in segments)


class SegmentedStream:
    """A virtual seekable stream presenting multiple segmented image chunks as one contiguous file."""

    def __init__(self, segment_paths: List[str]):
        """Initializes the virtual stream with discovered image segments.

        Args:
            segment_paths (List[str]): List of segment file paths in order.
        """
        self.segment_paths = segment_paths
        self.segment_sizes = [os.path.getsize(p) for p in segment_paths]
        self.total_size = sum(self.segment_sizes)
        self.current_pos = 0
        self._current_handle = None
        self._current_seg_idx = -1

    def _get_handle_for_offset(self, offset: int) -> Tuple[Optional[Any], int]:
        """Finds the open file handle and remaining bytes in the segment for a given global offset."""
        accum = 0
        for idx, sz in enumerate(self.segment_sizes):
            if accum <= offset < accum + sz:
                if self._current_seg_idx != idx:
                    if self._current_handle:
                        self._current_handle.close()
                    self._current_handle = open(self.segment_paths[idx], 'rb')
                    self._current_seg_idx = idx
                self._current_handle.seek(offset - accum)
                return self._current_handle, accum + sz - offset
            accum += sz
        return None, 0

    def seek(self, pos: int, whence: int = 0) -> int:
        """Sets the virtual position in the combined image.

        Args:
            pos (int): Target offset.
            whence (int, optional): Reference position (0: SEEK_SET, 1: SEEK_CUR, 2: SEEK_END).

        Returns:
            int: New virtual stream position.
        """
        if whence == 0:
            self.current_pos = pos
        elif whence == 1:
            self.current_pos += pos
        elif whence == 2:
            self.current_pos = self.total_size + pos
        self.current_pos = max(0, self.current_pos)
        return self.current_pos

    def tell(self) -> int:
        """Returns the current virtual position in the combined image."""
        return self.current_pos

    def read(self, size: int) -> bytes:
        """Reads bytes across segment boundaries transparently."""
        if self.current_pos >= self.total_size or size <= 0:
            return b""
        result = bytearray()
        needed = size
        while needed > 0 and self.current_pos < self.total_size:
            handle, remaining_in_seg = self._get_handle_for_offset(self.current_pos)
            if not handle or remaining_in_seg <= 0:
                break
            to_read = min(needed, remaining_in_seg)
            chunk = handle.read(to_read)
            if not chunk:
                break
            result.extend(chunk)
            self.current_pos += len(chunk)
            needed -= len(chunk)
        return bytes(result)

    def close(self):
        """Closes any open segment file handle."""
        if self._current_handle:
            self._current_handle.close()
            self._current_handle = None
            self._current_seg_idx = -1

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class BufferedClusterReader:
    """A custom buffered disk reader for large raw forensic images.

    Pulls large chunks of data into memory to reduce the system call overhead
    of reading cluster-by-cluster, while supporting the seek() and tell() methods
    required for gap-jumping heuristics.
    """

    def __init__(self, file_path: str, buffer_size: int = 16 * 1024 * 1024, lookbehind: int = 4 * 1024 * 1024):
        """Initializes the buffered cluster reader.

        Args:
            file_path (str): Path to the image file or first segment to read.
            buffer_size (int, optional): Buffer cache size in bytes (default: 16MB).
            lookbehind (int, optional): Buffer rewind lookbehind size in bytes (default: 4MB).
        """
        segments = discover_segments(file_path)
        if len(segments) > 1:
            self.file = SegmentedStream(segments)
        else:
            self.file = open(file_path, 'rb')
        self.buffer_size = buffer_size
        self.buffer = memoryview(b"")
        self.buffer_start_pos = 0
        self.current_pos = 0
        self.eof_pos = -1
        self.lookbehind = lookbehind

    def read(self, size: int) -> bytes:
        """Reads a chunk of bytes from the buffered file.

        Args:
            size (int): Number of bytes to read.

        Returns:
            bytes: The requested data chunk, or empty bytes if EOF is reached.
        """
        if self.eof_pos != -1 and self.current_pos >= self.eof_pos:
            return b""

        buffer_end = self.buffer_start_pos + len(self.buffer)

        # if the read falls outside the cached buffer (either rewinding past start or reading past end)
        if self.current_pos < self.buffer_start_pos or self.current_pos + size > buffer_end:
            # smart alignment: load the buffer so that current_pos is near the beginning,
            # but explicitly preserve a lookbehind window to accommodate f.seek() rewinds.
            read_start = max(0, self.current_pos - self.lookbehind)
            read_size = max(self.buffer_size, size + (self.current_pos - read_start))

            self.file.seek(read_start)
            raw_bytes = self.file.read(read_size)

            # check if the absolute end of the disk image
            if not raw_bytes and self.current_pos >= read_start + len(raw_bytes):
                self.eof_pos = self.current_pos
                return b""

            self.buffer = memoryview(raw_bytes)
            self.buffer_start_pos = read_start
            buffer_end = self.buffer_start_pos + len(self.buffer)

        # handle EOF clipping if the file ends before fulfilling the full requested 'size'
        available_bytes = min(size, buffer_end - self.current_pos)
        if available_bytes <= 0:
            self.eof_pos = self.current_pos
            return b""

        offset = self.current_pos - self.buffer_start_pos
        chunk = self.buffer[offset:offset + available_bytes].tobytes()
        self.current_pos += len(chunk)
        return chunk

    def seek(self, pos: int):
        """Sets the current file cursor position.

        Args:
            pos (int): File offset in bytes.
        """
        self.current_pos = pos

    def tell(self) -> int:
        """Gets the current file cursor position.

        Returns:
            int: The current file offset in bytes.
        """
        return self.current_pos

    def close(self):
        """Closes the underlying raw file stream."""
        self.file.close()

    def __enter__(self):
        """Enters the context manager block."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exits the context manager block, closing the stream."""
        self.close()
