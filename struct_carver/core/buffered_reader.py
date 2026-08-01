"""Buffered disk cluster reader for Struct Carver!

This module provides the BufferedClusterReader class, which pulls large chunks
of raw disk image data into memory buffers to reduce I/O system calls during scanning.
"""

class BufferedClusterReader:
    """A custom buffered disk reader for large raw forensic images.

    Pulls large chunks of data into memory to reduce the system call overhead
    of reading cluster-by-cluster, while supporting the seek() and tell() methods
    required for gap-jumping heuristics.
    """

    def __init__(self, file_path: str, buffer_size: int = 16 * 1024 * 1024, lookbehind: int = 4 * 1024 * 1024):
        """Initializes the buffered cluster reader.

        Args:
            file_path (str): Path to the image file to read.
            buffer_size (int, optional): Buffer cache size in bytes (default: 16MB).
            lookbehind (int, optional): Buffer rewind lookbehind size in bytes (default: 4MB).
        """
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
