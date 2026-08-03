"""Cryptographic hashing utilities.

This module provides the CryptoHasher class for generating forensic hashes
(SHA-256, MD5, SHA-1, SHA-512) for carved files and individual raw disk fragments.
"""

import os
import json
import datetime
import hashlib
from typing import Optional, List, Dict, Any


SUPPORTED_HASH_ALGOS = ["sha256", "md5", "sha1", "sha512"]


class CryptoHasher:
    """Computes cryptographic hashes for files and data chunks.

    Attributes:
        algo_name (str): Chosen hashing algorithm identifier.
    """

    def __init__(self, algo_name: str = "sha256"):
        """Initializes the hasher with the requested algorithm.

        Args:
            algo_name (str, optional): Algorithm name (default: "sha256").
        """
        algo_lower = algo_name.lower()
        if algo_lower not in SUPPORTED_HASH_ALGOS:
            raise ValueError(f"Unsupported hash algorithm '{algo_name}'. Supported: {', '.join(SUPPORTED_HASH_ALGOS)}")
        self.algo_name = algo_lower

    def _get_hasher(self):
        """Returns a new hashlib hash instance based on algo_name."""
        if self.algo_name == "sha256":
            return hashlib.sha256()
        elif self.algo_name == "md5":
            return hashlib.md5()
        elif self.algo_name == "sha1":
            return hashlib.sha1()
        elif self.algo_name == "sha512":
            return hashlib.sha512()
        else:
            return hashlib.new(self.algo_name)

    def hash_file(self, file_path: str, chunk_size: int = 1024 * 1024) -> str:
        """Computes the cryptographic hex digest of a file on disk streamingly.

        Args:
            file_path (str): Path to the file.
            chunk_size (int, optional): Buffer read size in bytes (default: 1MB).

        Returns:
            str: Hexadecimal hash digest string.
        """
        if not os.path.exists(file_path):
            return ""

        from struct_carver.core.buffered_reader import discover_segments
        segments = discover_segments(file_path)
        hasher = self._get_hasher()
        target_paths = segments if len(segments) > 1 else [file_path]
        for path in target_paths:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
        return hasher.hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        """Computes the cryptographic hex digest of an in-memory byte buffer.

        Args:
            data (bytes): Raw byte buffer.

        Returns:
            str: Hexadecimal hash digest string.
        """
        hasher = self._get_hasher()
        hasher.update(data)
        return hasher.hexdigest()

    def hash_file_range(self, file_path: str, start_offset: int, size: int, chunk_size: int = 1024 * 1024) -> str:
        """Computes the cryptographic hex digest of a specific byte span in a file on disk streamingly.

        Args:
            file_path (str): Path to the target image file.
            start_offset (int): Starting byte position in the file.
            size (int): Total number of bytes to hash.
            chunk_size (int, optional): Buffer read size in bytes (default: 1MB).

        Returns:
            str: Hexadecimal hash digest string.
        """
        if not os.path.exists(file_path) or size <= 0:
            return ""

        from struct_carver.core.buffered_reader import discover_segments, SegmentedStream
        segments = discover_segments(file_path)
        hasher = self._get_hasher()
        stream = SegmentedStream(segments) if len(segments) > 1 else open(file_path, "rb")
        bytes_left = size
        with stream as f:
            f.seek(start_offset)
            while bytes_left > 0:
                to_read = min(bytes_left, chunk_size)
                chunk = f.read(to_read)
                if not chunk:
                    break
                hasher.update(chunk)
                bytes_left -= len(chunk)
        return hasher.hexdigest()

    def generate_manifest_content(self, files: List[Dict[str, Any]]) -> str:
        """Generates standard checksum manifest content (e.g. for sha256sum).

        Args:
            files (List[Dict[str, Any]]): List of recovered file records with 'filename' and 'file_hash'.

        Returns:
            str: Standard checksum file content formatted as '<hash>  <filename>'.
        """
        lines = []
        for file_entry in files:
            file_hash = file_entry.get("file_hash", "")
            filename = file_entry.get("filename", "")
            if file_hash and filename:
                lines.append(f"{file_hash}  {filename}")
        return "\n".join(lines) + ("\n" if lines else "")

    def generate_csv_manifest(self, files: List[Dict[str, Any]]) -> str:
        """Generates a structured CSV forensic evidence manifest.

        Args:
            files (List[Dict[str, Any]]): List of recovered file records.

        Returns:
            str: CSV formatted string.
        """
        header = "file_id,filename,format,status,is_valid,hash_algo,file_hash,total_size,fragment_count,first_offset,start_lba,slack_bytes,entropy\n"
        rows = []
        for f in files:
            file_id = str(f.get("file_id", ""))
            filename = str(f.get("filename", ""))
            fmt = str(f.get("format", ""))
            status = str(f.get("status", ""))
            val_info = f.get("validation", {})
            is_valid = str(val_info.get("is_valid", "N/A"))
            algo = str(f.get("hash_algo", self.algo_name))
            f_hash = str(f.get("file_hash", ""))
            size = str(f.get("total_size", 0))
            frags = f.get("fragments", [])
            frag_count = str(len(frags))
            first_offset = str(frags[0]["start_offset"]) if frags else "0"
            start_lba = str(f.get("start_lba", int(first_offset) // 512 if frags else 0))
            slack_bytes = str(f.get("slack_bytes", 0))
            entropy = str(f.get("entropy", ""))

            row = f'"{file_id}","{filename}","{fmt}","{status}","{is_valid}","{algo}","{f_hash}",{size},{frag_count},{first_offset},{start_lba},{slack_bytes},"{entropy}"'
            rows.append(row)

        return header + "\n".join(rows) + ("\n" if rows else "")

    @staticmethod
    def _parse_timestamp_to_epoch(ts_str: Any) -> int:
        """Converts an extracted metadata timestamp string to integer UNIX epoch seconds.

        Args:
            ts_str (Any): Raw timestamp string.

        Returns:
            int: UNIX epoch timestamp in seconds, or 0 if unparseable.
        """
        if not ts_str or not isinstance(ts_str, str):
            return 0
        s = ts_str.strip()
        # handle PDF format: D:20230101120000
        if s.startswith("D:") and len(s) >= 16:
            try:
                dt = datetime.datetime.strptime(s[2:16], "%Y%m%d%H%M%S")
                return int(dt.timestamp())
            except (ValueError, OSError):
                pass
        # common ISO, EXIF, and standard patterns
        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y:%m:%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.datetime.strptime(s, fmt)
                return int(dt.timestamp())
            except (ValueError, OSError):
                continue
        return 0

    def generate_bodyfile_content(self, files: List[Dict[str, Any]]) -> str:
        """Generates SleuthKit Bodyfile 3.0 content for timeline analysis with mactime.

        Format:
        MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

        Args:
            files (List[Dict[str, Any]]): List of recovered file records.

        Returns:
            str: Bodyfile 3.0 lines.
        """
        lines = []
        for f in files:
            filename = f.get("filename", "unnamed")
            md5 = f.get("md5") or (f.get("file_hash", "0") if f.get("hash_algo") == "md5" else "0")
            first_offset = f["fragments"][0]["start_offset"] if f.get("fragments") else 0
            inode = f.get("start_lba", first_offset // 512)
            mode = "-rwxr-xr-x"
            uid = "0"
            gid = "0"
            size = str(f.get("total_size", f.get("size", 0)))

            meta = f.get("metadata", {}) or {}
            crtime = self._parse_timestamp_to_epoch(
                meta.get("created") or meta.get("creation time") or meta.get("creation_date")
            )
            mtime = self._parse_timestamp_to_epoch(
                meta.get("modified") or meta.get("moddate") or meta.get("timestamp") or meta.get("modification_date")
            )
            atime = mtime
            ctime = mtime

            line = f"{md5}|{filename}|{inode}|{mode}|{uid}|{gid}|{size}|{atime}|{mtime}|{ctime}|{crtime}"
            lines.append(line)
        return "\n".join(lines) + ("\n" if lines else "")

    def generate_jsonl_content(self, files: List[Dict[str, Any]]) -> str:
        """Generates JSON-Lines (JSONL) formatted output for SIEM ingestion.

        Args:
            files (List[Dict[str, Any]]): List of recovered file records.

        Returns:
            str: Line-delimited JSON string.
        """
        return "\n".join(json.dumps(f) for f in files) + ("\n" if files else "")
