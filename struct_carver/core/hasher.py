"""Cryptographic hashing utilities for Struct Carver!

This module provides the CryptoHasher class for generating forensic hashes
(SHA-256, MD5, SHA-1, SHA-512) for carved files and individual raw disk fragments.
"""

import os
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

        hasher = self._get_hasher()
        with open(file_path, "rb") as f:
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

        hasher = self._get_hasher()
        bytes_left = size
        with open(file_path, "rb") as f:
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
