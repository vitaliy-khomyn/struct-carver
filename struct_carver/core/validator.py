"""Forensic integrity validator for Struct Carver!

This module provides the FileValidator class, which inspects carved files
using format-specific validation routines (e.g. ZIP CRC32 checks, SQLite PRAGMA
integrity checks, image chunk CRCs, and JSON/XML/PDF structure syntax trees).
"""

import os
import json
import zlib
import struct
import zipfile
import sqlite3
import xml.etree.ElementTree as ET
from typing import Dict, Any, Tuple


class FileValidator:
    """Validates internal payload integrity of carved files."""

    def validate(self, file_path: str, fmt: str) -> Dict[str, Any]:
        """Runs format-specific validation on a carved file on disk.

        Args:
            file_path (str): Path to the carved file.
            fmt (str): Format extension string.

        Returns:
            Dict[str, Any]: Validation result containing:
                - 'is_valid' (bool): True if verified intact, False if corrupted.
                - 'details' (str): Descriptive validation message or error summary.
        """
        if not os.path.exists(file_path):
            return {"is_valid": False, "details": "File does not exist on disk"}

        if os.path.getsize(file_path) == 0:
            return {"is_valid": False, "details": "File is empty (0 bytes)"}

        fmt_lower = fmt.lower().strip(".")

        try:
            if fmt_lower in ["zip", "docx", "xlsx", "pptx"]:
                return self._validate_zip(file_path)
            elif fmt_lower in ["sqlite", "db"]:
                return self._validate_sqlite(file_path)
            elif fmt_lower == "json":
                return self._validate_json(file_path)
            elif fmt_lower == "xml":
                return self._validate_xml(file_path)
            elif fmt_lower == "html":
                return self._validate_html(file_path)
            elif fmt_lower == "png":
                return self._validate_png(file_path)
            elif fmt_lower == "bmp":
                return self._validate_bmp(file_path)
            elif fmt_lower == "gif":
                return self._validate_gif(file_path)
            elif fmt_lower in ["jpg", "jpeg"]:
                return self._validate_jpg(file_path)
            elif fmt_lower == "pdf":
                return self._validate_pdf(file_path)
            else:
                return {"is_valid": True, "details": f"Basic structure accepted ({fmt_lower})"}
        except Exception as e:
            return {"is_valid": False, "details": f"Validation exception: {str(e)}"}

    def _validate_zip(self, file_path: str) -> Dict[str, Any]:
        """Validates ZIP and Office document CRC32 checksums."""
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                corrupted_member = zf.testzip()
                if corrupted_member is not None:
                    return {"is_valid": False, "details": f"CRC32 mismatch in archive entry: {corrupted_member}"}
                return {"is_valid": True, "details": f"All archive entries passed CRC32 verification ({len(zf.namelist())} files)"}
        except Exception as err:
            return {"is_valid": False, "details": f"ZIP structure corrupted: {err}"}

    def _validate_sqlite(self, file_path: str) -> Dict[str, Any]:
        """Validates SQLite database integrity using PRAGMA integrity_check."""
        try:
            # open in read-only URI mode to prevent any file modification
            abs_path = os.path.abspath(file_path).replace("\\", "/")
            conn = sqlite3.connect(f"file:{abs_path}?mode=ro", uri=True)
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check(1);")
            row = cursor.fetchone()
            conn.close()

            if row and row[0] == "ok":
                return {"is_valid": True, "details": "SQLite PRAGMA integrity_check passed (ok)"}
            else:
                msg = row[0] if row else "Integrity check returned no result"
                return {"is_valid": False, "details": f"SQLite corrupted: {msg}"}
        except Exception as err:
            return {"is_valid": False, "details": f"SQLite connection failed: {err}"}

    def _validate_json(self, file_path: str) -> Dict[str, Any]:
        """Validates JSON document syntax by parsing into a Python AST."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                json.load(f)
            return {"is_valid": True, "details": "JSON syntax and structure valid"}
        except Exception as err:
            return {"is_valid": False, "details": f"JSON syntax error: {err}"}

    def _validate_xml(self, file_path: str) -> Dict[str, Any]:
        """Validates XML document grammar and tag balance."""
        try:
            ET.parse(file_path)
            return {"is_valid": True, "details": "XML document tree parsed successfully"}
        except Exception as err:
            return {"is_valid": False, "details": f"XML parse error: {err}"}

    def _validate_html(self, file_path: str) -> Dict[str, Any]:
        """Validates HTML document start and end tag boundaries."""
        try:
            with open(file_path, "rb") as f:
                content = f.read().strip().lower()
            if (content.startswith(b"<!doctype html") or content.startswith(b"<html")) and content.endswith(b"</html>"):
                return {"is_valid": True, "details": "HTML opening and closing tags verified"}
            return {"is_valid": False, "details": "HTML document missing opening or closing tags"}
        except Exception as err:
            return {"is_valid": False, "details": f"HTML read error: {err}"}

    def _validate_png(self, file_path: str) -> Dict[str, Any]:
        """Validates PNG header and chunk-level CRC32 checksums."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)
                if header != b"\x89PNG\r\n\x1a\n":
                    return {"is_valid": False, "details": "Invalid PNG file signature"}

                found_iend = False
                while True:
                    len_bytes = f.read(4)
                    if len(len_bytes) < 4:
                        break
                    chunk_len = struct.unpack(">I", len_bytes)[0]
                    chunk_type = f.read(4)
                    if len(chunk_type) < 4:
                        return {"is_valid": False, "details": "Unexpected EOF reading chunk type"}
                    chunk_data = f.read(chunk_len)
                    if len(chunk_data) < chunk_len:
                        return {"is_valid": False, "details": "Unexpected EOF reading chunk data"}
                    crc_bytes = f.read(4)
                    if len(crc_bytes) < 4:
                        return {"is_valid": False, "details": "Unexpected EOF reading chunk CRC"}
                    expected_crc = struct.unpack(">I", crc_bytes)[0]

                    calc_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
                    if calc_crc != expected_crc:
                        return {"is_valid": False, "details": f"CRC mismatch in PNG chunk {chunk_type.decode('ascii', errors='replace')}"}

                    if chunk_type == b"IEND":
                        found_iend = True
                        break

                if found_iend:
                    return {"is_valid": True, "details": "PNG header and chunk CRC32 checksums verified"}
                return {"is_valid": False, "details": "PNG missing IEND terminal chunk"}
        except Exception as err:
            return {"is_valid": False, "details": f"PNG parsing error: {err}"}

    def _validate_bmp(self, file_path: str) -> Dict[str, Any]:
        """Validates BMP file header and dimensions."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(14)
                if len(header) < 14 or header[:2] != b"BM":
                    return {"is_valid": False, "details": "Invalid BMP signature"}
                file_size = struct.unpack("<I", header[2:6])[0]
                actual_size = os.path.getsize(file_path)
                if actual_size < file_size:
                    return {"is_valid": False, "details": f"Truncated BMP (file size {actual_size} < header {file_size})"}
                return {"is_valid": True, "details": "BMP header and size verified"}
        except Exception as err:
            return {"is_valid": False, "details": f"BMP check error: {err}"}

    def _validate_gif(self, file_path: str) -> Dict[str, Any]:
        """Validates GIF header and terminal trailer byte."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(6)
                if header not in [b"GIF87a", b"GIF89a"]:
                    return {"is_valid": False, "details": "Invalid GIF signature"}
                f.seek(-1, os.SEEK_END)
                trailer = f.read(1)
                if trailer != b"\x3B":
                    return {"is_valid": False, "details": "GIF missing 0x3B trailer"}
                return {"is_valid": True, "details": "GIF header and trailer verified"}
        except Exception as err:
            return {"is_valid": False, "details": f"GIF check error: {err}"}

    def _validate_jpg(self, file_path: str) -> Dict[str, Any]:
        """Validates JPEG SOI and EOI markers."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                if not data.startswith(b"\xFF\xD8"):
                    return {"is_valid": False, "details": "Missing JPEG SOI marker"}
                if not data.rstrip(b"\x00").endswith(b"\xFF\xD9"):
                    return {"is_valid": False, "details": "Missing JPEG EOI marker"}
                return {"is_valid": True, "details": "JPEG SOI and EOI markers verified"}
        except Exception as err:
            return {"is_valid": False, "details": f"JPEG check error: {err}"}

    def _validate_pdf(self, file_path: str) -> Dict[str, Any]:
        """Validates PDF header and EOF trailer presence."""
        try:
            with open(file_path, "rb") as f:
                content = f.read()
                lower = content.lower()
                if not (lower.startswith(b"%pdf-") or b"%pdf-" in lower[:1024]):
                    return {"is_valid": False, "details": "Missing %PDF- header"}
                if b"%%eof" not in lower[-1024:]:
                    return {"is_valid": False, "details": "Missing %%EOF trailer marker"}
                return {"is_valid": True, "details": "PDF header and EOF trailer marker verified"}
        except Exception as err:
            return {"is_valid": False, "details": f"PDF check error: {err}"}
