"""Forensic metadata extractor module.

This module provides the MetadataExtractor class, which extracts embedded timestamps,
authors, camera makes/models, and document properties from carved files (JPEG, PDF,
Office documents, and PNG) to assist forensic investigators in building evidence timelines.
"""

import os
import struct
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional


class MetadataExtractor:
    """Extracts embedded forensic metadata and timestamps from carved file formats."""

    @classmethod
    def extract(cls, file_path: str, fmt: str) -> Dict[str, Any]:
        """Extracts metadata from a carved file based on its format.

        Args:
            file_path (str): Path to the target carved file on disk.
            fmt (str): Format extension string.

        Returns:
            Dict[str, Any]: Extracted metadata key-value dictionary.
        """
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return {}

        fmt_lower = fmt.lower().strip(".")
        try:
            if fmt_lower in ["jpg", "jpeg"]:
                return cls._extract_jpeg_exif(file_path)
            elif fmt_lower == "pdf":
                return cls._extract_pdf_metadata(file_path)
            elif fmt_lower in ["docx", "xlsx", "pptx", "zip"]:
                return cls._extract_office_metadata(file_path)
            elif fmt_lower == "png":
                return cls._extract_png_metadata(file_path)
            else:
                return {}
        except (OSError, struct.error, ValueError, IndexError, zipfile.BadZipFile, ET.ParseError):
            return {}

    @classmethod
    def _extract_jpeg_exif(cls, file_path: str) -> Dict[str, Any]:
        """Extracts basic EXIF tags (DateTime, Make, Model) from a JPEG file."""
        metadata: Dict[str, Any] = {}
        try:
            with open(file_path, "rb") as f:
                data = f.read(65536)  # EXIF header is typically in first 64KB

            idx = data.find(b"\xFF\xE1")  # APP1 marker
            if idx == -1 or idx + 14 >= len(data):
                return metadata

            if data[idx + 4:idx + 10] != b"Exif\x00\x00":
                return metadata

            tiff_start = idx + 10
            tiff_data = data[tiff_start:]
            if len(tiff_data) < 8:
                return metadata

            endian = tiff_data[:2]
            endian_char = "<" if endian == b"II" else ">" if endian == b"MM" else None
            if not endian_char:
                return metadata

            first_ifd_offset = struct.unpack(f"{endian_char}I", tiff_data[4:8])[0]
            if first_ifd_offset + 2 > len(tiff_data):
                return metadata

            num_entries = struct.unpack(f"{endian_char}H", tiff_data[first_ifd_offset:first_ifd_offset + 2])[0]
            curr = first_ifd_offset + 2

            tag_names = {
                0x010F: "make",
                0x0110: "model",
                0x0132: "datetime",
                0x9003: "datetime_original",
                0x9004: "datetime_digitized",
            }

            for _ in range(min(num_entries, 100)):
                if curr + 12 > len(tiff_data):
                    break
                tag, field_type, count, val_or_offset = struct.unpack(f"{endian_char}HHI I", tiff_data[curr:curr + 12])
                curr += 12

                if tag in tag_names and field_type == 2:  # ASCII string
                    if count <= 4:
                        str_bytes = struct.pack(f"{endian_char}I", val_or_offset)[:count]
                    elif val_or_offset + count <= len(tiff_data):
                        str_bytes = tiff_data[val_or_offset:val_or_offset + count]
                    else:
                        continue
                    clean_str = str_bytes.decode("ascii", errors="replace").rstrip("\x00").strip()
                    if clean_str:
                        metadata[tag_names[tag]] = clean_str
        except (OSError, struct.error, ValueError, IndexError):
            pass
        return metadata

    @classmethod
    def _extract_pdf_metadata(cls, file_path: str) -> Dict[str, Any]:
        """Extracts creation date, mod date, title, and author from a PDF document."""
        metadata: Dict[str, Any] = {}
        try:
            file_size = os.path.getsize(file_path)
            # read first 4KB and last 8KB for dictionary metadata
            with open(file_path, "rb") as f:
                head = f.read(4096)
                f.seek(max(0, file_size - 8192))
                tail = f.read(8192)

            text_chunks = head + b"\n" + tail
            for key in [b"/CreationDate", b"/ModDate", b"/Author", b"/Title", b"/Creator", b"/Producer"]:
                pos = text_chunks.find(key)
                if pos != -1:
                    val_start = pos + len(key)
                    # look for (string) or D:date string
                    paren_open = text_chunks.find(b"(", val_start)
                    paren_close = text_chunks.find(b")", paren_open) if paren_open != -1 else -1
                    if paren_open != -1 and paren_close != -1 and (paren_close - paren_open) < 200:
                        raw_val = text_chunks[paren_open + 1:paren_close].decode("latin1", errors="replace").strip()
                        prop_name = key.decode("ascii").lstrip("/").lower()
                        metadata[prop_name] = raw_val
        except (OSError, ValueError, IndexError):
            pass
        return metadata

    @classmethod
    def _extract_office_metadata(cls, file_path: str) -> Dict[str, Any]:
        """Extracts created, modified, and creator fields from docProps/core.xml in ZIP/Office archives."""
        metadata: Dict[str, Any] = {}
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                if "docProps/core.xml" in zf.namelist():
                    with zf.open("docProps/core.xml") as core_xml:
                        tree = ET.parse(core_xml)
                        root = tree.getroot()
                        # handle namespaces
                        for child in root:
                            tag_clean = child.tag.split("}")[-1].lower()
                            if tag_clean in ["created", "modified", "creator", "lastmodifiedby", "title"]:
                                if child.text:
                                    metadata[tag_clean] = child.text.strip()
        except (zipfile.BadZipFile, OSError, KeyError, ET.ParseError, ValueError):
            pass
        return metadata

    @classmethod
    def _extract_png_metadata(cls, file_path: str) -> Dict[str, Any]:
        """Extracts tIME timestamp and tEXt chunks from PNG files."""
        metadata: Dict[str, Any] = {}
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)
                if header != b"\x89PNG\r\n\x1a\n":
                    return metadata

                while True:
                    len_bytes = f.read(4)
                    if len(len_bytes) < 4:
                        break
                    chunk_len = struct.unpack(">I", len_bytes)[0]
                    chunk_type = f.read(4)
                    if len(chunk_type) < 4:
                        break

                    if chunk_type == b"tIME" and chunk_len >= 7:
                        time_data = f.read(7)
                        f.seek(chunk_len - 7 + 4, os.SEEK_CUR)  # skip rest + CRC
                        year, month, day, hour, minute, second = struct.unpack(">HBBBBB", time_data)
                        metadata["timestamp"] = f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"
                    elif chunk_type == b"tEXt" and chunk_len > 0:
                        text_data = f.read(chunk_len)
                        f.seek(4, os.SEEK_CUR)  # skip CRC
                        parts = text_data.split(b"\x00", 1)
                        if len(parts) == 2:
                            k = parts[0].decode("latin1", errors="replace").lower()
                            v = parts[1].decode("latin1", errors="replace").strip()
                            if k in ["title", "author", "description", "creation time"]:
                                metadata[k] = v
                    elif chunk_type == b"IEND":
                        break
                    else:
                        f.seek(chunk_len + 4, os.SEEK_CUR)  # skip data + CRC
        except (OSError, struct.error, ValueError, IndexError):
            pass
        return metadata
