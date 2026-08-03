"""Unit tests for advanced forensic features and hardening.

Verifies:
- Zip Slip path traversal defense and Zip Bomb bounds in PostProcessor.
- SleuthKit Bodyfile 3.0 export and JSONL stream timeline generation.
- Virtual segmented stream reader for multi-volume split raw images (.001, .002).
- Format category presets and expansion in ParserRegistry.
- Deep payload integrity validation for MP4/MOV ISO atoms and RIFF (WAV/AVI) sub-chunks.
- Carver max-file-size truncation guard for runaway allocations.
"""

import os
import io
import json
import struct
import zipfile
import tempfile
import unittest
from struct_carver.core.hasher import CryptoHasher
from struct_carver.core.post_processor import PostProcessor
from struct_carver.core.buffered_reader import (
    discover_segments,
    get_image_size,
    SegmentedStream,
)
from struct_carver.core.validator import FileValidator
from struct_carver.core.carver import Carver
from struct_carver.formats.registry import ParserRegistry, expand_format_categories


class TestAdvancedFeatures(unittest.TestCase):
    """Test suite for advanced forensic standards, hardening, and multi-volume images."""

    def test_zip_slip_path_traversal_prevention(self):
        """Verify Zip Slip path traversal entries are neutralized and not extracted outside target dir."""
        import logging
        test_logger = logging.getLogger("test_zip_slip")
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = os.path.join(tmp_dir, "slip.zip")

            # create malicious zip containing an escape path
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("legit.txt", b"Safe payload content")
                zf.writestr("../../evil.txt", b"Malicious payload escaping root")
                zf.writestr("/absolute_evil.txt", b"Absolute malicious payload")

            post = PostProcessor(extract_archives=True)
            post.post_process(
                file_path=zip_path,
                ext="zip",
                output_dir=tmp_dir,
                filename="slip.zip",
                logger=test_logger,
            )

            extracted_dir = f"{zip_path}_extracted"
            self.assertTrue(os.path.exists(extracted_dir))

            # legit file should be extracted
            legit_file = os.path.join(extracted_dir, "legit.txt")
            self.assertTrue(os.path.exists(legit_file))

            # evil files must NOT exist outside target directory
            self.assertFalse(os.path.exists(os.path.join(tmp_dir, "evil.txt")))
            self.assertFalse(os.path.exists(os.path.join(tmp_dir, "..", "evil.txt")))

    def test_zip_bomb_safety_limits(self):
        """Verify extraction aborts when uncompressed size exceeds max extraction limit."""
        import logging
        test_logger = logging.getLogger("test_zip_bomb")
        with tempfile.TemporaryDirectory() as tmp_dir:
            zip_path = os.path.join(tmp_dir, "bomb.zip")
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                # 100KB compressed data that expands to ~10MB
                zf.writestr("huge.bin", b"\x00" * (10 * 1024 * 1024))

            # configure low ceiling of 1MB
            post = PostProcessor(extract_archives=True, max_extract_size=1 * 1024 * 1024)
            post.post_process(
                file_path=zip_path,
                ext="zip",
                output_dir=tmp_dir,
                filename="bomb.zip",
                logger=test_logger,
            )

            extracted_dir = f"{zip_path}_extracted"
            # extraction should have aborted before extracting huge.bin
            self.assertFalse(os.path.exists(os.path.join(extracted_dir, "huge.bin")))

    def test_bodyfile_generation(self):
        """Verify SleuthKit Bodyfile 3.0 formatting with inode, mode, size, and timestamps."""
        hasher = CryptoHasher("sha256")
        files = [
            {
                "filename": "carved_0001.pdf",
                "format": "pdf",
                "status": "complete",
                "size": 2048,
                "file_hash": "deadbeef1234",
                "md5": "0123456789abcdef0123456789abcdef",
                "fragments": [{"start_offset": 8192, "end_offset": 10240, "size": 2048}],
                "metadata": {
                    "creation_date": "2023-01-01 12:00:00",
                    "modification_date": "2023-01-02 15:30:00",
                },
            },
            {
                "filename": "carved_0002.jpg",
                "format": "jpg",
                "status": "complete",
                "size": 4096,
                "file_hash": "aabbccdd5678",
                "fragments": [{"start_offset": 16384, "end_offset": 20480, "size": 4096}],
            },
        ]

        bodyfile_content = hasher.generate_bodyfile_content(files)
        lines = [line for line in bodyfile_content.strip().split("\n") if line]
        self.assertEqual(len(lines), 2)

        # line 1: check MD5, filename, synthetic inode (8192 // 512 = 16)
        parts1 = lines[0].split("|")
        self.assertEqual(len(parts1), 11)
        self.assertEqual(parts1[0], "0123456789abcdef0123456789abcdef")
        self.assertEqual(parts1[1], "carved_0001.pdf")
        self.assertEqual(parts1[2], "16")  # synthetic inode = sector 16
        self.assertEqual(parts1[6], "2048")  # size
        self.assertTrue(int(parts1[7]) > 0)  # timestamp parsed
        self.assertTrue(int(parts1[8]) > 0)

        # line 2: check synthetic inode for 16384 (16384 // 512 = 32)
        parts2 = lines[1].split("|")
        self.assertEqual(parts2[1], "carved_0002.jpg")
        self.assertEqual(parts2[2], "32")
        self.assertEqual(parts2[6], "4096")

    def test_jsonl_generation(self):
        """Verify SIEM line-delimited JSON export produces valid standalone JSON objects per file."""
        hasher = CryptoHasher("sha256")
        files = [
            {
                "filename": "carved_0001.png",
                "format": "png",
                "size": 512,
                "file_hash": "hash1",
                "fragments": [{"start_offset": 0, "end_offset": 512, "size": 512}],
            },
            {
                "filename": "carved_0002.zip",
                "format": "zip",
                "size": 1024,
                "file_hash": "hash2",
                "fragments": [{"start_offset": 4096, "end_offset": 5120, "size": 1024}],
            },
        ]
        jsonl_content = hasher.generate_jsonl_content(files)
        lines = [line for line in jsonl_content.strip().split("\n") if line]
        self.assertEqual(len(lines), 2)

        parsed1 = json.loads(lines[0])
        self.assertEqual(parsed1["filename"], "carved_0001.png")
        self.assertEqual(parsed1["format"], "png")

        parsed2 = json.loads(lines[1])
        self.assertEqual(parsed2["filename"], "carved_0002.zip")
        self.assertEqual(parsed2["format"], "zip")

    def test_segmented_stream_reader(self):
        """Verify seamless seeking and reading across multi-segment split disk images."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            seg1_path = os.path.join(tmp_dir, "disk.raw.001")
            seg2_path = os.path.join(tmp_dir, "disk.raw.002")
            seg3_path = os.path.join(tmp_dir, "disk.raw.003")

            chunk1 = b"A" * 1000
            chunk2 = b"B" * 1000
            chunk3 = b"C" * 1000

            with open(seg1_path, "wb") as f:
                f.write(chunk1)
            with open(seg2_path, "wb") as f:
                f.write(chunk2)
            with open(seg3_path, "wb") as f:
                f.write(chunk3)

            # verify discovery
            segments = discover_segments(seg1_path)
            self.assertEqual(len(segments), 3)
            self.assertEqual(segments[0], seg1_path)
            self.assertEqual(segments[1], seg2_path)
            self.assertEqual(segments[2], seg3_path)

            # verify cumulative size
            total_size = get_image_size(seg1_path)
            self.assertEqual(total_size, 3000)

            # verify seamless cross-segment streaming
            stream = SegmentedStream(segments)
            try:
                # read across boundary 1 (from 900 to 1100)
                stream.seek(900)
                data = stream.read(200)
                self.assertEqual(data, b"A" * 100 + b"B" * 100)
                self.assertEqual(stream.tell(), 1100)

                # seek from end
                stream.seek(-100, io.SEEK_END)
                self.assertEqual(stream.tell(), 2900)
                tail = stream.read(100)
                self.assertEqual(tail, b"C" * 100)
                self.assertEqual(stream.tell(), 3000)

                # read at EOF
                eof_bytes = stream.read(50)
                self.assertEqual(eof_bytes, b"")
            finally:
                stream.close()

    def test_format_category_presets(self):
        """Verify category aliases expand to full lists of supported formats."""
        # test images preset
        images = expand_format_categories(["images"])
        self.assertIn("jpg", images)
        self.assertIn("png", images)
        self.assertIn("gif", images)
        self.assertIn("bmp", images)
        self.assertIn("tiff", images)
        self.assertIn("pcx", images)

        # test mixed list with duplicates
        mixed = expand_format_categories(["documents", "zip", "pdf"])
        self.assertIn("pdf", mixed)
        self.assertIn("docx", mixed)
        self.assertIn("zip", mixed)
        self.assertEqual(mixed.count("pdf"), 1)  # deduplicated

        # test ParserRegistry initialization with category
        registry = ParserRegistry(formats=["images"])
        exts = [registry.get_extension(p) for p in registry.parsers]
        self.assertTrue(all(ext in ["jpg", "png", "gif", "bmp", "tiff", "pcx"] for ext in exts))

    def test_deep_mp4_validation(self):
        """Verify deep MP4/MOV ISO atom parsing validates ftyp, moov, and mdat atoms."""
        validator = FileValidator()
        with tempfile.TemporaryDirectory() as tmp_dir:
            mp4_path = os.path.join(tmp_dir, "sample.mp4")

            # construct valid MP4: ftyp atom + moov atom
            # ftyp: length 24, type 'ftyp', major_brand 'isom', minor_version 0, compatible_brands 'isom'
            ftyp_payload = b"isom" + struct.pack(">I", 0) + b"isom"
            ftyp_box = struct.pack(">I", 8 + len(ftyp_payload)) + b"ftyp" + ftyp_payload

            # moov: length 16, type 'moov', dummy payload
            moov_payload = b"\x00" * 8
            moov_box = struct.pack(">I", 8 + len(moov_payload)) + b"moov" + moov_payload

            with open(mp4_path, "wb") as f:
                f.write(ftyp_box + moov_box)

            res = validator.validate(mp4_path, "mp4")
            self.assertTrue(res["is_valid"], f"Valid MP4 rejected: {res['details']}")

            # test corrupt atom length
            corrupt_path = os.path.join(tmp_dir, "corrupt.mp4")
            with open(corrupt_path, "wb") as f:
                f.write(struct.pack(">I", 2) + b"ftyp" + ftyp_payload)  # length 2 is invalid (< 8)

            corrupt_res = validator.validate(corrupt_path, "mp4")
            self.assertFalse(corrupt_res["is_valid"])

    def test_deep_riff_validation(self):
        """Verify RIFF sub-chunk verification for WAV (fmt, data) and AVI (hdrl)."""
        validator = FileValidator()
        with tempfile.TemporaryDirectory() as tmp_dir:
            wav_path = os.path.join(tmp_dir, "sample.wav")

            # build valid WAV: RIFF header + fmt chunk + data chunk
            fmt_payload = b"\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00"  # 16 bytes PCM
            fmt_chunk = b"fmt " + struct.pack("<I", len(fmt_payload)) + fmt_payload
            data_payload = b"\x00\x80" * 10  # 20 bytes audio data
            data_chunk = b"data" + struct.pack("<I", len(data_payload)) + data_payload

            riff_payload = b"WAVE" + fmt_chunk + data_chunk
            riff_header = b"RIFF" + struct.pack("<I", len(riff_payload)) + riff_payload

            with open(wav_path, "wb") as f:
                f.write(riff_header)

            res = validator.validate(wav_path, "wav")
            self.assertTrue(res["is_valid"], f"Valid WAV rejected: {res['details']}")

            # test WAV missing data chunk
            missing_data_path = os.path.join(tmp_dir, "missing_data.wav")
            incomplete_payload = b"WAVE" + fmt_chunk
            incomplete_hdr = b"RIFF" + struct.pack("<I", len(incomplete_payload)) + incomplete_payload
            with open(missing_data_path, "wb") as f:
                f.write(incomplete_hdr)

            res_incomplete = validator.validate(missing_data_path, "wav")
            self.assertFalse(res_incomplete["is_valid"])
            self.assertIn("Missing required RIFF sub-chunk: data", res_incomplete["details"])

    def test_carver_max_file_size(self):
        """Verify Carver truncates runaway carving if file size exceeds max_file_size."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            img_path = os.path.join(tmp_dir, "large.raw")
            # create 16KB disk image with text/html start tag followed by endless content
            cluster_size = 512
            with open(img_path, "wb") as f:
                f.write(b"<html><body>" + b"A" * 10000)

            # set max_file_size to 1024 bytes
            carver = Carver(
                cluster_size=cluster_size,
                formats=["html"],
                max_file_size=1024,
                quiet=True,
            )
            carver.carve(img_path, tmp_dir, 0, os.path.getsize(img_path), worker_id=0)

            report_file = os.path.join(tmp_dir, "carve_report_w0.json")
            self.assertTrue(os.path.exists(report_file))
            with open(report_file, "r") as f:
                rep = json.load(f)

            self.assertGreaterEqual(len(rep["files"]), 1)
            carved_file = rep["files"][0]
            # status should be partial because it exceeded max_file_size
            self.assertEqual(carved_file["status"], "partial")
            self.assertLessEqual(carved_file["size"], 1024 + cluster_size)


if __name__ == "__main__":
    unittest.main()
