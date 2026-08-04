"""Unit and integration tests for TAR format parsing and carving.

Verifies TAR header validation, octal checksum verification, header offset
step-back in HeaderDetector, and end-to-end archive extraction from disk images.
"""

import io
import os
import tarfile
import tempfile
import unittest
from struct_carver.core.carver import Carver
from struct_carver.core.header_detector import HeaderDetector
from struct_carver.formats.binary.tar_parser import TARParser
from struct_carver.formats.registry import ParserRegistry


class TestTARParser(unittest.TestCase):
    """Test suite for TAR parser block alignment and checksum verification."""

    def _create_tar_archive(self, files_dict: dict) -> bytes:
        """Helper to create a standard in-memory POSIX TAR archive.

        Args:
            files_dict (dict): Dictionary mapping filenames to byte contents.

        Returns:
            bytes: Valid TAR archive byte sequence.
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for name, content in files_dict.items():
                ti = tarfile.TarInfo(name=name)
                ti.size = len(content)
                tar.addfile(ti, io.BytesIO(content))
        return buf.getvalue()

    def test_tar_valid_checksum_and_parse(self):
        """Verify TAR parser validates octal checksums and completes on end-of-archive blocks."""
        archive_data = self._create_tar_archive({
            "hello.txt": b"Hello forensic carver!\n",
            "data.bin": b"\x01\x02\x03\x04" * 128
        })

        parser = TARParser()
        is_corrupted, is_complete, advance, remaining = parser.analyze_binary(archive_data)

        self.assertFalse(is_corrupted)
        self.assertTrue(is_complete)
        # advance completes at 3072 bytes (end of two 512-byte zero blocks, excluding tape record padding)
        self.assertEqual(advance, 3072)
        with tarfile.open(fileobj=io.BytesIO(archive_data[:advance]), mode="r") as tar:
            self.assertEqual(tar.getnames(), ["hello.txt", "data.bin"])

    def test_tar_validate_header_checksum_rejection(self):
        """Verify candidate TAR header validation rejects invalid checksums."""
        parser = TARParser()
        header = bytearray(512)
        header[257:262] = b'ustar'
        header[124:135] = b'00000000010'
        header[148:155] = b'777777\x00'  # bogus checksum

        self.assertFalse(parser.validate_header(bytes(header), 0))

    def test_tar_header_detector_offset_stepback(self):
        """Verify HeaderDetector steps back 257 bytes to byte 0 of the TAR header block."""
        archive_data = self._create_tar_archive({"test.txt": b"sample data"})
        prefix = b"\xaa" * 120
        cluster = prefix + archive_data

        registry = ParserRegistry()
        detector = HeaderDetector(registry)

        with tempfile.TemporaryDirectory() as temp_dir:
            matched, parser, engine, handle, search_buffer, file_start = detector.detect_header(
                cluster=cluster,
                prev_overlap=b"",
                file_id=1,
                output_dir=temp_dir,
                worker_id=0
            )

            if handle:
                handle.close()

            self.assertTrue(matched)
            self.assertIsInstance(parser, TARParser)
            self.assertEqual(file_start, 120)
            # search_buffer must start at byte 0 of the TAR archive (not at +257 ustar)
            self.assertTrue(search_buffer.startswith(archive_data[:64]))

    def test_tar_carver_end_to_end_extraction(self):
        """Verify Carver recovers complete, unpackable TAR archive from simulated disk image."""
        original_files = {
            "evidence/report.txt": b"Forensic carving verification passed.\n",
            "evidence/hash.sha256": b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
        }
        tar_bytes = self._create_tar_archive(original_files)

        cluster_size = 512
        prefix_padding = b"\x00" * 512
        suffix_padding = b"\x00" * 1024
        disk_image = prefix_padding + tar_bytes + suffix_padding

        with tempfile.TemporaryDirectory() as temp_dir:
            img_path = os.path.join(temp_dir, "disk.dd")
            out_dir = os.path.join(temp_dir, "carved")

            with open(img_path, "wb") as f:
                f.write(disk_image)

            carver = Carver(cluster_size=cluster_size, formats=["tar"], quiet=True)
            carver.carve(img_path, out_dir)

            carved_tars = [
                f for f in os.listdir(out_dir)
                if f.endswith(".tar") and not f.startswith("carve_report")
            ]
            self.assertEqual(len(carved_tars), 1)

            carved_path = os.path.join(out_dir, carved_tars[0])
            with tarfile.open(carved_path, "r") as tar:
                extracted_names = tar.getnames()
                self.assertIn("evidence/report.txt", extracted_names)
                self.assertIn("evidence/hash.sha256", extracted_names)

                report_data = tar.extractfile("evidence/report.txt").read()
                self.assertEqual(report_data, original_files["evidence/report.txt"])


if __name__ == "__main__":
    unittest.main()
