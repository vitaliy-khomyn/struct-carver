"""Unit tests for container format disambiguation across RIFF, ASF, Box, and ZIP families."""
import os
import io
import shutil
import struct
import tempfile
import unittest
import zipfile
import logging

from struct_carver.core.header_detector import HeaderDetector
from struct_carver.core.post_processor import PostProcessor
from struct_carver.formats.registry import ParserRegistry
from struct_carver.formats.binary.zip_parser import ZIPParser
from struct_carver.formats.binary.tiff_parser import TIFFParser
from struct_carver.formats.binary.wav_parser import WAVParser
from struct_carver.formats.binary.avi_parser import AVIParser
from struct_carver.formats.binary.wma_parser import WMAParser
from struct_carver.formats.binary.wmv_parser import WMVParser
from struct_carver.formats.binary.mp4_parser import MP4Parser
from struct_carver.formats.binary.mov_parser import MOVParser


class TestContainerDisambiguation(unittest.TestCase):
    """Test suite covering container disambiguation, validation, and post-processing."""

    def setUp(self):
        """Set up temporary working directory and null logger for test isolation."""
        self.test_dir = tempfile.mkdtemp()
        self.logger = logging.getLogger("test_disambiguation")
        self.logger.addHandler(logging.NullHandler())

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. ParserRegistry Deduplication Tests
    # -------------------------------------------------------------------------

    def test_registry_deduplicates_same_class_parsers(self):
        """Verify registry creates only one parser instance per underlying parser class."""
        # documents category includes docx, xlsx, pptx which all map to ZIPParser
        registry = ParserRegistry(formats=['zip', 'docx', 'xlsx', 'pptx'])
        zip_parsers = [p for p in registry.parsers if isinstance(p, ZIPParser)]
        self.assertEqual(len(zip_parsers), 1, "Only one ZIPParser instance should be registered")

        # tiff and tif both map to TIFFParser
        registry_tiff = ParserRegistry(formats=['tiff', 'tif'])
        tiff_parsers = [p for p in registry_tiff.parsers if isinstance(p, TIFFParser)]
        self.assertEqual(len(tiff_parsers), 1, "Only one TIFFParser instance should be registered")

    # -------------------------------------------------------------------------
    # 2. RIFF Container Disambiguation (WAV vs AVI)
    # -------------------------------------------------------------------------

    def test_riff_header_validation(self):
        """Verify RIFF parsers validate FourCC at byte offset +8."""
        wav_parser = WAVParser()
        avi_parser = AVIParser()

        wav_header = b'RIFF\x20\x00\x00\x00WAVEfmt '
        avi_header = b'RIFF\x20\x00\x00\x00AVI LIST'
        invalid_riff = b'RIFF\x20\x00\x00\x00WEBPVP8 '

        self.assertTrue(wav_parser.validate_header(wav_header, 0))
        self.assertFalse(wav_parser.validate_header(avi_header, 0))
        self.assertFalse(wav_parser.validate_header(invalid_riff, 0))

        self.assertTrue(avi_parser.validate_header(avi_header, 0))
        self.assertFalse(avi_parser.validate_header(wav_header, 0))
        self.assertFalse(avi_parser.validate_header(invalid_riff, 0))

    def test_riff_header_detector_routing(self):
        """Verify HeaderDetector routes RIFF stream to correct parser based on FourCC."""
        registry = ParserRegistry(formats=['wav', 'avi'])
        detector = HeaderDetector(registry)

        chunk_avi = b'\x00\x00RIFF\x20\x00\x00\x00AVI LIST\x00\x00'
        matched_avi, parser_avi, _, handle_avi, _, file_start_avi = detector.detect_header(
            cluster=chunk_avi,
            prev_overlap=b"",
            file_id=1,
            output_dir=self.test_dir,
            worker_id=0
        )
        if handle_avi:
            handle_avi.close()
        self.assertTrue(matched_avi)
        self.assertIsInstance(parser_avi, AVIParser)
        self.assertEqual(file_start_avi, 2)

        chunk_wav = b'\x00\x00RIFF\x20\x00\x00\x00WAVEfmt \x00\x00'
        matched_wav, parser_wav, _, handle_wav, _, file_start_wav = detector.detect_header(
            cluster=chunk_wav,
            prev_overlap=b"",
            file_id=2,
            output_dir=self.test_dir,
            worker_id=0
        )
        if handle_wav:
            handle_wav.close()
        self.assertTrue(matched_wav)
        self.assertIsInstance(parser_wav, WAVParser)
        self.assertEqual(file_start_wav, 2)

    # -------------------------------------------------------------------------
    # 3. ASF Container Disambiguation & Bug Fix (WMA vs WMV)
    # -------------------------------------------------------------------------

    def _build_synthetic_asf(self, has_video: bool = False, total_size: int = 1000) -> bytes:
        """Helper to construct synthetic ASF container with correct GUIDs."""
        hdr_guid = b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C'
        # correct ASF_File_Properties_Object GUID: 8C1FC1A1-854F-11D0-ACB0-00A0C90349BE
        fp_guid = b'\xA1\xC1\x1F\x8C\x4F\x85\xD0\x11\xAC\xB0\x00\xA0\xC9\x03\x49\xBE'
        fp_obj = fp_guid + struct.pack('<Q', 104) + b'\x00' * 16 + struct.pack('<Q', total_size)
        fp_obj += b'\x00' * (104 - len(fp_obj))

        if has_video:
            # ASF_Video_Media GUID (little-endian): BC19EFC0-5B4D-11CF-A8FD-00805F5C442B
            stream_guid = b'\xC0\xEF\x19\xBC\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B'
        else:
            # ASF_Audio_Media GUID (little-endian): F8699E40-5B4D-11CF-A8FD-00805F5C442B
            stream_guid = b'\x40\x9E\x69\xF8\x4D\x5B\xCF\x11\xA8\xFD\x00\x80\x5F\x5C\x44\x2B'

        hdr_size = 16 + 8 + 6 + len(fp_obj) + len(stream_guid)
        hdr_obj = hdr_guid + struct.pack('<Q', hdr_size) + b'\x00' * 6
        payload = hdr_obj + fp_obj + stream_guid
        if len(payload) < total_size:
            payload += b'\x00' * (total_size - len(payload))
        return payload

    def test_asf_wma_wmv_stream_discrimination(self):
        """Verify WMAParser accepts audio-only ASF and WMVParser accepts video ASF."""
        wma_data = self._build_synthetic_asf(has_video=False)
        wmv_data = self._build_synthetic_asf(has_video=True)

        wma_parser = WMAParser()
        wmv_parser = WMVParser()

        # audio-only stream
        is_corr_wma, is_comp_wma, adv_wma, _ = wma_parser.analyze_binary(wma_data)
        self.assertFalse(is_corr_wma, "WMAParser should accept audio ASF")
        self.assertTrue(is_comp_wma)
        self.assertEqual(adv_wma, 1000)

        is_corr_wmv, _, _, _ = wmv_parser.analyze_binary(wma_data)
        self.assertTrue(is_corr_wmv, "WMVParser should reject audio-only ASF")

        # video stream
        wma_parser_2 = WMAParser()
        is_corr_wma2, _, _, _ = wma_parser_2.analyze_binary(wmv_data)
        self.assertTrue(is_corr_wma2, "WMAParser should reject video ASF")

        wmv_parser_2 = WMVParser()
        is_corr_wmv2, is_comp_wmv2, adv_wmv2, _ = wmv_parser_2.analyze_binary(wmv_data)
        self.assertFalse(is_corr_wmv2, "WMVParser should accept video ASF")
        self.assertTrue(is_comp_wmv2)
        self.assertEqual(adv_wmv2, 1000)

    # -------------------------------------------------------------------------
    # 4. ISO BMFF / QuickTime Box Disambiguation (MP4 vs MOV)
    # -------------------------------------------------------------------------

    def test_box_header_validation(self):
        """Verify BaseBoxParser matches variable ftyp box lengths and distinguishes MP4 from MOV."""
        mp4_parser = MP4Parser()
        mov_parser = MOVParser()

        # variable ftyp lengths (24, 28, 32 bytes)
        mp4_isom_24 = b'\x00\x00\x00\x18ftypisom' + b'\x00' * 12
        mp4_mp42_32 = b'\x00\x00\x00\x20ftypmp42' + b'\x00' * 20
        mov_qt_20 = b'\x00\x00\x00\x14ftypqt  ' + b'\x00' * 8
        mov_standalone_moov = b'\x00\x00\x00\x20moov' + b'\x00' * 24

        # MP4 should validate isom, mp42 and reject qt and standalone moov
        self.assertTrue(mp4_parser.validate_header(mp4_isom_24, 0))
        self.assertTrue(mp4_parser.validate_header(mp4_mp42_32, 0))
        self.assertFalse(mp4_parser.validate_header(mov_qt_20, 0))
        self.assertFalse(mp4_parser.validate_header(mov_standalone_moov, 0))

        # MOV should validate qt and standalone atoms, and reject isom/mp42
        self.assertTrue(mov_parser.validate_header(mov_qt_20, 0))
        self.assertTrue(mov_parser.validate_header(mov_standalone_moov, 0))
        self.assertFalse(mov_parser.validate_header(mp4_isom_24, 0))
        self.assertFalse(mov_parser.validate_header(mp4_mp42_32, 0))

    def test_box_header_detector_offset(self):
        """Verify HeaderDetector correctly locates box header when header_offset is 4."""
        registry = ParserRegistry(formats=['mp4', 'mov'])
        detector = HeaderDetector(registry)

        # ftyp is at offset 4 within the file, file starts at offset 5 in chunk
        raw_stream = b'PAD--' + b'\x00\x00\x00\x1cftypisom' + b'\x00' * 16
        matched, parser, _, handle, _, file_start = detector.detect_header(
            cluster=raw_stream,
            prev_overlap=b"",
            file_id=1,
            output_dir=self.test_dir,
            worker_id=0
        )
        if handle:
            handle.close()
        self.assertTrue(matched)
        self.assertEqual(file_start, 5)
        self.assertIsInstance(parser, MP4Parser)

    # -------------------------------------------------------------------------
    # 5. PostProcessor Disambiguation Tests
    # -------------------------------------------------------------------------

    def test_post_process_zip_office_documents(self):
        """Verify PostProcessor disambiguates docx, xlsx, pptx, odt, and jar from zip."""
        processor = PostProcessor()

        # 1. docx
        docx_path = os.path.join(self.test_dir, "file1.zip")
        with zipfile.ZipFile(docx_path, 'w') as zf:
            zf.writestr("[Content_Types].xml", '<Types><Override ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
            zf.writestr("word/document.xml", "<document/>")
        new_ext, new_name = processor.post_process(docx_path, "zip", self.test_dir, "file1.zip", self.logger)
        self.assertEqual(new_ext, "docx")
        self.assertEqual(new_name, "file1.docx")
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, "file1.docx")))

        # 2. xlsx
        xlsx_path = os.path.join(self.test_dir, "file2.zip")
        with zipfile.ZipFile(xlsx_path, 'w') as zf:
            zf.writestr("[Content_Types].xml", '<Types><Override ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>')
            zf.writestr("xl/workbook.xml", "<workbook/>")
        new_ext, new_name = processor.post_process(xlsx_path, "zip", self.test_dir, "file2.zip", self.logger)
        self.assertEqual(new_ext, "xlsx")
        self.assertEqual(new_name, "file2.xlsx")

        # 3. pptx
        pptx_path = os.path.join(self.test_dir, "file3.zip")
        with zipfile.ZipFile(pptx_path, 'w') as zf:
            zf.writestr("ppt/presentation.xml", "<presentation/>")
        new_ext, new_name = processor.post_process(pptx_path, "zip", self.test_dir, "file3.zip", self.logger)
        self.assertEqual(new_ext, "pptx")
        self.assertEqual(new_name, "file3.pptx")

        # 4. odt
        odt_path = os.path.join(self.test_dir, "file4.zip")
        with zipfile.ZipFile(odt_path, 'w') as zf:
            zf.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        new_ext, new_name = processor.post_process(odt_path, "zip", self.test_dir, "file4.zip", self.logger)
        self.assertEqual(new_ext, "odt")
        self.assertEqual(new_name, "file4.odt")

        # 5. jar
        jar_path = os.path.join(self.test_dir, "file5.zip")
        with zipfile.ZipFile(jar_path, 'w') as zf:
            zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        new_ext, new_name = processor.post_process(jar_path, "zip", self.test_dir, "file5.zip", self.logger)
        self.assertEqual(new_ext, "jar")
        self.assertEqual(new_name, "file5.jar")

    def test_post_process_riff_asf_box(self):
        """Verify PostProcessor disambiguates RIFF, ASF, and Box formats."""
        processor = PostProcessor()

        # RIFF: carved as wav but is avi
        avi_file = os.path.join(self.test_dir, "carved.wav")
        with open(avi_file, 'wb') as f:
            f.write(b'RIFF\x20\x00\x00\x00AVI LIST' + b'\x00' * 20)
        ext, name = processor.post_process(avi_file, "wav", self.test_dir, "carved.wav", self.logger)
        self.assertEqual(ext, "avi")
        self.assertEqual(name, "carved.avi")

        # ASF: carved as wma but contains video stream
        wmv_data = self._build_synthetic_asf(has_video=True)
        wmv_file = os.path.join(self.test_dir, "carved.wma")
        with open(wmv_file, 'wb') as f:
            f.write(wmv_data)
        ext, name = processor.post_process(wmv_file, "wma", self.test_dir, "carved.wma", self.logger)
        self.assertEqual(ext, "wmv")
        self.assertEqual(name, "carved.wmv")

        # Box: carved as mp4 but is qt
        mov_file = os.path.join(self.test_dir, "carved.mp4")
        with open(mov_file, 'wb') as f:
            f.write(b'\x00\x00\x00\x14ftypqt  ' + b'\x00' * 8)
        ext, name = processor.post_process(mov_file, "mp4", self.test_dir, "carved.mp4", self.logger)
        self.assertEqual(ext, "mov")
        self.assertEqual(name, "carved.mov")


if __name__ == '__main__':
    unittest.main()
