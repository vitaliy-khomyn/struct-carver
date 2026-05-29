import unittest
import struct
import zlib
import bz2
from struct_carver.formats.binary.pcx_parser import PCXParser
from struct_carver.formats.binary.wav_parser import WAVParser
from struct_carver.formats.binary.mp3_parser import MP3Parser
from struct_carver.formats.binary.au_parser import AUParser
from struct_carver.formats.binary.wma_parser import WMAParser
from struct_carver.formats.binary.wmv_parser import WMVParser
from struct_carver.formats.binary.avi_parser import AVIParser
from struct_carver.formats.binary.mp4_parser import MP4Parser
from struct_carver.formats.binary.mov_parser import MOVParser
from struct_carver.formats.binary.flv_parser import FLVParser
from struct_carver.formats.binary.mpg_parser import MPGParser
from struct_carver.formats.binary.seven_z_parser import SevenZParser
from struct_carver.formats.binary.rar_parser import RARParser
from struct_carver.formats.binary.gz_parser import GZParser
from struct_carver.formats.binary.bz2_parser import BZ2Parser
from struct_carver.formats.binary.tar_parser import TARParser
from struct_carver.formats.binary.wim_parser import WIMParser


class TestNewBinaryParsers(unittest.TestCase):

    def test_pcx_parser(self):
        parser = PCXParser()
        # Build 128-byte PCX Header
        # Width: XMax - XMin + 1 = 9 - 0 + 1 = 10
        # Height: YMax - YMin + 1 = 9 - 0 + 1 = 10
        # Version = 5, BitsPerPixel = 8, NPlanes = 1, BytesPerLine = 10
        header = bytearray(128)
        header[0] = 0x0A  # Manufacturer
        header[1] = 5     # Version
        header[2] = 1     # Encoding
        header[3] = 8     # BitsPerPixel
        # XMin, YMin, XMax, YMax
        struct.pack_into('<hhhh', header, 4, 0, 0, 9, 9)
        header[65] = 1    # NPlanes
        struct.pack_into('<H', header, 66, 10)  # BytesPerLine

        # RLE Data: 10 lines of 10 bytes = 100 bytes
        # We write 100 single bytes (not run-length encoded)
        rle_data = b'\x01' * 100

        # Optional 256-color palette (preceded by 0x0C, then 768 bytes)
        palette = b'\x0C' + b'\x02' * 768

        data = header + rle_data + palette
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, len(data))

    def test_wav_parser(self):
        parser = WAVParser()
        # RIFF size = 4 (for 'WAVE') + 8 (for subchunk) + 12 (data) = 24
        data = b'RIFF' + struct.pack('<I', 24) + b'WAVE' + b'subc' + struct.pack('<I', 4) + b'1234'
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 32) # RIFF + size + rest (8 + 24)

    def test_mp3_parser(self):
        parser = MP3Parser()
        # ID3 header: 'ID3', version (2), flags (1), size (4 synchsafe)
        # Size = 10 bytes
        id3_header = b'ID3\x03\x00\x00\x00\x00\x00\x0A' + b'A' * 10
        # Frame Header: Sync (0xFF, 0xFB = Layer III), Bitrate index 9 (128kbps), Sample Rate index 0 (44100Hz), Padding 0
        # Version 3 (MPEG 1), Layer 1 (Layer III) -> frame size = 144 * 128000 // 44100 = 417 bytes
        frame_header = b'\xFF\xFB\x90\x64' + b'\x00' * 413
        # ID3v1 Tag: 'TAG' + 125 bytes
        id3v1_tag = b'TAG' + b'B' * 125

        data = id3_header + frame_header + id3v1_tag
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, len(data))

    def test_au_parser(self):
        parser = AUParser()
        # Header: magic (4), data_offset (4), data_size (4)
        data = b'.snd' + struct.pack('>II', 24, 10) + b'\x00' * 12 + b'1234567890'
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 34)

    def test_asf_wma_wmv_parser(self):
        wma = WMAParser()
        wmv = WMVParser()

        # Header Object GUID: 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C (16 bytes)
        # Header size: 120 bytes (8 bytes)
        hdr_guid = b'\x30\x26\xB2\x75\x8E\x66\xCF\x11\xA6\xD9\x00\xAA\x00\x62\xCE\x6C'
        header_obj = hdr_guid + struct.pack('<Q', 120) + b'\x00' * 6

        # File Properties Object GUID: A1 5F C1 8C 85 4F D0 11 AC B0 00 A0 C9 03 49 BE (16 bytes)
        # Size: 104 bytes (8 bytes)
        # Client ID: 16 bytes
        # File Size: 1000 bytes (8 bytes)
        fp_guid = b'\xA1\x5F\xC1\x8C\x4F\x85\xD0\x11\xAC\xB0\x00\xA0\xC9\x03\x49\xBE'
        fp_obj = fp_guid + struct.pack('<Q', 104) + b'\x00' * 16 + struct.pack('<Q', 1000)
        # Pad FP to 104 bytes
        fp_obj += b'\x00' * (104 - len(fp_obj))

        data = header_obj + fp_obj + b'\x00' * (120 - len(header_obj) - len(fp_obj))
        # Add padding to reach file size 1000
        data += b'\x00' * (1000 - len(data))

        # Test WMA
        is_corr, is_comp, adv, rem = wma.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 1000)

        # Test WMV
        is_corr, is_comp, adv, rem = wmv.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 1000)

    def test_avi_parser(self):
        parser = AVIParser()
        data = b'RIFF' + struct.pack('<I', 20) + b'AVI ' + b'\x00' * 20
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 28)

    def test_mp4_mov_parser(self):
        mp4 = MP4Parser()
        mov = MOVParser()

        # Box 1: ftyp (size 16)
        ftyp = struct.pack('>I', 16) + b'ftyp' + b'12345678'
        # Box 2: mdat (size 24)
        mdat = struct.pack('>I', 24) + b'mdat' + b'1234567812345678'
        # Terminator: invalid box (e.g. zeros)
        term = b'\x00\x00\x00\x00'

        data = ftyp + mdat + term

        # Test MP4
        is_corr, is_comp, adv, rem = mp4.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 40) # size of ftyp (16) + mdat (24)

        # Test MOV
        is_corr, is_comp, adv, rem = mov.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 40)

    def test_flv_parser(self):
        parser = FLVParser()
        # Header: FLV\x01, Flags (5), Header size (9)
        hdr = b'FLV\x01\x05\x00\x00\x00\x09'
        # PreviousTagSize0 (4)
        prev0 = b'\x00\x00\x00\x00'
        # Tag 1: Type (8), Data size (3 bytes: 5), Timestamp (3), TS ext (1), StreamID (3) -> 11 bytes header
        tag1_hdr = b'\x08\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00'
        tag1_data = b'audio'
        tag1_prev = struct.pack('>I', 16) # PreviousTagSize = 11 + 5 = 16
        # Terminating block (invalid tag type)
        term = b'\x00'

        data = hdr + prev0 + tag1_hdr + tag1_data + tag1_prev + term
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, len(data) - 1)

    def test_mpg_parser(self):
        parser = MPGParser()
        # starts with \x00\x00\x01\xBA, contains some bytes, ends with \x00\x00\x01\xB9
        data = b'\x00\x00\x01\xBA' + b'\x00' * 50 + b'\x00\x00\x01\xB9'
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, len(data))

    def test_seven_z_parser(self):
        parser = SevenZParser()
        # Header: signature (6), version (2), CRC (4), next_header_offset (8), next_header_size (8), CRC (4)
        # size = 32
        data = b'7z\xBC\xAF\x27\x1C\x00\x02\x00\x00\x00\x00' + struct.pack('<QQ', 10, 5) + b'\x00\x00\x00\x00'
        # Followed by 15 bytes of data
        data += b'A' * 15
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 47) # 32 + 10 + 5

    def test_rar_parser(self):
        parser = RARParser()
        # RAR4: Rar!\x1a\x07\x00
        # Block 1 (Archive Header): CRC (2), Type (0x73), Flags (0), Size (7)
        blk1 = struct.pack('<HBBH', 0, 0x73, 0, 7)
        # Block 2 (Terminator): CRC (2), Type (0x7B), Flags (0), Size (7)
        blk2 = struct.pack('<HBBH', 0, 0x7B, 0, 7)

        data = b'Rar!\x1a\x07\x00' + blk1 + blk2
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, len(data))

    def test_gz_parser(self):
        parser = GZParser()
        # Compress simple string
        raw_data = b"Hello, GZIP parser test!"
        compressor = zlib.compressobj(wbits=16 + zlib.MAX_WBITS)
        gz_bytes = compressor.compress(raw_data) + compressor.flush()

        # Followed by some trailing noise
        data = gz_bytes + b"TRAILING"
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, len(gz_bytes))

    def test_bz2_parser(self):
        parser = BZ2Parser()
        raw_data = b"Hello, BZIP2 parser test!"
        bz2_bytes = bz2.compress(raw_data)

        data = bz2_bytes + b"TRAILING"
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, len(bz2_bytes))

    def test_tar_parser(self):
        parser = TARParser()
        # Header block (512 bytes): ustar at 257, size (8) at 124
        header = bytearray(512)
        header[257:262] = b'ustar'
        header[124:135] = b'00000000010' # 8 octal
        # Data block: 512 bytes (padded 8 bytes)
        data_block = b'A' * 512
        # Terminator: 1024 bytes of zero
        term = b'\x00' * 1024

        data = header + data_block + term
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, len(data))

    def test_wim_parser(self):
        parser = WIMParser()
        # WIM Header (120 bytes)
        # Signature: MSWIM\x00\x00\x00
        # Header Size: 120 (offset 8)
        hdr = bytearray(120)
        hdr[0:8] = b'MSWIM\x00\x00\x00'
        struct.pack_into('<I', hdr, 8, 120)

        # Offset Table Resource Descriptor (offset 48): size = 100, offset = 1000
        struct.pack_into('<Q', hdr, 48, 100)
        struct.pack_into('<Q', hdr, 56, 1000)

        # XML Descriptor (offset 72): size = 200, offset = 1100
        struct.pack_into('<Q', hdr, 72, 200)
        struct.pack_into('<Q', hdr, 80, 1100)

        # Total WIM size = 1100 + 200 = 1300
        data = hdr + b'\x00' * (1300 - 120)
        is_corr, is_comp, adv, rem = parser.analyze_binary(data)
        self.assertFalse(is_corr)
        self.assertTrue(is_comp)
        self.assertEqual(adv, 1300)


if __name__ == '__main__':
    unittest.main()
