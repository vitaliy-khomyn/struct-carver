import unittest
import os
import tempfile
from struct_carver.core.carver import BufferedClusterReader


class TestBufferedClusterReader(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_file = os.path.join(self.temp_dir.name, "test_buffer.bin")
        # 62 bytes total
        self.test_data = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        with open(self.test_file, 'wb') as f:
            f.write(self.test_data)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_read_within_buffer(self):
        # Use a tiny buffer to easily trigger reloading logic
        with BufferedClusterReader(self.test_file, buffer_size=16) as reader:
            self.assertEqual(reader.read(4), b"0123")
            self.assertEqual(reader.tell(), 4)
            self.assertEqual(reader.read(4), b"4567")
            self.assertEqual(reader.tell(), 8)

    def test_read_across_buffers(self):
        with BufferedClusterReader(self.test_file, buffer_size=16) as reader:
            # Forcing a read larger than the buffer_size dynamically stretches the internal max() load
            self.assertEqual(reader.read(20), self.test_data[:20])
            self.assertEqual(reader.tell(), 20)
            self.assertEqual(reader.read(10), self.test_data[20:30])

    def test_seek_and_tell(self):
        with BufferedClusterReader(self.test_file, buffer_size=10) as reader:
            reader.seek(10)
            self.assertEqual(reader.tell(), 10)
            self.assertEqual(reader.read(5), b"abcde")

            # Reverse seek inside an already loaded buffer
            reader.seek(2)
            self.assertEqual(reader.read(3), b"234")

    def test_eof_handling(self):
        with BufferedClusterReader(self.test_file, buffer_size=16) as reader:
            reader.seek(len(self.test_data) - 2)
            self.assertEqual(reader.read(10), b"YZ")
            self.assertEqual(reader.read(5), b"")
            # Subsequent reads out of bounds should consistently return empty bytes
            self.assertEqual(reader.read(5), b"")
