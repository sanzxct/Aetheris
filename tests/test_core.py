import unittest
import os
import sys


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)


from src.core.reader import AetherisReader
from src.utils.crypto import AetherisCrypto

class TestAetherisCore(unittest.TestCase):
    
    def setUp(self):
       
        self.test_file = os.path.join(BASE_DIR, "samples", "putty.exe")
        
        
        if not os.path.exists(self.test_file):
            os.makedirs(os.path.dirname(self.test_file), exist_ok=True)
            with open(self.test_file, "wb") as f:
                f.write(b"MZ" + b"\x00" * 100)

    def test_reader_identification(self):
        reader = AetherisReader(self.test_file)
        fmt, info = reader.identify_format()
        self.assertEqual(fmt, "EXE_DLL")
        self.assertEqual(info['category'], "EXECUTABLE")

    def test_crypto_hashing(self):
        crypto = AetherisCrypto(self.test_file)
        hashes = crypto.get_file_hashes()
        self.assertIn('sha256', hashes)
        self.assertEqual(len(hashes['sha256']), 64)

if __name__ == '__main__':
    unittest.main()