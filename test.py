__author__ = 'yousefhamza'

import unittest
from aes import AES


class AES_TEST(unittest.TestCase):
    def setUp(self):
        master_key = 0x2b7e151628aed2a6abf7158809cf4f3c
        self.AES = AES(master_key)

    def test_encryption(self):
        plaintext = 0x3243f6a8885a308d313198a2e0370734
        encrypted = self.AES.encrypt(plaintext)

        self.assertEqual(encrypted, 0x3925841d02dc09fbdc118597196a0b32)

    def test_decryption(self):
        ciphertext = 0x3925841d02dc09fbdc118597196a0b32
        decrypted = self.AES.decrypt(ciphertext)

        self.assertEqual(decrypted, 0x3243f6a8885a308d313198a2e0370734)


"""
L3odr0id testing system

https://github.com/L3odr0id
"""
from hypothesis import given, example
from hypothesis.strategies import integers, text
from aes import text2matrix, matrix2text


class TestMatrix(unittest.TestCase):
    @given(a=integers(min_value=0))
    def test_matrix(self, a):
        h = int(hex(a), 16)
        text = text2matrix(h)
        mat = matrix2text(text)
        self.assertEqual(h, mat, '"There and back" rule does not work with matrix')

    def test_incorrect_input(self):
        with self.assertRaises(IndexError, msg='You should handle broken matrix input'):
            matrix2text([[], []])


class TestMainClass(unittest.TestCase):
    @given(key=integers(min_value=0), data=integers(min_value=0))
    def test_system(self, key, data):
        a = AES(int(hex(key), 16))

        plaintext = data
        encrypted = a.encrypt(plaintext)
        decrypted = a.decrypt(encrypted)

        self.assertFalse(encrypted == decrypted, 'Data is not encrypted')
        self.assertEqual(decrypted, data, 'Something is wrong with encryption - decryption process')

    @given(key=text(), data=text())
    def test_wrong_input(self, key, data):
        with self.assertRaises(TypeError, msg='You should handle wrong input'):
            a = AES(key)

            plaintext = data
            encrypted = a.encrypt(plaintext)
            a.decrypt(encrypted)

    @given(key=integers(max_value=-1))
    def test_bad_input(self, key):
        with self.assertRaises(Exception) as context:
            AES(key)
        self.assertTrue('Key can not be < 0' in str(context.exception))
        a = AES(123)
        with self.assertRaises(Exception) as context:
            a.encrypt(key)
        self.assertTrue('Plaintext can not be < 0' in str(context.exception))


if __name__ == "__main__":
    unittest.main()