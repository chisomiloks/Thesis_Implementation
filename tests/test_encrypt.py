"""Test suite for file encryption and decrytion"""

import pytest
from src.abe_schemes.abe_symmetric_file_encryption import *


def test_verify_file_content():
    with open('test_data/test_file.txt', 'r') as f:
        content = f.readlines()
    f.close()
    actual = 'This is a sample file to test encryption and decryption modules.\n'
    assert content[0] == actual
    assert len(content) == 1


def test_key_generation():
    a, b = symmetric_key_gen()
    z = abe_key_extract(b)
    assert a == z
