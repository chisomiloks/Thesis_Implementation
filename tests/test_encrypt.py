"""Test suite for file encryption and decrytion"""

import pytest
from src.abe_schemes.abe_symmetric_file_encryption import *


def test_verify_file_content():
    with open('test_data/sample_file.txt') as f:
        content = f.readlines()
    actual = 'This is a sample file to test encryption and decryption modules.\n'
    assert content[0] == actual
    assert len(content) == 1


def test_key_generation():
    a, b = symmetric_key_gen()
    z = abe_key_extract(b)
    assert a == z
