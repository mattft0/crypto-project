import sys
import os
import pytest

# Add the root directory of the project to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dsa import DSA_generate_keys, DSA_sign, DSA_verify, DSA_sign_with_fixed_k, H

def test_dsa_generate_keys():
    private_key, public_key = DSA_generate_keys()
    assert isinstance(private_key, int)
    assert isinstance(public_key, int)
    assert 1 <= private_key <= 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3 - 1

def test_dsa_sign_verify():
    private_key, public_key = DSA_generate_keys()
    message = b"Test message"
    signature = DSA_sign(message, private_key)
    assert DSA_verify(message, signature[0], signature[1], public_key)

def test_dsa_sign_with_fixed_k():
    message = b"An important message !"
    k = 0x7e7f77278fe5232f30056200582ab6e7cae23992bca75929573b779c62ef4759
    x = 0x49582493d17932dabd014bb712fc55af453ebfb2767537007b0ccff6e857e6a3
    r, s = DSA_sign_with_fixed_k(message, x, k)
    assert r == 0x5ddf26ae653f5583e44259985262c84b483b74be46dec74b07906c5896e26e5a
    assert s == 0x194101d2c55ac599e4a61603bc6667dcc23bd2e9bdbef353ec3cb839dcce6ec1

if __name__ == "__main__":
    pytest.main()
