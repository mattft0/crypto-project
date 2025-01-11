import sys
import os
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ecdsa import H, ecdsa_generate_nonce, ecdsa_generate_keys, ecdsa_sign, ecdsa_verify, ecdsa_sign_fixed_nonce, ORDER, P, BASE_U, BASE_V


def test_H():
    message = b"This is a test message."
    hash_value = H(message)
    assert isinstance(hash_value, int)
    assert hash_value > 0


def test_ecdsa_generate_nonce():
    nonce = ecdsa_generate_nonce()
    assert isinstance(nonce, int)
    assert 1 <= nonce < ORDER


def test_ecdsa_generate_keys():
    private_key, public_key = ecdsa_generate_keys()
    assert isinstance(private_key, int)
    assert 1 <= private_key < ORDER
    assert isinstance(public_key, tuple)
    assert len(public_key) == 2
    assert isinstance(public_key[0], int)
    assert isinstance(public_key[1], int)


def test_ecdsa_sign():
    message = b"This is a test message."
    private_key, public_key = ecdsa_generate_keys()
    signature = ecdsa_sign(message, private_key)
    assert isinstance(signature, tuple)
    assert len(signature) == 2
    assert isinstance(signature[0], int)
    assert isinstance(signature[1], int)
    assert 1 <= signature[0] < ORDER
    assert 1 <= signature[1] < ORDER


def test_ecdsa_verify():
    message = b"This is a test message."
    private_key, public_key = ecdsa_generate_keys()
    signature = ecdsa_sign(message, private_key)
    assert ecdsa_verify(message, signature, public_key)
    assert not ecdsa_verify(b"This is a different message.", signature, public_key)


def test_ecdsa_sign_fixed_nonce():
    message = b"A very very important message !"
    private_key = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8
    fixed_nonce = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6
    expected_r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
    expected_s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33
    r, s = ecdsa_sign_fixed_nonce(message, private_key, fixed_nonce)
    assert r == expected_r
    assert s == expected_s
