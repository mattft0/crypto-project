import sys
import os
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ecelgamal import eg_encode, eceg_generate_keys, eceg_encrypt, eceg_decrypt, ORDER, P, BASE_U, BASE_V
from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes

def test_eg_encode():
    assert eg_encode(0) == (1, 0)
    assert eg_encode(1) == (BASE_U, BASE_V)
    with pytest.raises(ValueError):
        eg_encode(2)

def test_eceg_generate_keys():
    private_key, public_key = eceg_generate_keys()
    assert isinstance(private_key, int)
    assert 1 <= private_key <= ORDER - 1
    assert len(public_key) == 2
    assert isinstance(public_key[0], int)
    assert isinstance(public_key[1], int)

def test_eceg_encryption_decryption():
    private_key, public_key = eceg_generate_keys()
    messages = [1, 0, 1, 1, 0]
    encrypted_messages = [eceg_encrypt(message, public_key) for message in messages]
    C1 = (0, 0)
    C2 = (0, 0)
    for C in encrypted_messages:
        C1 = add(*C1, *C[0], P)
        C2 = add(*C2, *C[1], P)
    decrypted_message = eceg_decrypt(C1, C2, private_key)
    assert decrypted_message == sum(messages)