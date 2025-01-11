import sys
import os
import pytest

# Add the root directory of the project to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elgamal import brute_log, eg_generate_keys, eg_encrypt, eg_decrypt, PARAM_P, PARAM_Q, PARAM_G

def test_eg_generate_keys():
    private_key, public_key = eg_generate_keys()
    assert isinstance(private_key, int)
    assert isinstance(public_key, int)

def test_eg_encrypt_multiplicative():
    message = 2
    private_key, public_key = eg_generate_keys()
    c1, c2 = eg_encrypt(message, public_key)
    assert isinstance(c1, int)
    assert isinstance(c2, int)

def test_eg_encrypt_additive():
    message = 2
    private_key, public_key = eg_generate_keys()
    c1, c2 = eg_encrypt(message, public_key, additive=True)
    assert isinstance(c1, int)
    assert isinstance(c2, int)

def test_eg_decrypt_multiplicative():
    message = 2
    private_key, public_key = eg_generate_keys()
    c1, c2 = eg_encrypt(message, public_key)
    decrypted_message = eg_decrypt(c1, c2, private_key)
    assert isinstance(decrypted_message, int)
    assert decrypted_message == message

def test_eg_decrypt_additive():
    message = 2
    private_key, public_key = eg_generate_keys()
    c1, c2 = eg_encrypt(message, public_key, additive=True)
    encrypted_message = pow(c1, private_key, PARAM_P)
    decrypted_message = brute_log(PARAM_G, (c2 - encrypted_message) % PARAM_P, PARAM_P)
    assert isinstance(decrypted_message, int)
    assert decrypted_message == message

def test_eg_homomorphic_multiplicative():
    message1 = 2
    message2 = 3
    private_key, public_key = eg_generate_keys()
    c11, c12 = eg_encrypt(message1, public_key)
    c21, c22 = eg_encrypt(message2, public_key)
    c31, c32 = (c11 * c21) % PARAM_P, (c12 * c22) % PARAM_P
    decrypted_message = eg_decrypt(c31, c32, private_key)
    assert isinstance(decrypted_message, int)
    assert decrypted_message == (message1 * message2) % PARAM_P

def test_eg_homomorphic_additive():
    message1 = 2
    message2 = 3
    private_key, public_key = eg_generate_keys()
    c11, c12 = eg_encrypt(message1, public_key, additive=True)
    c21, c22 = eg_encrypt(message2, public_key, additive=True)
    c31, c32 = (c11 * c21) % PARAM_P, (c12 + c22) % PARAM_P
    encrypted_message = pow(c31, private_key, PARAM_P)
    decrypted_message = brute_log(PARAM_G, (c32 - encrypted_message) % PARAM_P, PARAM_P)
    assert isinstance(decrypted_message, int)
    assert decrypted_message == (message1 + message2) % PARAM_P
