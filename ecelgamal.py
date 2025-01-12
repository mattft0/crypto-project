from rfc7748 import x25519, add, sub, computeVcoordinate, mult
from algebra import mod_inv, int_to_bytes
from random import randint

P = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BASE_U = 9
BASE_V = computeVcoordinate(BASE_U)

def brute_ec_log(C1, C2, P):
    s1, s2 = 1, 0
    for i in range(P):
        if s1 == C1 and s2 == C2:
            return i
        s1, s2 = add(s1, s2, BASE_U, BASE_V, P)
    return -1

def eg_encode(message):
    if message == 0:
        return (1, 0)
    if message == 1:
        return (BASE_U, BASE_V)
    raise ValueError("Message must be 0 or 1")

def eceg_generate_keys():
    private_key = randint(1, ORDER - 1)
    public_key = mult(private_key, BASE_U, BASE_V, P)
    return private_key, public_key

def eceg_encrypt(message, public_key):
    r = randint(1, ORDER - 1)
    C1 = mult(r, BASE_U, BASE_V, P)
    encoded_message = eg_encode(message)
    C2 = add(*encoded_message, *mult(r, *public_key, P), P)
    print(f"Encrypted message: {message} -> C1: {C1}, C2: {C2}")
    return C1, C2

def eceg_decrypt(C1, C2, private_key):
    C1_neg = sub(0, 0, *C1, P)
    C2_dec = add(*mult(private_key, *C1_neg, P), *C2, P)
    print(f"Decrypting C1_neg: {C1_neg}, C2_dec: {C2_dec}")
    result = brute_ec_log(*C2_dec, P)
    print(f"Decrypted result: {result}")
    return result
