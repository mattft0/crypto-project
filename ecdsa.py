from rfc7748 import add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from algebra import mod_inv
import secrets

# Constants
p = 2**255 - 19
ORDER = 2**252 + 27742317777372353535851937790883648493
BaseU = 9
BaseV = computeVcoordinate(BaseU)

def H(message):
    h = SHA256.new(message)
    return int(h.hexdigest(), 16)

def ECDSA_generate_nonce():
    return secrets.randbelow(ORDER - 1) + 1

def ECDSA_generate_keys():
    priv = ECDSA_generate_nonce()
    Pub_U, Pub_V = mult(priv, BaseU, BaseV, p)
    return priv, (Pub_U, Pub_V)

def ECDSA_sign(message, private_key):
    hash_tempo = H(message)
    nonce = ECDSA_generate_nonce()
    U, _ = mult(nonce, BaseU, BaseV, p)
    deriv = U % ORDER
    k_inv = mod_inv(nonce, ORDER)
    sign = (k_inv * (hash_tempo + deriv * private_key)) % ORDER
    return deriv, sign

def ECDSA_verify(message, signature, public_key):
    r, s = signature
    Pub_U, Pub_V = public_key
    hash_tempo = H(message)
    w = mod_inv(s, ORDER)
    u1 = (hash_tempo * w) % ORDER
    u2 = (r * w) % ORDER
    U1_U, U1_V = mult(u1, BaseU, BaseV, p)
    U2_U, U2_V = mult(u2, Pub_U, Pub_V, p)
    U_U, U_V = add(U1_U, U1_V, U2_U, U2_V, p)
    return r == U_U % ORDER

if __name__ == "__main__":
    # Fixed test values for 5.2
    message = b"A very very important message !"
    private_key = 0xc841f4896fe86c971bedbcf114a6cfd97e4454c9be9aba876d5a195995e2ba8
    fixed_nonce = 0x2c92639dcf417afeae31e0f8fddc8e48b3e11d840523f54aaa97174221faee6

    # Expected results
    r = 0x429146a1375614034c65c2b6a86b2fc4aec00147f223cb2a7a22272d4a3fdd2
    s = 0xf23bcdebe2e0d8571d195a9b8a05364b14944032032eeeecd22a0f6e94f8f33

    # Generate signature
    def ECDSA_sign_fixed_nonce(message, private_key, fixed_nonce):
        hash_tempo = H(message)
        U, _ = mult(fixed_nonce, BaseU, BaseV, p)
        deriv = U % ORDER
        k_inv = mod_inv(fixed_nonce, ORDER)
        sign = (k_inv * (hash_tempo + deriv * private_key)) % ORDER
        return deriv, sign

    derivation, signe = ECDSA_sign_fixed_nonce(message, private_key, fixed_nonce)
    signature = (derivation, signe)

    # Check against expected results
    print("Signature:", signature)
    print("Matches expected r and s:", derivation == r and signe == s)

    # Public key computation
    Pub_U, Pub_V = mult(private_key, BaseU, BaseV, p)
    public_key = (Pub_U, Pub_V)

    # Verify signature
    is_valid = ECDSA_verify(message, signature, public_key)
    print("Signature verification result:", is_valid)
