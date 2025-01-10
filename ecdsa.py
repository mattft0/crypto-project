from rfc7748 import x25519, add, computeVcoordinate, mult
from Crypto.Hash import SHA256
from random import randint
from algebra import mod_inv
import secrets

p = 2**255 - 19
ORDER = (2**252 + 27742317777372353535851937790883648493)

BaseU = 9
BaseV = computeVcoordinate(BaseU)


def H(message):
    h = SHA256.new(message)
    return (int(h.hexdigest(), 16))

def ECDSA_generate_nonce():
    return (int(secrets.randbelow(ORDER -1) +1))
    
def ECDSA_generate_keys(): #génère une clée privée qui est choisi aléatoirement dans ECDSA_generate_nonce | partie publique correspond à la "transposition" sur la courbe donc des coordonnées sur celle ci
    priv = ECDSA_generate_nonce()
    Pub_U, Pub_V = mult(priv, BaseU, BaseV, p)
    return priv, (Pub_U, Pub_V)
#print(ECDSA_generate_keys())

def ECDSA_sign(message, private_key): # signature à partir de la clée privée et un message donnée 
    hash_tempo = H(message)
    nonce = ECDSA_generate_nonce()
    U, _ = mult(nonce, BaseU, BaseV, p)
    deriv = U % ORDER

    k_inv = mod_inv(nonce, ORDER)
    sign = (k_inv * (hash_tempo + deriv * private_key)) % ORDER
           
    return deriv, sign


def ECDSA_verify(message, signature, public_key):
    # Unpack the signature
    r, s = signature
    
    # Unpack the public key (Pub_U, Pub_V)
    Pub_U, Pub_V = public_key
    
    # Step 1: Compute the hash of the message
    hash_tempo = H(message)
    
    # Step 2: Compute the modular inverse of s
    w = mod_inv(s, ORDER)
    
    # Step 3: Compute u1 and u2
    u1 = (hash_tempo * w) % ORDER
    u2 = (r * w) % ORDER
    
    # Step 4: Compute the point P = u1 * Base + u2 * Pub
    U1_U, U1_V = mult(u1, BaseU, BaseV, p)
    U2_U, U2_V = mult(u2, Pub_U, Pub_V, p)
    
    # Add the two points
    U_U, U_V = add(U1_U, U1_V, U2_U, U2_V, p)
    
    # Step 5: Verify the x-coordinate of the point matches r
    return (r == U_U % ORDER)

if __name__ == "__main__":

    # 5.1 ECDSA validation
    private_key, public_key = ECDSA_generate_keys()

    # Step 2: Define a test message (as bytes)
    message = b"Hello, this is a test message for ECDSA."

    # Step 3: Sign the message using the private key
    signature = ECDSA_sign(message, private_key)
    print("Signature:", signature)

    # Step 4: Verify the signature using the public key
    is_valid = ECDSA_verify(message, signature, public_key)
    
    # Step 5: Output the verification result
    if is_valid:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")