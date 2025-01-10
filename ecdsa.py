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


def ECDSA_verify("""TBC"""):
    return """TBC"""
