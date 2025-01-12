from random import randint
from elgamal import eg_generate_keys, eg_encrypt, eg_decrypt  # Import your existing functions
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Parameters for ElGamal encryption
PARAM_P = 0x87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597
PARAM_Q = 0x8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3
PARAM_G = 0x3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659

def homomorphic_add(enc_values1, enc_values2, param_p):
    return [(c1_1, (c2_1 + c2_2) % param_p) for (c1_1, c2_1), (c1_2, c2_2) in zip(enc_values1, enc_values2)]

# Signing key generation
def generate_signing_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Sign data
def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify signature
def verify_signature(public_key, data, signature):
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
    
    
# # 7.1 
# # Key generation
# private_key, public_key = eg_generate_keys()

# # Voter 1 votes for C2
# voter1_vote = [0, 1, 0, 0, 0]
# voter1_encrypted = [eg_encrypt(value, public_key, additive=True) for value in voter1_vote]

# # Voter 2 votes for C4
# voter2_vote = [0, 0, 0, 1, 0]
# voter2_encrypted = [eg_encrypt(value, public_key, additive=True) for value in voter2_vote]

# # Aggregate the votes homomorphically
# aggregated_encrypted = homomorphic_add(voter1_encrypted, voter2_encrypted, PARAM_P)

# # Decrypt the aggregated result
# aggregated_result = [eg_decrypt(c1, c2, private_key, additive=True) for c1, c2 in aggregated_encrypted]

# # Display results
# print("Voter 1 Encrypted Ballot:", voter1_encrypted)
# print("Voter 2 Encrypted Ballot:", voter2_encrypted)
# print("Aggregated Encrypted Ballot:", aggregated_encrypted)
# print("Decrypted Aggregated Result:", aggregated_result)

# 7.2


# Key generation for ElGamal and signing
private_key_enc, public_key_enc = eg_generate_keys()
signing_private_key, signing_public_key = generate_signing_keys()

# Voter 1 votes for C2
voter1_vote = [0, 1, 0, 0, 0]
voter1_encrypted = [eg_encrypt(value, public_key_enc, additive=True) for value in voter1_vote]

# Serialize encrypted ballot for signing
serialized_ballot = b"".join(
    (str(c1).encode() + str(c2).encode()) for c1, c2 in voter1_encrypted
)
voter1_signature = sign_data(signing_private_key, serialized_ballot)

# Verify signature
is_valid = verify_signature(signing_public_key, serialized_ballot, voter1_signature)
print("Is Voter 1's signature valid?", is_valid)

# Homomorphic addition example
# Voter 2 votes for C4
voter2_vote = [0, 0, 0, 1, 0]
voter2_encrypted = [eg_encrypt(value, public_key_enc, additive=True) for value in voter2_vote]

# Aggregate votes homomorphically
aggregated_encrypted = homomorphic_add(voter1_encrypted, voter2_encrypted, PARAM_P)

# Decrypt the aggregated result
aggregated_result = [eg_decrypt(c1, c2, private_key_enc, additive=True) for c1, c2 in aggregated_encrypted]

# Display results
print("Voter 1 Encrypted Ballot:", voter1_encrypted)
print("Voter 1 Signature:", voter1_signature)
print("Aggregated Encrypted Ballot:", aggregated_encrypted)
print("Decrypted Aggregated Result:", aggregated_result)