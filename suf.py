import seal
import numpy as np

# SEAL Context
parms = seal.EncryptionParameters(seal.scheme_type.BFV)
poly_modulus_degree = 8192
parms.set_poly_modulus_degree(poly_modulus_degree)
parms.set_coeff_modulus(seal.CoeffModulus.BFVDefault(poly_modulus_degree))
parms.set_plain_modulus(seal.PlainModulus.Batching(poly_modulus_degree, 20))

context = seal.SEALContext(parms)
keygen = seal.KeyGenerator(context)
public_key = keygen.public_key()
secret_key = keygen.secret_key()
encryptor = seal.Encryptor(context, public_key)
decryptor = seal.Decryptor(context, secret_key)
evaluator = seal.Evaluator(context)
encoder = seal.BatchEncoder(context)

# Sample votes (1 for 'Yes', 0 for 'No')
votes = [1, 0, 1, 1, 0, 1, 0, 1]

# Encode and encrypt each vote
encrypted_votes = []
for vote in votes:
    plain_vote = encoder.encode([vote])  # Convert to plaintext
    encrypted_vote = encryptor.encrypt(plain_vote)  # Encrypt
    encrypted_votes.append(encrypted_vote)

# Homomorphic addition (secure tallying)
encrypted_tally = encrypted_votes[0]
for i in range(1, len(encrypted_votes)):
    evaluator.add_inplace(encrypted_tally, encrypted_votes[i])  # Add votes

# Decrypt result
plain_tally = decryptor.decrypt(encrypted_tally)
decoded_tally = encoder.decode(plain_tally)

print(f"Total 'Yes' votes: {decoded_tally[0]} out of {len(votes)}")
