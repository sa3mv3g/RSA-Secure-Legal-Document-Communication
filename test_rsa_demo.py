"""Quick demo of RSA utilities"""
from rsa_utils import SHA256, RSAKey, PKCS1_OAEP, PSS

# Test SHA-256
print('='*60)
print('SHA-256 Test')
print('='*60)
msg = b'abc'
h = SHA256(msg)
print(f'Message: {msg}')
print(f'SHA-256 Hash: {h.hexdigest()}')
print(f'Expected:     ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
print()

# Generate RSA keys (smaller size for faster demo)
print('='*60)
print('RSA Key Generation (1024-bit for demo speed)')
print('='*60)
key = RSAKey.generate(1024)
print(f'Key size: {key.key_size} bits')
print(f'Public exponent (e): {key.e}')
print(f'Modulus (n): {hex(key.n)[:50]}...')
print()

# Test encryption/decryption
print('='*60)
print('RSA-OAEP Encryption/Decryption')
print('='*60)
message = b'Hello, Legal Document!'
print(f'Original message: {message}')

cipher = PKCS1_OAEP.new(key)
ciphertext = cipher.encrypt(message)
print(f'Ciphertext (hex): {ciphertext.hex()[:60]}...')

decrypted = cipher.decrypt(ciphertext)
print(f'Decrypted message: {decrypted}')
print(f'Match: {message == decrypted}')
print()

# Test signing/verification
print('='*60)
print('RSA-PSS Digital Signature')
print('='*60)
msg_to_sign = b'I agree to the contract terms.'
print(f'Message to sign: {msg_to_sign}')

msg_hash = SHA256(msg_to_sign)
signer = PSS.new(key)
signature = signer.sign(msg_hash)
print(f'Signature (hex): {signature.hex()[:60]}...')

# Verify
msg_hash2 = SHA256(msg_to_sign)
verifier = PSS.new(key.public_key())
try:
    verifier.verify(msg_hash2, signature)
    print('Signature verification: VALID')
except ValueError:
    print('Signature verification: INVALID')

# Test with tampered message
print()
print('Testing with tampered message...')
tampered_hash = SHA256(b'I agree to the contract terms!')  # Added '!'
try:
    verifier.verify(tampered_hash, signature)
    print('Tampered verification: VALID (unexpected!)')
except ValueError:
    print('Tampered verification: INVALID (as expected)')

print()
print('='*60)
print('Demo Complete!')
print('='*60)
