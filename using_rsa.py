from rsa import *

((n, e), (n, d)) = getRSAKeyPair()

# Bob's public key and private key

print("Public Key: (n, e)")
print("n:", n)
print("e:", e)
print()

print("Private Key: (d)")
print("d:", d)
print()

# Alice encrypts message using the public key
m = "Hi Bob, this is Alice"
print("Plaintext Message:", m)
print()

# block splitting should be done here

RSAencrypted = RSAEncrypt(strToInt(m), (n, e))

print("Encrypted Message:", RSAencrypted)
print()

RSAdecrypted = RSADecrypt(RSAencrypted, (n, d))
RSADecryptedMessage = intToStr(RSAdecrypted)

print("Decrypted Message:", RSADecryptedMessage)
print()
