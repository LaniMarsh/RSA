from logging import exception
from Crypto.Util.number import getPrime
from typing import List


# if length not specified, 2048 is used as default
def getLargePrime(n : int = 2048) -> int:
  return getPrime(n)


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

# find inverse of A mod C (d mod phi)
# (A * B) mod C = 1
# (d * e) mod phi = 1
# find gcd between d and phi
def mod_inverse(e, phi):
    g, x, _ = egcd(e, phi)
    if g != 1:
      raise exception('Modular inverse does not exist')
    else:
      return x % phi

# compute secret key d
def getRSAPrivateKey(phi : int, e : int) -> int:
  return mod_inverse(e, phi)

def getRSAKeyPair() -> tuple:
  p = getLargePrime()
  q = getLargePrime()
  n = p * q
  phi = (p - 1) * (q - 1)
  e = 65537
  d = getRSAPrivateKey(phi, e)

  # verify de equivalent to 1 mod phi
  print("de:", (d * e)%phi)
  print("should be equal to")
  print(1)
  print()

  return ((n, e), (n, d))

# convert message to int
def strToInt(m : str) -> int:
  bin_m = m.encode()
  hex_m = bin_m.hex()
  int_m = int(hex_m, 16)

  print("Converted message to int:", int_m)
  print()

  return int_m

def intToStr(m : int) -> str:
  # convert int to hex
  hex_m = hex(m)[2:]
  print("Converted int to hex string:", hex_m)
  print()
  # convert from hex back to string
  str_m = bytes.fromhex(hex_m).decode("ascii")
  return str_m

# implement RSA encryption
# c = m^e mod n
def RSAEncrypt(m : int, public_key : tuple) -> int:
  n, e = public_key

  # calculate c
  c = pow(m, e, n)

  return c

# implement RSA decryption
def RSADecrypt(c : int, private_key : tuple) -> int:
  n, d = private_key

  m = pow(c, d, n)

  return m

def RSASign(m: int, private_key: tuple) -> int:
    n, d = private_key
    return pow(m, d, n)

def RSAVerify(m: int, signature: int, public_key: tuple) -> bool:
    n, e = public_key
    return pow(signature, e, n) == m

def MallorySignature(m1: int, m2: int, sig1: int, sig2: int, n: int) -> tuple:
    m3 = (m1 * m2) % n
    sig3 = (sig1 * sig2) % n
    return m3, sig3
