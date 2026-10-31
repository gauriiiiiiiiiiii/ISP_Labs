"""
Experiment 6: RSA Algorithm
Key generation, encryption, decryption from scratch.
Uses Miller-Rabin primality test and extended Euclidean.
"""

import random
import math


# ── Math helpers ──────────────────────────────────────────────────────────────

def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a: int, m: int) -> int:
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a},{m})={g}")
    return x % m


def miller_rabin(n: int, k: int = 10) -> bool:
    """Probabilistic primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1   # ensure top bit set, odd
        if miller_rabin(n):
            return n


# ── RSA key generation ────────────────────────────────────────────────────────

def rsa_keygen(bits: int = 512):
    """
    Returns (public_key, private_key) where:
        public_key  = (e, n)
        private_key = (d, n)
    bits: total modulus size (each prime = bits//2).
    """
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        if math.gcd(e, phi) == 1:
            break
    d = mod_inverse(e, phi)
    return (e, n), (d, n), p, q


# ── RSA encrypt / decrypt ─────────────────────────────────────────────────────

def rsa_encrypt(message: int, public_key: tuple) -> int:
    e, n = public_key
    if message >= n:
        raise ValueError("Message too large for key size")
    return pow(message, e, n)


def rsa_decrypt(ciphertext: int, private_key: tuple) -> int:
    d, n = private_key
    return pow(ciphertext, d, n)


# ── Text ↔ integer helpers ────────────────────────────────────────────────────

def text_to_int(text: str) -> int:
    return int.from_bytes(text.encode(), 'big')


def int_to_text(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big').decode()


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 6: RSA Algorithm")
    print("=" * 60)

    print("\n  --- Key Generation (512-bit) ---")
    pub, priv, p, q = rsa_keygen(bits=512)
    e, n = pub
    d, _ = priv
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = p×q = {n}")
    print(f"  φ(n) = (p-1)(q-1)")
    print(f"  e = {e}")
    print(f"  d = {d}")
    print(f"\n  Public key  : (e={e}, n={n})")
    print(f"  Private key : (d=<hidden>, n={n})")

    # Integer message (small for demo)
    print("\n  --- Encrypt/Decrypt Integer Message ---")
    m = 42
    ct = rsa_encrypt(m, pub)
    dt = rsa_decrypt(ct, priv)
    print(f"  Plaintext  : {m}")
    print(f"  Ciphertext : {ct}")
    print(f"  Decrypted  : {dt}")
    assert dt == m, "RSA roundtrip failed!"
    print("  ✓ Integer roundtrip verified")

    # Text message
    print("\n  --- Encrypt/Decrypt Text Message ---")
    msg = "RSA Demo"
    m_int = text_to_int(msg)
    print(f"  Message   : '{msg}'")
    print(f"  As int    : {m_int}")
    ct_int = rsa_encrypt(m_int, pub)
    dt_int = rsa_decrypt(ct_int, priv)
    recovered = int_to_text(dt_int)
    print(f"  Encrypted : {ct_int}")
    print(f"  Decrypted : '{recovered}'")
    assert recovered == msg
    print("  ✓ Text roundtrip verified")

    # Security properties
    print("\n  --- Security Properties ---")
    print(f"  Key size           : 512 bits")
    print(f"  n bit length       : {n.bit_length()} bits")
    print(f"  Factoring n → p,q  : computationally infeasible for large n")
    print(f"  e (public exponent): {e} (Fermat prime, fast encryption)")
    print(f"  Verify: e×d mod φ(n) should be 1")
    phi = (p-1)*(q-1)
    print(f"  e×d mod φ(n)       : {(e*d) % phi}")
    assert (e * d) % phi == 1
    print("  ✓ Key pair verified")


if __name__ == "__main__":
    demo()
