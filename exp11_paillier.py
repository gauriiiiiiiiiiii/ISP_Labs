"""
Experiment 11: Paillier Partially Homomorphic Encryption
Demonstrates additive homomorphism: Dec(Enc(m1) × Enc(m2) mod n²) = m1 + m2.
"""

import random
import math
import secrets


# ── Miller-Rabin (reused locally) ─────────────────────────────────────────────

def miller_rabin(n: int, k: int = 10) -> bool:
    if n < 2: return False
    if n in (2, 3): return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        n = secrets.randbits(bits)
        n |= (1 << (bits - 1)) | 1
        if miller_rabin(n):
            return n


def lcm(a: int, b: int) -> int:
    return a * b // math.gcd(a, b)


def mod_inverse(a: int, m: int) -> int:
    def ext_gcd(a, b):
        if a == 0: return b, 0, 1
        g, x, y = ext_gcd(b % a, a)
        return g, y - (b // a) * x, x
    _, x, _ = ext_gcd(a % m, m)
    return x % m


# ── L function ────────────────────────────────────────────────────────────────

def L(u: int, n: int) -> int:
    """L(u) = (u - 1) / n"""
    return (u - 1) // n


# ── Paillier key generation ───────────────────────────────────────────────────

def paillier_keygen(bits: int = 256):
    """
    Generate Paillier public/private keys.
    Public : (n, g)
    Private: (λ, μ)
    bits   : bit size of each prime p, q (n = p*q is 2*bits).
    """
    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)
        if p == q:
            continue
        n    = p * q
        n2   = n * n
        lam  = lcm(p - 1, q - 1)

        # Simplified Paillier: g = n + 1  (always valid)
        g   = n + 1

        # μ = (L(g^λ mod n²))^{-1} mod n
        gl  = pow(g, lam, n2)
        mu  = mod_inverse(L(gl, n), n)

        return (n, g), (lam, mu), p, q


# ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

def paillier_encrypt(m: int, public_key: tuple) -> int:
    n, g = public_key
    n2   = n * n
    if not (0 <= m < n):
        raise ValueError(f"Plaintext must be in [0, n): {m} >= {n}")
    # Choose random r with gcd(r, n) = 1
    while True:
        r = secrets.randbelow(n)
        if r > 0 and math.gcd(r, n) == 1:
            break
    return (pow(g, m, n2) * pow(r, n, n2)) % n2


def paillier_decrypt(c: int, public_key: tuple, private_key: tuple) -> int:
    n, g   = public_key
    lam, mu = private_key
    n2     = n * n
    return (L(pow(c, lam, n2), n) * mu) % n


# ── Homomorphic operations ────────────────────────────────────────────────────

def homo_add(c1: int, c2: int, n: int) -> int:
    """Enc(m1) × Enc(m2) mod n² = Enc(m1 + m2)"""
    return (c1 * c2) % (n * n)


def homo_add_const(c: int, k: int, public_key: tuple) -> int:
    """Enc(m) × g^k mod n² = Enc(m + k)"""
    n, g = public_key
    return (c * pow(g, k, n * n)) % (n * n)


def homo_mul_const(c: int, k: int, n: int) -> int:
    """Enc(m)^k mod n² = Enc(m × k)"""
    return pow(c, k, n * n)


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 11: Paillier Partially Homomorphic Encryption")
    print("=" * 60)

    print("\n  Generating Paillier keys (256-bit primes, 512-bit n)...")
    pub, priv, p, q = paillier_keygen(bits=256)
    n, g = pub
    lam, mu = priv
    print(f"  p = {p}")
    print(f"  q = {q}")
    print(f"  n = {n}")
    print(f"  g = n+1 = {g}")
    print(f"  λ = lcm(p-1, q-1) = {lam}")
    print(f"  μ = {mu}")

    # Basic encrypt/decrypt
    print("\n  --- Basic Encryption/Decryption ---")
    m = 42
    c = paillier_encrypt(m, pub)
    d = paillier_decrypt(c, pub, priv)
    print(f"  Plaintext  : {m}")
    print(f"  Ciphertext : {c}")
    print(f"  Decrypted  : {d}")
    assert d == m, "Paillier basic roundtrip failed"
    print("  ✓ Roundtrip verified")

    # Homomorphic addition
    print("\n  --- Homomorphic Addition: Dec(Enc(m1)×Enc(m2)) = m1+m2 ---")
    m1, m2 = 25, 17
    c1 = paillier_encrypt(m1, pub)
    c2 = paillier_encrypt(m2, pub)
    c_sum = homo_add(c1, c2, n)
    dec_sum = paillier_decrypt(c_sum, pub, priv)
    print(f"  m1 = {m1},  m2 = {m2}")
    print(f"  Enc(m1) = {c1}")
    print(f"  Enc(m2) = {c2}")
    print(f"  Enc(m1)×Enc(m2) mod n² = {c_sum}")
    print(f"  Dec(Enc(m1)×Enc(m2)) = {dec_sum}  (expected {m1+m2})")
    assert dec_sum == m1 + m2
    print("  ✓ Homomorphic addition verified")

    # Add constant without decrypting
    print("\n  --- Add Constant Without Decrypting ---")
    k = 100
    c_const = homo_add_const(c1, k, pub)
    dec_const = paillier_decrypt(c_const, pub, priv)
    print(f"  m1 = {m1},  k = {k}")
    print(f"  Dec(Enc(m1) × g^k) = {dec_const}  (expected {m1+k})")
    assert dec_const == m1 + k
    print("  ✓ Constant addition verified")

    # Scalar multiplication
    print("\n  --- Scalar Multiplication: Dec(Enc(m)^k) = m×k ---")
    k2 = 7
    c_mul = homo_mul_const(c1, k2, n)
    dec_mul = paillier_decrypt(c_mul, pub, priv)
    print(f"  m1 = {m1},  k = {k2}")
    print(f"  Dec(Enc(m1)^k) = {dec_mul}  (expected {m1*k2})")
    assert dec_mul == m1 * k2
    print("  ✓ Scalar multiplication verified")

    # Real-world application: encrypted voting tally
    print("\n  --- Application: Private Vote Tally ---")
    votes = [1, 0, 1, 1, 0, 1, 0, 1]   # 1=yes, 0=no
    enc_votes = [paillier_encrypt(v, pub) for v in votes]
    # Tally without decrypting individual votes
    tally_enc = enc_votes[0]
    for ev in enc_votes[1:]:
        tally_enc = homo_add(tally_enc, ev, n)
    tally = paillier_decrypt(tally_enc, pub, priv)
    print(f"  Votes    : {votes}")
    print(f"  Expected : {sum(votes)} yes votes")
    print(f"  Tallied (homomorphically, no individual vote decrypted): {tally}")
    assert tally == sum(votes)
    print("  ✓ Private tally verified — individual votes never decrypted!")

    print("\n  --- Properties ---")
    print("  • Additive homomorphism ONLY (not multiplicative → 'partially' HE)")
    print("  • Semantic security: two encryptions of same m are computationally indistinguishable")
    print("  • IND-CPA secure under Decisional Composite Residuosity (DCR) assumption")


if __name__ == "__main__":
    demo()
