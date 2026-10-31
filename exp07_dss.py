"""
Experiment 7: Digital Signature Standard (DSS / DSA)
Message authentication and integrity verification.
"""

import hashlib
import random
import math
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
from exp06_rsa import extended_gcd


def mod_inverse(a: int, m: int) -> int:
    _, x, _ = extended_gcd(a % m, m)
    return x % m


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


# ── DSA parameter generation ──────────────────────────────────────────────────

def generate_dsa_params(L=512, N=160):
    """
    Generate DSA domain parameters (p, q, g).
    L: bit length of p (512 for demo; 1024+ for production).
    N: bit length of q (160, i.e., SHA-1 output size).
    """
    # 1. Generate prime q (N-bit)
    while True:
        q = random.getrandbits(N)
        q |= (1 << (N - 1)) | 1
        if miller_rabin(q):
            break

    # 2. Generate prime p = k*q + 1 (L-bit)
    while True:
        k = random.getrandbits(L - N)
        p = k * q + 1
        if p.bit_length() == L and miller_rabin(p):
            break

    # 3. Generate g (generator of order q in Z_p*)
    while True:
        h = random.randint(2, p - 2)
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            break

    return p, q, g


# ── DSA key generation ────────────────────────────────────────────────────────

def generate_dsa_keypair(p, q, g):
    """Private key x, public key y = g^x mod p."""
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    return x, y


# ── Sign ──────────────────────────────────────────────────────────────────────

def dsa_sign(message: bytes, p, q, g, x) -> tuple:
    """
    Sign message with private key x.
    Returns (r, s).
    """
    h = int(hashlib.sha1(message).hexdigest(), 16)
    while True:
        k = random.randint(1, q - 1)
        r = pow(g, k, p) % q
        if r == 0:
            continue
        k_inv = mod_inverse(k, q)
        s = (k_inv * (h + x * r)) % q
        if s != 0:
            break
    return r, s


# ── Verify ────────────────────────────────────────────────────────────────────

def dsa_verify(message: bytes, signature: tuple, p, q, g, y) -> bool:
    """Verify signature (r, s) with public key y."""
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    h = int(hashlib.sha1(message).hexdigest(), 16)
    w  = mod_inverse(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v  = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    return v == r


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 7: Digital Signature Standard (DSS/DSA)")
    print("=" * 60)

    print("\n  Generating DSA parameters (L=512, N=160)...")
    p, q, g = generate_dsa_params(L=512, N=160)
    print(f"  p ({p.bit_length()} bits) = {p}")
    print(f"  q ({q.bit_length()} bits) = {q}")
    print(f"  g = {g}")

    print("\n  --- Key Generation ---")
    x, y = generate_dsa_keypair(p, q, g)
    print(f"  Private key x = {x}")
    print(f"  Public  key y = {y}")

    print("\n  --- Signing ---")
    message = b"Hello, this is a secure message!"
    print(f"  Message : {message.decode()}")
    h = int(hashlib.sha1(message).hexdigest(), 16)
    print(f"  SHA-1 hash (H) : {h}")
    r, s = dsa_sign(message, p, q, g, x)
    print(f"  Signature r = {r}")
    print(f"  Signature s = {s}")

    print("\n  --- Verification ---")
    valid = dsa_verify(message, (r, s), p, q, g, y)
    print(f"  Signature valid: {valid}")
    assert valid, "Signature verification failed!"
    print("  ✓ Authentic signature verified")

    # Tampered message
    print("\n  --- Tampered Message Test ---")
    tampered = b"Hello, this is a TAMPERED message!"
    valid_tampered = dsa_verify(tampered, (r, s), p, q, g, y)
    print(f"  Tampered message: {tampered.decode()}")
    print(f"  Signature valid : {valid_tampered}")
    assert not valid_tampered, "Should reject tampered message!"
    print("  ✓ Tampered message correctly rejected")

    # Wrong key
    print("\n  --- Wrong Key Test ---")
    x2, y2 = generate_dsa_keypair(p, q, g)
    valid_wrongkey = dsa_verify(message, (r, s), p, q, g, y2)
    print(f"  Using wrong public key: {valid_wrongkey}")
    assert not valid_wrongkey
    print("  ✓ Wrong key correctly rejected")

    print("\n  --- DSS Security Properties ---")
    print("  1. Unforgeability: Only holder of x can produce valid (r,s)")
    print("  2. Non-repudiation: Signer cannot deny producing the signature")
    print("  3. Integrity: Any bit-flip in message invalidates signature")
    print("  4. k reuse attack: If same k used twice → x leaks (critical!)")


if __name__ == "__main__":
    demo()
