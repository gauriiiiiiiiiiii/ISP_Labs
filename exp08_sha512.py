"""
Experiment 8: SHA-512 Cryptographic Hash Function
Full from-scratch SHA-512 implementation + hashlib verification.
Generates message digests for different inputs.
"""

import struct
import hashlib


# ── SHA-512 constants ─────────────────────────────────────────────────────────

# First 64 bits of fractional parts of cube roots of first 80 primes
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]

# Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
H0 = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
]

MASK64 = 0xFFFFFFFFFFFFFFFF


def rotr64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & MASK64


def sha512(message: bytes) -> bytes:
    # Pre-processing: padding
    ml = len(message) * 8          # message length in bits
    message = bytearray(message)
    message.append(0x80)
    while len(message) % 128 != 112:
        message.append(0x00)
    message += ml.to_bytes(16, 'big')

    # Initialize hash values
    H = H0[:]

    # Process each 1024-bit (128-byte) block
    for block_start in range(0, len(message), 128):
        chunk = message[block_start:block_start + 128]

        # Prepare message schedule W[0..79]
        W = list(struct.unpack('>16Q', chunk))
        for i in range(16, 80):
            s0 = rotr64(W[i-15], 1)  ^ rotr64(W[i-15], 8)  ^ (W[i-15] >> 7)
            s1 = rotr64(W[i-2],  19) ^ rotr64(W[i-2],  61) ^ (W[i-2]  >> 6)
            W.append((W[i-16] + s0 + W[i-7] + s1) & MASK64)

        a, b, c, d, e, f, g, h = H

        for i in range(80):
            S1    = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
            ch    = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + W[i]) & MASK64
            S0    = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
            maj   = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & MASK64

            h = g; g = f; f = e
            e = (d + temp1) & MASK64
            d = c; c = b; b = a
            a = (temp1 + temp2) & MASK64

        H = [(H[i] + v) & MASK64 for i, v in enumerate([a, b, c, d, e, f, g, h])]

    return struct.pack('>8Q', *H)


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 8: SHA-512 Cryptographic Hash Function")
    print("=" * 60)

    test_inputs = [
        b"",
        b"abc",
        b"Hello, World!",
        b"The quick brown fox jumps over the lazy dog",
        b"ISP Lab Experiment 8 - SHA-512",
        b"a" * 1000,
    ]

    print(f"\n  {'Input':<45} | SHA-512 Digest (first 32 hex chars)")
    print(f"  {'-'*45}-+-{'-'*65}")

    for inp in test_inputs:
        our_hash  = sha512(inp).hex()
        ref_hash  = hashlib.sha512(inp).hexdigest()
        label     = repr(inp) if len(inp) <= 40 else f"'{inp[:20].decode()}...' ({len(inp)} bytes)"
        match     = "✓" if our_hash == ref_hash else "✗"
        print(f"  {label:<45} | {our_hash[:32]}...  {match}")
        assert our_hash == ref_hash, f"Mismatch for {inp!r}!"

    print("\n  ✓ All digests match Python's hashlib.sha512")

    # Avalanche effect
    print("\n  --- Avalanche Effect ---")
    m1 = b"Hello"
    m2 = b"hello"    # single bit difference (H vs h)
    h1 = sha512(m1).hex()
    h2 = sha512(m2).hex()
    bits1 = bin(int(h1, 16))[2:].zfill(512)
    bits2 = bin(int(h2, 16))[2:].zfill(512)
    diff  = sum(a != b for a, b in zip(bits1, bits2))
    print(f"  m1 = {m1} → {h1[:32]}...")
    print(f"  m2 = {m2} → {h2[:32]}...")
    print(f"  Changed bits: {diff}/512 ({diff/512*100:.1f}%)  — ideal ≈ 50%")

    # Pre-image resistance
    print("\n  --- Properties ---")
    print("  1. Pre-image resistance  : Given H(m), infeasible to find m")
    print("  2. Second pre-image      : Given m1, infeasible to find m2 with H(m1)=H(m2)")
    print("  3. Collision resistance  : Infeasible to find any (m1,m2) with H(m1)=H(m2)")
    print("  4. Output size           : 512 bits = 64 bytes")
    print("  5. Block size            : 1024 bits, 80 rounds")


if __name__ == "__main__":
    demo()
