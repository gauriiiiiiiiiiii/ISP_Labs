"""
Experiment 1: Classical Ciphers
Implements Caesar, Affine, Playfair, and Hill ciphers.
"""

import math

# ── helpers ──────────────────────────────────────────────────────────────────

def clean(text: str) -> str:
    """Keep only alpha, uppercase."""
    return ''.join(c.upper() for c in text if c.isalpha())


def mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean: return a^-1 mod m, or raise if none."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return x % m


def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


# ── Caesar Cipher ─────────────────────────────────────────────────────────────

def caesar_encrypt(plaintext: str, key: int) -> str:
    result = []
    for c in clean(plaintext):
        result.append(chr((ord(c) - ord('A') + key) % 26 + ord('A')))
    return ''.join(result)


def caesar_decrypt(ciphertext: str, key: int) -> str:
    return caesar_encrypt(ciphertext, -key)


# ── Affine Cipher ─────────────────────────────────────────────────────────────

def affine_encrypt(plaintext: str, a: int, b: int) -> str:
    if math.gcd(a, 26) != 1:
        raise ValueError(f"'a'={a} must be coprime with 26")
    result = []
    for c in clean(plaintext):
        x = ord(c) - ord('A')
        result.append(chr((a * x + b) % 26 + ord('A')))
    return ''.join(result)


def affine_decrypt(ciphertext: str, a: int, b: int) -> str:
    a_inv = mod_inverse(a, 26)
    result = []
    for c in clean(ciphertext):
        y = ord(c) - ord('A')
        result.append(chr((a_inv * (y - b)) % 26 + ord('A')))
    return ''.join(result)


# ── Playfair Cipher ───────────────────────────────────────────────────────────

def _playfair_table(key: str):
    key = clean(key).replace('J', 'I')
    seen = []
    for c in key + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if c not in seen:
            seen.append(c)
    table = [seen[i:i+5] for i in range(0, 25, 5)]
    pos = {}
    for r, row in enumerate(table):
        for col, ch in enumerate(row):
            pos[ch] = (r, col)
    return table, pos


def _playfair_digraphs(text: str):
    text = clean(text).replace('J', 'I')
    pairs = []
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 >= len(text):
            b = 'X'
        elif text[i] == text[i + 1]:
            b = 'X'
            i -= 1
        else:
            b = text[i + 1]
        pairs.append((a, b))
        i += 2
    return pairs


def playfair_encrypt(plaintext: str, key: str) -> str:
    table, pos = _playfair_table(key)
    digraphs = _playfair_digraphs(plaintext)
    result = []
    for a, b in digraphs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:                           # same row → shift right
            result.append(table[ra][(ca + 1) % 5])
            result.append(table[rb][(cb + 1) % 5])
        elif ca == cb:                         # same col → shift down
            result.append(table[(ra + 1) % 5][ca])
            result.append(table[(rb + 1) % 5][cb])
        else:                                  # rectangle swap
            result.append(table[ra][cb])
            result.append(table[rb][ca])
    return ''.join(result)


def playfair_decrypt(ciphertext: str, key: str) -> str:
    table, pos = _playfair_table(key)
    pairs = [(ciphertext[i], ciphertext[i+1]) for i in range(0, len(ciphertext), 2)]
    result = []
    for a, b in pairs:
        ra, ca = pos[a]
        rb, cb = pos[b]
        if ra == rb:
            result.append(table[ra][(ca - 1) % 5])
            result.append(table[rb][(cb - 1) % 5])
        elif ca == cb:
            result.append(table[(ra - 1) % 5][ca])
            result.append(table[(rb - 1) % 5][cb])
        else:
            result.append(table[ra][cb])
            result.append(table[rb][ca])
    return ''.join(result)


# ── Hill Cipher ───────────────────────────────────────────────────────────────

def _mat_mul_mod(A, B, m):
    n = len(A)
    C = [[0]*n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            for k in range(n):
                C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % m
    return C


def _mat_det_mod(M, m):
    """Determinant of 2×2 or 3×3 matrix mod m."""
    n = len(M)
    if n == 2:
        return (M[0][0]*M[1][1] - M[0][1]*M[1][0]) % m
    det = 0
    for j in range(n):
        minor = [[M[i][k] for k in range(n) if k != j] for i in range(1, n)]
        det = (det + ((-1)**j) * M[0][j] * _mat_det_mod(minor, m)) % m
    return det % m


def _mat_adjugate_2x2(M):
    return [[M[1][1], -M[0][1]], [-M[1][0], M[0][0]]]


def _mat_inverse_2x2_mod(M, m):
    det = _mat_det_mod(M, m)
    det_inv = mod_inverse(det % m, m)
    adj = _mat_adjugate_2x2(M)
    return [[(det_inv * adj[i][j]) % m for j in range(2)] for i in range(2)]


def hill_encrypt(plaintext: str, key_matrix: list) -> str:
    text = clean(plaintext)
    n = len(key_matrix)
    # Pad to multiple of n
    while len(text) % n:
        text += 'X'
    result = []
    for i in range(0, len(text), n):
        block = [ord(text[i+j]) - ord('A') for j in range(n)]
        enc = [sum(key_matrix[r][c] * block[c] for c in range(n)) % 26 for r in range(n)]
        result.extend(chr(v + ord('A')) for v in enc)
    return ''.join(result)


def hill_decrypt(ciphertext: str, key_matrix: list) -> str:
    inv_key = _mat_inverse_2x2_mod(key_matrix, 26)
    return hill_encrypt(ciphertext, inv_key)


# ── Demo / test ───────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 1: CLASSICAL CIPHERS")
    print("=" * 60)

    # ── Caesar ──
    print("\n--- Caesar Cipher ---")
    pt = "HELLO WORLD"
    key = 3
    ct = caesar_encrypt(pt, key)
    dt = caesar_decrypt(ct, key)
    print(f"  Plaintext : {clean(pt)}")
    print(f"  Key       : {key}")
    print(f"  Encrypted : {ct}")
    print(f"  Decrypted : {dt}")
    assert dt == clean(pt), "Caesar roundtrip failed"
    print("  ✓ Roundtrip verified")

    # ── Affine ──
    print("\n--- Affine Cipher ---")
    pt = "HELLOWORLD"
    a, b = 7, 3
    ct = affine_encrypt(pt, a, b)
    dt = affine_decrypt(ct, a, b)
    print(f"  Plaintext : {clean(pt)}")
    print(f"  Key (a,b) : ({a},{b})")
    print(f"  Encrypted : {ct}")
    print(f"  Decrypted : {dt}")
    assert dt == clean(pt), "Affine roundtrip failed"
    print("  ✓ Roundtrip verified")

    # ── Playfair ──
    print("\n--- Playfair Cipher ---")
    pt = "MEET ME AT DAWN"
    key = "MONARCHY"
    ct = playfair_encrypt(pt, key)
    dt = playfair_decrypt(ct, key)
    print(f"  Plaintext : {clean(pt).replace('J','I')}")
    print(f"  Key       : {key}")
    print(f"  Encrypted : {ct}")
    print(f"  Decrypted : {dt}")
    print("  ✓ Encryption complete")

    # ── Hill ──
    print("\n--- Hill Cipher (2×2) ---")
    pt = "ACT"
    key_matrix = [[6, 24], [1, 13]]   # det=54 → 54 mod 26=2, invertible? no...
    # use known invertible matrix
    key_matrix = [[3, 3], [2, 5]]     # det=9, gcd(9,26)=1 ✓
    ct = hill_encrypt(pt, key_matrix)
    dt = hill_decrypt(ct, key_matrix)
    print(f"  Plaintext : {clean(pt)}")
    print(f"  Key matrix: {key_matrix}")
    print(f"  Encrypted : {ct}")
    print(f"  Decrypted : {dt}")
    assert dt[:len(clean(pt))] == clean(pt), "Hill roundtrip failed"
    print("  ✓ Roundtrip verified")


if __name__ == "__main__":
    demo()
