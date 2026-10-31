"""
Experiment 4: RC4 Stream Cipher
Simulates KSA (Key Scheduling Algorithm) and PRGA (Pseudo-Random Generation Algorithm).
Analyzes keystream generation and encryption process.
"""


# ── KSA ──────────────────────────────────────────────────────────────────────

def ksa(key: bytes) -> list:
    """Key Scheduling Algorithm — produces initial permutation S."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


# ── PRGA ─────────────────────────────────────────────────────────────────────

def prga(S: list, length: int):
    """Pseudo-Random Generation Algorithm — yields keystream bytes."""
    S = S[:]
    i = j = 0
    stream = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        stream.append(k)
    return stream


# ── RC4 encrypt / decrypt ─────────────────────────────────────────────────────

def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 is symmetric: same function for encrypt and decrypt."""
    S = ksa(key)
    stream = prga(S, len(data))
    return bytes(b ^ k for b, k in zip(data, stream))


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 4: RC4 Stream Cipher")
    print("=" * 60)

    key       = b'SecretKey'
    plaintext = b'Hello RC4 World!'

    print(f"\n  Key       : {key}")
    print(f"  Plaintext : {plaintext}")

    # KSA analysis
    S = ksa(key)
    print(f"\n  --- KSA ---")
    print(f"  S[0..7]   : {S[:8]}")

    # Keystream analysis
    stream = prga(S, 16)
    print(f"\n  --- PRGA (first 16 keystream bytes) ---")
    hex_stream = ' '.join(f'{b:02X}' for b in stream)
    print(f"  Keystream : {hex_stream}")

    # Encrypt
    ciphertext = rc4(key, plaintext)
    print(f"\n  --- Encryption ---")
    print(f"  Ciphertext (hex): {ciphertext.hex().upper()}")

    # Decrypt (same operation)
    decrypted = rc4(key, ciphertext)
    print(f"\n  --- Decryption ---")
    print(f"  Decrypted : {decrypted}")

    assert decrypted == plaintext, "RC4 roundtrip failed!"
    print("  ✓ Roundtrip verified")

    # Keystream statistics
    full_stream = prga(ksa(key), 256)
    unique = len(set(full_stream))
    print(f"\n  --- Keystream Statistics (256 bytes) ---")
    print(f"  Unique byte values : {unique}/256")
    print(f"  Mean value         : {sum(full_stream)/len(full_stream):.2f} (expected ~127.5)")

    # Demonstrate key sensitivity
    print(f"\n  --- Key Sensitivity ---")
    key2 = b'SecretKey!'           # one char different
    ct2  = rc4(key2, plaintext)
    diff = sum(a != b for a, b in zip(ciphertext, ct2))
    print(f"  Key 1 CT : {ciphertext.hex().upper()}")
    print(f"  Key 2 CT : {ct2.hex().upper()}")
    print(f"  Different bytes: {diff}/{len(plaintext)}")

    # Known weakness: same key + nonce reuse → XOR reveals plaintext
    print(f"\n  --- Known Weakness: Keystream Reuse ---")
    pt1 = b'ATTACK AT DAWN!!'
    pt2 = b'ATTACK AT NOON!!'
    ct1 = rc4(key, pt1)
    ct2b = rc4(key, pt2)
    xored = bytes(a ^ b for a, b in zip(ct1, ct2b))
    recovered = bytes(a ^ b for a, b in zip(xored, pt1))
    print(f"  If same key reused: CT1 XOR CT2 XOR PT1 = {recovered}")
    print(f"  Reveals PT2       : {pt2}")
    print("  ✓ Weakness demonstrated — never reuse RC4 key+nonce!")


if __name__ == "__main__":
    demo()
