"""
Experiment 5: Block Cipher Modes of Operation — ECB, CBC, CFB, OFB, CTR
Uses the AES-128 implementation from exp03. Compares ciphertext patterns.
"""

import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) if '__file__' in dir() else os.getcwd())
from exp03_aes import aes_encrypt_block, aes_decrypt_block, pkcs7_pad, pkcs7_unpad


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


BS = 16   # AES block size


# ── ECB ───────────────────────────────────────────────────────────────────────

def ecb_encrypt(pt: bytes, key: bytes) -> bytes:
    padded = pkcs7_pad(pt)
    return b''.join(aes_encrypt_block(padded[i:i+BS], key) for i in range(0, len(padded), BS))


def ecb_decrypt(ct: bytes, key: bytes) -> bytes:
    pt = b''.join(aes_decrypt_block(ct[i:i+BS], key) for i in range(0, len(ct), BS))
    return pkcs7_unpad(pt)


# ── CBC ───────────────────────────────────────────────────────────────────────

def cbc_encrypt(pt: bytes, key: bytes, iv: bytes) -> bytes:
    padded = pkcs7_pad(pt)
    prev   = iv
    ct     = b''
    for i in range(0, len(padded), BS):
        block = xor_bytes(padded[i:i+BS], prev)
        enc   = aes_encrypt_block(block, key)
        ct   += enc
        prev  = enc
    return ct


def cbc_decrypt(ct: bytes, key: bytes, iv: bytes) -> bytes:
    prev = iv
    pt   = b''
    for i in range(0, len(ct), BS):
        dec  = aes_decrypt_block(ct[i:i+BS], key)
        pt  += xor_bytes(dec, prev)
        prev = ct[i:i+BS]
    return pkcs7_unpad(pt)


# ── CFB ───────────────────────────────────────────────────────────────────────

def cfb_encrypt(pt: bytes, key: bytes, iv: bytes) -> bytes:
    padded = pkcs7_pad(pt)
    prev   = iv
    ct     = b''
    for i in range(0, len(padded), BS):
        enc  = aes_encrypt_block(prev, key)
        blk  = xor_bytes(padded[i:i+BS], enc)
        ct  += blk
        prev = blk
    return ct


def cfb_decrypt(ct: bytes, key: bytes, iv: bytes) -> bytes:
    prev = iv
    pt   = b''
    for i in range(0, len(ct), BS):
        enc  = aes_encrypt_block(prev, key)
        pt  += xor_bytes(ct[i:i+BS], enc)
        prev = ct[i:i+BS]
    return pkcs7_unpad(pt)


# ── OFB ───────────────────────────────────────────────────────────────────────

def ofb_encrypt(pt: bytes, key: bytes, iv: bytes) -> bytes:
    padded = pkcs7_pad(pt)
    keystream = b''
    ks = iv
    while len(keystream) < len(padded):
        ks = aes_encrypt_block(ks, key)
        keystream += ks
    return bytes(p ^ k for p, k in zip(padded, keystream))


def ofb_decrypt(ct: bytes, key: bytes, iv: bytes) -> bytes:
    keystream = b''
    ks = iv
    while len(keystream) < len(ct):
        ks = aes_encrypt_block(ks, key)
        keystream += ks
    pt = bytes(c ^ k for c, k in zip(ct, keystream))
    return pkcs7_unpad(pt)


# ── CTR ───────────────────────────────────────────────────────────────────────

def _ctr_keystream(nonce: bytes, length: int, key: bytes) -> bytes:
    stream = b''
    counter = 0
    while len(stream) < length:
        ctr_block = nonce + counter.to_bytes(8, 'big')
        stream += aes_encrypt_block(ctr_block, key)
        counter += 1
    return stream[:length]


def ctr_encrypt(pt: bytes, key: bytes, nonce: bytes) -> bytes:
    ks = _ctr_keystream(nonce, len(pt), key)
    return bytes(p ^ k for p, k in zip(pt, ks))


def ctr_decrypt(ct: bytes, key: bytes, nonce: bytes) -> bytes:
    ks = _ctr_keystream(nonce, len(ct), key)
    return bytes(c ^ k for c, k in zip(ct, ks))


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 5: AES Block Cipher Modes (ECB/CBC/CFB/OFB/CTR)")
    print("=" * 60)

    key  = b'0123456789ABCDEF'   # 16 bytes
    iv   = b'\x00' * BS
    nonce = b'\x00' * 8

    # Two identical 16-byte blocks → demonstrates ECB weakness
    pt   = b'AAAAAAAAAAAAAAAA' * 2    # 32 bytes, two identical blocks

    print(f"\n  Key        : {key}")
    print(f"  IV/Nonce   : (all zeros, 16/8 bytes)")
    print(f"  Plaintext  : {pt!r}")
    print(f"  (Note: two identical 16-byte blocks)")

    tests = [
        ("ECB",
         ecb_encrypt(pt, key),
         lambda ct: ecb_decrypt(ct, key)),
        ("CBC",
         cbc_encrypt(pt, key, iv),
         lambda ct: cbc_decrypt(ct, key, iv)),
        ("CFB",
         cfb_encrypt(pt, key, iv),
         lambda ct: cfb_decrypt(ct, key, iv)),
        ("OFB",
         ofb_encrypt(pt, key, iv),
         lambda ct: ofb_decrypt(ct, key, iv)),
        ("CTR",
         ctr_encrypt(pt, key, nonce),
         lambda ct: ctr_decrypt(ct, key, nonce)),
    ]

    print(f"\n  {'Mode':<5} | {'Ciphertext (hex, first 64 chars)':<64} | Block1==Block2")
    print(f"  {'-'*5}-+-{'-'*64}-+-{'-'*14}")
    for mode, ct, dec_fn in tests:
        b1 = ct[:BS].hex().upper()
        b2 = ct[BS:2*BS].hex().upper() if len(ct) >= 2*BS else '(n/a)'
        same = "SAME (⚠ ECB leak!)" if b1 == b2 else "Different ✓"
        print(f"  {mode:<5} | {ct.hex().upper()[:64]:<64} | {same}")
        recovered = dec_fn(ct)
        assert recovered == pt, f"{mode} roundtrip failed! got {recovered!r}"

    print("\n  ✓ All 5 modes encrypt/decrypt correctly")
    print("\n  --- ECB Pattern Leakage Explanation ---")
    print("  ECB encrypts each block independently.")
    print("  Identical plaintext blocks → identical ciphertext blocks.")
    print("  CBC/CFB/OFB/CTR use chaining/feedback → no pattern leakage.")

    # Additional: real-text ECB pattern leak demo
    print("\n  --- Pattern Analysis with Structured Data ---")
    structured = (b'ATTACK AT DAWN!!' * 3)  # three identical blocks
    ecb_ct = ecb_encrypt(structured, key)
    cbc_ct = cbc_encrypt(structured, key, iv)
    ecb_blocks = [ecb_ct[i:i+BS].hex() for i in range(0, len(ecb_ct)-BS, BS)]
    cbc_blocks = [cbc_ct[i:i+BS].hex() for i in range(0, len(cbc_ct)-BS, BS)]
    ecb_unique = len(set(ecb_blocks))
    cbc_unique = len(set(cbc_blocks))
    print(f"  Structured PT (3×same block):")
    print(f"    ECB unique blocks: {ecb_unique}/3  ← patterns visible")
    print(f"    CBC unique blocks: {cbc_unique}/3  ← no patterns")


if __name__ == "__main__":
    demo()
