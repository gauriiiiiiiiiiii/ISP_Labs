"""
Experiment 3: AES-128 with round-wise transformation analysis.
Full from-scratch AES: SubBytes, ShiftRows, MixColumns, AddRoundKey.
"""

# ── AES constants ─────────────────────────────────────────────────────────────

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

# ── GF(2^8) arithmetic ────────────────────────────────────────────────────────

def xtime(a: int) -> int:
    """Multiply by x (0x02) in GF(2^8)."""
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff


def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) using peasant's algorithm."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p


# ── State helpers ─────────────────────────────────────────────────────────────

def bytes_to_state(b: bytes) -> list:
    """16-byte block → 4×4 column-major state."""
    return [[b[r + 4*c] for c in range(4)] for r in range(4)]


def state_to_bytes(s: list) -> bytes:
    return bytes(s[r][c] for c in range(4) for r in range(4))


# ── AES transformations ───────────────────────────────────────────────────────

def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def inv_sub_bytes(state):
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def shift_rows(state):
    return [[(state[r][(c + r) % 4]) for c in range(4)] for r in range(4)]


def inv_shift_rows(state):
    return [[(state[r][(c - r) % 4]) for c in range(4)] for r in range(4)]


def mix_columns(state):
    out = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        out[0][c] = gf_mul(0x02,col[0])^gf_mul(0x03,col[1])^col[2]^col[3]
        out[1][c] = col[0]^gf_mul(0x02,col[1])^gf_mul(0x03,col[2])^col[3]
        out[2][c] = col[0]^col[1]^gf_mul(0x02,col[2])^gf_mul(0x03,col[3])
        out[3][c] = gf_mul(0x03,col[0])^col[1]^col[2]^gf_mul(0x02,col[3])
    return out


def inv_mix_columns(state):
    out = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        out[0][c] = gf_mul(0x0e,col[0])^gf_mul(0x0b,col[1])^gf_mul(0x0d,col[2])^gf_mul(0x09,col[3])
        out[1][c] = gf_mul(0x09,col[0])^gf_mul(0x0e,col[1])^gf_mul(0x0b,col[2])^gf_mul(0x0d,col[3])
        out[2][c] = gf_mul(0x0d,col[0])^gf_mul(0x09,col[1])^gf_mul(0x0e,col[2])^gf_mul(0x0b,col[3])
        out[3][c] = gf_mul(0x0b,col[0])^gf_mul(0x0d,col[1])^gf_mul(0x09,col[2])^gf_mul(0x0e,col[3])
    return out


def add_round_key(state, round_key):
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


# ── Key expansion ─────────────────────────────────────────────────────────────

def key_expansion(key: bytes) -> list:
    """AES-128 key schedule → list of 11 round-key states."""
    w = list(key)                            # 16 bytes = 4 words × 4 bytes
    for i in range(4, 44):
        temp = w[(i-1)*4 : i*4]
        if i % 4 == 0:
            # RotWord + SubWord + Rcon
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i//4 - 1]
        w += [w[(i-4)*4+j] ^ temp[j] for j in range(4)]
    # Split into 11 round key states
    round_keys = []
    for rnd in range(11):
        b = bytes(w[rnd*16 : (rnd+1)*16])
        round_keys.append(bytes_to_state(b))
    return round_keys


# ── AES encrypt / decrypt ─────────────────────────────────────────────────────

def aes_encrypt_block(block: bytes, key: bytes, verbose=False) -> bytes:
    rk = key_expansion(key)
    state = bytes_to_state(block)
    state = add_round_key(state, rk[0])
    if verbose:
        print(f"    Initial ARK   : {state_to_bytes(state).hex().upper()}")

    for rnd in range(1, 11):
        state = sub_bytes(state)
        if verbose:
            print(f"  Round {rnd:2d} SubBytes  : {state_to_bytes(state).hex().upper()}")
        state = shift_rows(state)
        if verbose:
            print(f"  Round {rnd:2d} ShiftRows : {state_to_bytes(state).hex().upper()}")
        if rnd < 10:
            state = mix_columns(state)
            if verbose:
                print(f"  Round {rnd:2d} MixCols  : {state_to_bytes(state).hex().upper()}")
        state = add_round_key(state, rk[rnd])
        if verbose:
            print(f"  Round {rnd:2d} ARK      : {state_to_bytes(state).hex().upper()}")
    return state_to_bytes(state)


def aes_decrypt_block(block: bytes, key: bytes) -> bytes:
    rk = key_expansion(key)
    state = bytes_to_state(block)
    state = add_round_key(state, rk[10])
    for rnd in range(9, -1, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, rk[rnd])
        if rnd > 0:
            state = inv_mix_columns(state)
    return state_to_bytes(state)


# ── PKCS#7 padding ────────────────────────────────────────────────────────────

def pkcs7_pad(data: bytes, block=16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad] * pad)


def pkcs7_unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


def aes_encrypt(pt: bytes, key: bytes) -> bytes:
    padded = pkcs7_pad(pt)
    return b''.join(aes_encrypt_block(padded[i:i+16], key) for i in range(0, len(padded), 16))


def aes_decrypt(ct: bytes, key: bytes) -> bytes:
    pt = b''.join(aes_decrypt_block(ct[i:i+16], key) for i in range(0, len(ct), 16))
    return pkcs7_unpad(pt)


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 3: AES-128 with Round-wise Analysis")
    print("=" * 60)

    # NIST FIPS-197 test vector
    key   = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
    block = bytes.fromhex('00112233445566778899aabbccddeeff')
    expected_ct = bytes.fromhex('69c4e0d86a7b0430d8cdb78070b4c55a')   # NIST FIPS-197 Appendix C.1

    print(f"\n  Key       : {key.hex().upper()}")
    print(f"  Plaintext : {block.hex().upper()}")
    print(f"\n  === Round-wise Transformations ===")
    ct = aes_encrypt_block(block, key, verbose=True)
    print(f"\n  Ciphertext : {ct.hex().upper()}")
    print(f"  Expected   : {expected_ct.hex().upper()}")
    assert ct == expected_ct, "AES-128 NIST vector failed!"
    print("  ✓ NIST vector verified")

    # Roundtrip with arbitrary text
    key2 = b'SecretKey1234567'          # 16 bytes
    pt   = b'AES Experiment 3'
    ct2  = aes_encrypt(pt, key2)
    dt2  = aes_decrypt(ct2, key2)
    print(f"\n  Plaintext  : {pt}")
    print(f"  Encrypted  : {ct2.hex().upper()}")
    print(f"  Decrypted  : {dt2}")
    assert dt2 == pt
    print("  ✓ Roundtrip verified")


if __name__ == "__main__":
    demo()
