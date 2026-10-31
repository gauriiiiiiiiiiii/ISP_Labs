"""
Experiment 10: Shamir's Secret Sharing Scheme
Splits a secret into n shares; any k shares reconstruct it.
Uses polynomial interpolation over a prime field.
"""

import random
import secrets


# ── Large prime for the field ─────────────────────────────────────────────────
# Must be larger than the secret and n.
PRIME = 2**127 - 1   # Mersenne prime (large enough for text secrets)


# ── Polynomial evaluation ──────────────────────────────────────────────────────

def _eval_poly(coeffs: list, x: int, p: int) -> int:
    """Evaluate polynomial at x mod p using Horner's method."""
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % p
    return result


# ── Share generation ──────────────────────────────────────────────────────────

def split_secret(secret: int, k: int, n: int, p: int = PRIME) -> list:
    """
    Split `secret` into n shares, any k reconstruct it.
    Returns list of (x, y) pairs.
    """
    if secret >= p:
        raise ValueError("Secret must be less than prime p")
    if k < 2 or k > n:
        raise ValueError("Require 2 ≤ k ≤ n")

    # Random polynomial of degree k-1: f(x) = secret + a1*x + ... + a_{k-1}*x^{k-1}
    coeffs = [secret] + [secrets.randbelow(p) for _ in range(k - 1)]
    shares = [(i, _eval_poly(coeffs, i, p)) for i in range(1, n + 1)]
    return shares


# ── Lagrange interpolation ────────────────────────────────────────────────────

def _mod_inverse(a: int, p: int) -> int:
    """Fermat's little theorem: a^{p-2} mod p (valid for prime p)."""
    return pow(a, p - 2, p)


def reconstruct_secret(shares: list, p: int = PRIME) -> int:
    """
    Reconstruct secret from k shares using Lagrange interpolation.
    shares: list of (x, y) tuples (any k of them).
    """
    secret = 0
    xs = [s[0] for s in shares]
    ys = [s[1] for s in shares]
    k  = len(shares)
    for i in range(k):
        num = ys[i]
        den = 1
        for j in range(k):
            if i == j:
                continue
            num = (num * (-xs[j])) % p
            den = (den * (xs[i] - xs[j])) % p
        secret = (secret + num * _mod_inverse(den, p)) % p
    return secret


# ── Text ↔ int helpers ────────────────────────────────────────────────────────

def text_to_int(text: str) -> int:
    return int.from_bytes(text.encode('utf-8'), 'big')


def int_to_text(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, 'big').decode('utf-8')


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 10: Shamir's Secret Sharing Scheme")
    print("=" * 60)

    # Example 1: integer secret, (3, 5) threshold
    print("\n  --- Example 1: Integer Secret ---")
    secret = 1234567890
    k, n   = 3, 5
    print(f"  Secret   : {secret}")
    print(f"  Threshold: {k}-of-{n}")

    shares = split_secret(secret, k, n)
    print(f"\n  Generated shares:")
    for x, y in shares:
        print(f"    Share {x}: {y}")

    # Reconstruct with exactly k shares
    chosen = shares[:k]
    recovered = reconstruct_secret(chosen)
    print(f"\n  Using shares {[s[0] for s in chosen]}: recovered = {recovered}")
    assert recovered == secret
    print("  ✓ Exact threshold: success")

    # Reconstruct with more shares
    chosen2 = shares[:k+1]
    recovered2 = reconstruct_secret(chosen2)
    assert recovered2 == secret
    print(f"  Using {k+1} shares: recovered = {recovered2}  ✓")

    # Try with k-1 shares (should give wrong answer)
    chosen_few = shares[:k-1]
    wrong = reconstruct_secret(chosen_few)
    print(f"  Using only {k-1} shares: recovered = {wrong}  (wrong — security holds)")
    assert wrong != secret
    print("  ✓ Below threshold: incorrect reconstruction (security verified)")

    # Example 2: text secret
    print("\n  --- Example 2: Text Secret ---")
    secret_text = "TopSecret!"
    secret_int  = text_to_int(secret_text)
    print(f"  Secret text : '{secret_text}'")
    print(f"  As integer  : {secret_int}")

    k2, n2 = 2, 4
    shares2 = split_secret(secret_int, k2, n2)
    print(f"\n  Shares (2-of-4):")
    for x, y in shares2:
        print(f"    Share {x}: {y}")

    # Use any 2 shares
    import random
    chosen3 = random.sample(shares2, k2)
    chosen3.sort(key=lambda s: s[0])
    rec3 = reconstruct_secret(chosen3)
    rec_text = int_to_text(rec3)
    print(f"\n  Using shares {[s[0] for s in chosen3]}: '{rec_text}'")
    assert rec_text == secret_text
    print("  ✓ Text secret reconstructed correctly")

    # Example 3: full demonstration with all subsets
    print("\n  --- Example 3: Exhaustive Subset Test (k=2, n=4) ---")
    from itertools import combinations
    all_valid = True
    for combo in combinations(range(n2), k2):
        subset = [shares2[i] for i in combo]
        r = reconstruct_secret(subset)
        match = (r == secret_int)
        print(f"    Shares {[s[0] for s in subset]}: {'✓' if match else '✗'}")
        if not match:
            all_valid = False
    assert all_valid
    print(f"  ✓ All C({n2},{k2})={len(list(combinations(range(n2),k2)))} subsets reconstruct correctly")

    print("\n  --- Information-Theoretic Security ---")
    print("  • Any k-1 shares reveal ZERO information about the secret.")
    print("  • Based on polynomial interpolation over a finite field.")
    print("  • Perfect information-theoretic security (unlike computationally secure schemes).")


if __name__ == "__main__":
    demo()
