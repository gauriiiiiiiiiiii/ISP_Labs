"""
Experiment 9: Needham-Schroeder Authentication Protocol
Simulates the symmetric-key variant.
Demonstrates the replay attack vulnerability and the Denning-Sacco fix (timestamps).
"""

import os
import time
import hashlib
import secrets


# ── Simplified symmetric encryption (XOR-based for simulation) ────────────────
# Real deployment would use AES-CBC; here we keep it readable.

def sym_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Simulate encryption: AES-like (actually XOR keystream for clarity)."""
    from exp04_rc4 import rc4
    return rc4(key, plaintext)


def sym_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    from exp04_rc4 import rc4
    return rc4(key, ciphertext)


def generate_key() -> bytes:
    return secrets.token_bytes(16)


# ── Protocol entities ─────────────────────────────────────────────────────────

class KDC:
    """Key Distribution Center — knows all long-term keys."""
    def __init__(self):
        self.keys = {}          # name → key

    def register(self, name: str) -> bytes:
        key = generate_key()
        self.keys[name] = key
        return key

    def issue_ticket(self, alice: str, bob: str) -> bytes:
        """
        NS Step 2: KDC sends to Alice:
          { K_ab, B, { K_ab, A }_Kb }_Ka
        """
        Ka  = self.keys[alice]
        Kb  = self.keys[bob]
        K_ab = generate_key()
        # Ticket for Bob: {K_ab, A}_Kb
        ticket_plaintext = K_ab + alice.encode().ljust(16)
        ticket = sym_encrypt(Kb, ticket_plaintext)
        # Outer: {K_ab, B, ticket}_Ka
        outer_plaintext = K_ab + bob.encode().ljust(16) + ticket
        return sym_encrypt(Ka, outer_plaintext), K_ab


class Principal:
    """Alice or Bob."""
    def __init__(self, name: str, key: bytes):
        self.name = name
        self.key  = key
        self.session_key = None


# ── Needham-Schroeder (original, 1978) ───────────────────────────────────────

def run_ns_protocol(verbose=True):
    kdc = KDC()
    Ka  = kdc.register("Alice")
    Kb  = kdc.register("Bob")
    alice = Principal("Alice", Ka)
    bob   = Principal("Bob",   Kb)

    if verbose:
        print("\n  === Needham-Schroeder Symmetric Protocol ===\n")

    # Step 1: Alice → KDC: (A, B, N_a)
    N_a = secrets.token_bytes(8)
    if verbose:
        print(f"  Step 1 — Alice → KDC: (Alice, Bob, N_a={N_a.hex()})")

    # Step 2: KDC → Alice: {K_ab, B, {K_ab, A}_Kb}_Ka
    encrypted_bundle, K_ab_real = kdc.issue_ticket("Alice", "Bob")
    if verbose:
        print(f"  Step 2 — KDC → Alice: encrypted bundle ({len(encrypted_bundle)} bytes)")

    # Alice decrypts outer layer
    outer = sym_decrypt(Ka, encrypted_bundle)
    K_ab_alice = outer[:16]
    ticket     = outer[32:]          # {K_ab, A}_Kb
    alice.session_key = K_ab_alice
    if verbose:
        print(f"  Alice extracts: K_ab={K_ab_alice.hex()}, ticket for Bob")

    # Step 3: Alice → Bob: { ticket, {N_b}_K_ab } — send ticket + nonce
    N_b = secrets.token_bytes(8)
    msg3 = ticket + sym_encrypt(K_ab_alice, N_b)
    if verbose:
        print(f"  Step 3 — Alice → Bob: ticket + encrypted nonce")

    # Bob decrypts ticket
    ticket_plain = sym_decrypt(Kb, ticket)
    K_ab_bob     = ticket_plain[:16]
    sender       = ticket_plain[16:32].rstrip()
    bob.session_key = K_ab_bob
    if verbose:
        print(f"  Bob decrypts ticket: K_ab={K_ab_bob.hex()}, sender={sender}")

    # Bob decrypts N_b
    N_b_enc      = msg3[len(ticket):]
    N_b_received = sym_decrypt(K_ab_bob, N_b_enc)
    if verbose:
        print(f"  Bob recovers N_b = {N_b_received.hex()}")

    # Step 4: Bob → Alice: {N_b - 1}_K_ab  (nonce challenge-response)
    N_b_minus_1 = (int.from_bytes(N_b_received, 'big') - 1).to_bytes(8, 'big')
    msg4 = sym_encrypt(K_ab_bob, N_b_minus_1)
    if verbose:
        print(f"  Step 4 — Bob → Alice: {{N_b-1}}_K_ab")

    # Alice verifies
    received = sym_decrypt(K_ab_alice, msg4)
    expected = (int.from_bytes(N_b, 'big') - 1).to_bytes(8, 'big')
    auth_ok  = (received == expected)
    if verbose:
        print(f"  Alice verifies N_b-1: {'✓ OK' if auth_ok else '✗ FAILED'}")

    return alice.session_key, bob.session_key, auth_ok


# ── Replay Attack Demonstration ───────────────────────────────────────────────

def demonstrate_replay_attack():
    print("\n  === Replay Attack on Original NS Protocol ===\n")
    print("  Scenario:")
    print("  - Attacker Eve previously captured an old session ticket for Bob.")
    print("  - Old ticket was: {K_old, Alice}_Kb  (with compromised K_old)")
    print("  - Eve replays Step 3 using the OLD ticket.")
    print("  - Bob cannot distinguish fresh vs. replayed ticket → accepts K_old!")
    print()
    print("  Attack steps:")
    print("  1. Eve records old message:  Alice → Bob: {K_old_ticket}")
    print("  2. Later, Eve replays:       Eve  → Bob: {K_old_ticket}  (pretending to be Alice)")
    print("  3. Bob decrypts ticket, gets K_old, sends N_b encrypted with K_old")
    print("  4. Eve (who knows K_old) completes the handshake.")
    print("  5. Bob believes he's talking to Alice, but it's Eve!")
    print()
    print("  Root cause: No freshness guarantee in the ticket.")


# ── Denning-Sacco Fix (timestamps) ───────────────────────────────────────────

def run_ns_with_timestamps(verbose=True):
    print("\n  === Needham-Schroeder with Timestamps (Denning-Sacco 1981 fix) ===\n")
    print("  Fix: KDC adds a timestamp T to the ticket.")
    print("  Ticket: {K_ab, A, T}_Kb")
    print("  Bob checks: |T_now - T| < Δ (small time window, e.g. 5 minutes)")
    print()

    T = time.time()
    MAX_SKEW = 300   # 5 minutes in seconds

    # Simulate fresh ticket
    T_fresh = T - 30    # 30 seconds ago
    T_replay = T - 600  # 10 minutes ago (stale)

    print(f"  Current time       : {T:.0f}")
    print(f"  Fresh ticket time  : {T_fresh:.0f}  → age {T - T_fresh:.0f}s → {'ACCEPT ✓' if abs(T - T_fresh) < MAX_SKEW else 'REJECT ✗'}")
    print(f"  Replay ticket time : {T_replay:.0f} → age {T - T_replay:.0f}s → {'ACCEPT ✓' if abs(T - T_replay) < MAX_SKEW else 'REJECT ✗'}")
    print()
    print("  Result: Replayed old ticket is rejected because timestamp is too old.")
    print("  Requirement: Clocks must be synchronized (e.g. via NTP).")


# ── Demo ──────────────────────────────────────────────────────────────────────

def demo():
    print("=" * 60)
    print("EXPERIMENT 9: Needham-Schroeder Authentication Protocol")
    print("=" * 60)

    alice_key, bob_key, ok = run_ns_protocol(verbose=True)
    assert ok
    assert alice_key == bob_key
    print(f"\n  Session key agreed: {alice_key.hex()}")
    print("  ✓ Mutual authentication complete, shared session key established")

    demonstrate_replay_attack()
    run_ns_with_timestamps()

    print("\n  === Summary: Security Analysis ===")
    print("  Attack             | Original NS | NS+Timestamps")
    print("  -------------------|-------------|---------------")
    print("  Eavesdropping      | Resistant   | Resistant")
    print("  Replay attack      | Vulnerable  | Resistant ✓")
    print("  MITM (with KDC)    | Resistant   | Resistant")
    print("  Clock sync needed  | No          | Yes")


if __name__ == "__main__":
    demo()
