"""
Experiment 12: Real-World Attacks — Simulation & Countermeasures
Covers: ARP Spoofing, DNS Poisoning, SQL Injection.
Uses only stdlib (no scapy/nmap). Pure simulation with educational output.
"""

import hashlib
import re
import sqlite3
import os
import tempfile


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 1: ARP SPOOFING
# ══════════════════════════════════════════════════════════════════════════════

class ARPCache:
    """Simulates a host's ARP cache."""
    def __init__(self, name: str):
        self.name  = name
        self.cache = {}   # IP → MAC

    def update(self, ip: str, mac: str, source: str = ""):
        old = self.cache.get(ip)
        self.cache[ip] = mac
        tag = f" (was {old})" if old and old != mac else ""
        print(f"  [{self.name}] ARP cache: {ip} → {mac}{tag}  ← {source}")

    def get(self, ip: str):
        return self.cache.get(ip, None)


def simulate_arp_spoofing():
    print("=" * 60)
    print("ATTACK 1: ARP Spoofing (MITM via Gratuitous ARP)")
    print("=" * 60)

    # Network setup
    gateway_ip  = "192.168.1.1"
    gateway_mac = "AA:BB:CC:DD:EE:FF"
    victim_ip   = "192.168.1.100"
    victim_mac  = "11:22:33:44:55:66"
    attacker_ip = "192.168.1.200"
    attacker_mac= "DE:AD:BE:EF:00:01"

    print(f"\n  Network layout:")
    print(f"    Gateway  : {gateway_ip} ({gateway_mac})")
    print(f"    Victim   : {victim_ip}  ({victim_mac})")
    print(f"    Attacker : {attacker_ip} ({attacker_mac})")

    victim_cache  = ARPCache("Victim")
    gateway_cache = ARPCache("Gateway")

    print("\n  --- Phase 1: Legitimate ARP Replies ---")
    victim_cache.update(gateway_ip,  gateway_mac, "real gateway")
    gateway_cache.update(victim_ip,  victim_mac,  "real victim")

    print("\n  --- Phase 2: Attacker Sends Gratuitous ARP (Poisoning) ---")
    # Attacker tells victim: gateway IP → attacker's MAC
    victim_cache.update(gateway_ip,  attacker_mac, "ATTACKER (spoofed!)")
    # Attacker tells gateway: victim IP → attacker's MAC
    gateway_cache.update(victim_ip,  attacker_mac, "ATTACKER (spoofed!)")

    print("\n  --- Phase 3: Traffic Now Flows Through Attacker (MITM) ---")
    print(f"  Victim sends packet to '{gateway_ip}' → resolves to {victim_cache.get(gateway_ip)} (ATTACKER!)")
    print(f"  Gateway sends packet to '{victim_ip}'  → resolves to {gateway_cache.get(victim_ip)} (ATTACKER!)")
    print("  Attacker intercepts, reads, and forwards traffic → Man-in-the-Middle!")

    print("\n  --- Countermeasures ---")
    countermeasures = [
        ("Static ARP entries",         "Configure permanent IP→MAC bindings for critical hosts."),
        ("Dynamic ARP Inspection (DAI)","Switch validates ARP packets against DHCP snooping table."),
        ("ARP watch / detection",       "Tools like arpwatch alert on IP→MAC changes."),
        ("VLAN segmentation",           "Limit ARP broadcast domain size."),
        ("Encrypted traffic (TLS/VPN)", "Even if intercepted, ciphertext is unreadable."),
    ]
    for cm, desc in countermeasures:
        print(f"  ✓ {cm}: {desc}")


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 2: DNS CACHE POISONING
# ══════════════════════════════════════════════════════════════════════════════

class DNSResolver:
    """Simulates a recursive DNS resolver with a cache."""
    def __init__(self, name: str, dnssec: bool = False):
        self.name   = name
        self.cache  = {}
        self.dnssec = dnssec

    def query(self, domain: str) -> str:
        if domain in self.cache:
            ip, valid_sig = self.cache[domain]
            if self.dnssec and not valid_sig:
                print(f"  [{self.name}] DNSSEC validation FAILED for {domain} → BLOCKED")
                return None
            return ip
        return None

    def cache_response(self, domain: str, ip: str, valid_sig: bool = True):
        self.cache[domain] = (ip, valid_sig)
        sig_tag = " [DNSSEC✓]" if valid_sig else " [NO SIG ⚠]"
        print(f"  [{self.name}] Cached: {domain} → {ip}{sig_tag}")


def simulate_dns_poisoning():
    print("\n" + "=" * 60)
    print("ATTACK 2: DNS Cache Poisoning (Kaminsky Attack variant)")
    print("=" * 60)

    legitimate_ip = "93.184.216.34"    # example.com real IP
    attacker_ip   = "10.0.0.99"        # attacker-controlled server
    domain        = "bank.example.com"

    print(f"\n  Target domain  : {domain}")
    print(f"  Legitimate IP  : {legitimate_ip}")
    print(f"  Attacker's IP  : {attacker_ip}")

    # Vulnerable resolver (no DNSSEC)
    print("\n  --- Scenario A: Vulnerable Resolver (no DNSSEC) ---")
    resolver = DNSResolver("Resolver-A", dnssec=False)
    print(f"  Client queries {domain}...")
    print(f"  Resolver-A sends query to authoritative NS (UDP, random src port)")
    print(f"  Attacker flood-sends forged responses with guessed Transaction ID")
    # Attacker wins the race (simulated)
    resolver.cache_response(domain, attacker_ip, valid_sig=False)
    resolved = resolver.query(domain)
    print(f"  Client resolves {domain} → {resolved}  (ATTACKER's server!)")
    print("  ⚠ Victim connects to fake bank site — phishing / credential theft!")

    # DNSSEC-protected resolver
    print("\n  --- Scenario B: Protected Resolver (DNSSEC enabled) ---")
    resolver2 = DNSResolver("Resolver-B", dnssec=True)
    resolver2.cache_response(domain, attacker_ip, valid_sig=False)   # attacker's response
    resolved2 = resolver2.query(domain)
    print(f"  Result: {resolved2}  (None = blocked by DNSSEC)")

    # Legitimate response
    resolver2.cache_response(domain, legitimate_ip, valid_sig=True)
    resolved3 = resolver2.query(domain)
    print(f"  Legitimate signed response → {resolved3}  ✓")

    print("\n  --- Countermeasures ---")
    cms = [
        ("DNSSEC", "Cryptographically sign DNS records; resolvers verify signatures."),
        ("Source port randomization", "Increases Transaction ID brute-force difficulty from 2^16 to ~2^32."),
        ("DNS-over-HTTPS (DoH)", "Encrypts DNS queries, prevents on-path injection."),
        ("DNS-over-TLS (DoT)",  "Encrypts at transport layer (port 853)."),
        ("Short TTL + monitoring", "Limits cache poisoning window; detect anomalies."),
        ("0x20 encoding",       "Mix case in query; authoritative must preserve case (validates origin)."),
    ]
    for cm, desc in cms:
        print(f"  ✓ {cm}: {desc}")


# ══════════════════════════════════════════════════════════════════════════════
#  ATTACK 3: SQL INJECTION
# ══════════════════════════════════════════════════════════════════════════════

def setup_demo_db(db_path: str):
    """Create a small demo database."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("""
        CREATE TABLE secret_data (
            id INTEGER PRIMARY KEY,
            data TEXT
        )
    """)
    users = [
        ("alice",   hashlib.sha256(b"alice123").hexdigest(),   "admin"),
        ("bob",     hashlib.sha256(b"bobpass").hexdigest(),    "user"),
        ("charlie", hashlib.sha256(b"ch4rlie!").hexdigest(),   "user"),
    ]
    conn.executemany("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", users)
    conn.execute("INSERT INTO secret_data (data) VALUES (?)", ("TOP SECRET: salary=$200000",))
    conn.commit()
    conn.close()


# ── Vulnerable login (string concatenation) ───────────────────────────────────

def vulnerable_login(db_path: str, username: str, password: str) -> str:
    """VULNERABLE: builds query with string concatenation."""
    conn   = sqlite3.connect(db_path)
    query  = f"SELECT * FROM users WHERE username='{username}' AND password_hash='{password}'"
    # Attacker can see the query in error messages or guess it
    try:
        rows = conn.execute(query).fetchall()
    except sqlite3.OperationalError as e:
        conn.close()
        return f"DB ERROR: {e}"
    conn.close()
    return f"LOGIN OK — {rows}" if rows else "Login failed"


# ── Safe login (parameterised query) ─────────────────────────────────────────

def safe_login(db_path: str, username: str, password: str) -> str:
    """SAFE: uses parameterised queries — input never interpolated into SQL."""
    conn  = sqlite3.connect(db_path)
    ph    = hashlib.sha256(password.encode()).hexdigest()
    rows  = conn.execute(
        "SELECT id, username, role FROM users WHERE username=? AND password_hash=?",
        (username, ph)
    ).fetchall()
    conn.close()
    return f"LOGIN OK — {rows}" if rows else "Login failed"


def simulate_sql_injection():
    print("\n" + "=" * 60)
    print("ATTACK 3: SQL Injection")
    print("=" * 60)

    db_path = tempfile.mktemp(suffix=".db")
    setup_demo_db(db_path)

    print("\n  Database has users: alice (admin), bob (user), charlie (user)")
    print("  Vulnerable login: 'SELECT * FROM users WHERE username=\\'<input>\\' AND ...'")

    # Normal login
    print("\n  --- Normal Login ---")
    res = vulnerable_login(db_path, "alice", hashlib.sha256(b"alice123").hexdigest())
    print(f"  username=alice, correct_hash → {res}")

    # Auth bypass via tautology
    print("\n  --- Attack 1: Auth Bypass (Tautology) ---")
    sqli_user = "' OR '1'='1"
    sqli_pass = "anything"
    print(f"  username='{sqli_user}' → injected SQL:")
    print(f"  SELECT * FROM users WHERE username='' OR '1'='1' AND password_hash='anything'")
    res2 = vulnerable_login(db_path, sqli_user, sqli_pass)
    print(f"  Result: {res2}")
    if "alice" in res2 or "bob" in res2:
        print("  ⚠ BYPASSED AUTH — attacker logged in without valid credentials!")

    # Extract extra data via UNION
    print("\n  --- Attack 2: UNION-based Data Exfiltration ---")
    sqli_union = "' UNION SELECT id, data, 'x', 'x' FROM secret_data--"
    res3 = vulnerable_login(db_path, sqli_union, "irrelevant")
    print(f"  username='{sqli_union}'")
    print(f"  Result: {res3}")
    if "TOP SECRET" in res3:
        print("  ⚠ EXFILTRATED secret_data table content!")

    # Drop table attempt (SQLite read-only via fetchall - won't cascade, but shows intent)
    print("\n  --- Attack 3: Comment Bypass ---")
    sqli_comment = "alice'--"
    res4 = vulnerable_login(db_path, sqli_comment, "anything")
    print(f"  username=\"alice'--\" → comment strips password check")
    print(f"  Result: {res4}")
    if "alice" in res4:
        print("  ⚠ Logged in as alice without knowing her password!")

    # Safe parameterised versions
    print("\n  --- Safe Version (Parameterised Queries) ---")
    attacks = [
        ("' OR '1'='1", "anything"),
        ("alice'--",     "anything"),
    ]
    for u, p in attacks:
        res_safe = safe_login(db_path, u, p)
        print(f"  username='{u}' → {res_safe}")
    # Legitimate login
    safe_ok = safe_login(db_path, "alice", "alice123")
    print(f"  alice / alice123 → {safe_ok}")

    print("\n  --- Countermeasures ---")
    cms = [
        ("Parameterised queries / Prepared statements",
         "Input never concatenated into SQL — driver handles escaping."),
        ("ORM (SQLAlchemy, Django ORM)",
         "Higher-level abstraction; queries always parameterised."),
        ("Stored procedures",
         "Logic lives in DB; user input is data, never SQL structure."),
        ("Input validation / allow-listing",
         "Reject unexpected characters; validate data types."),
        ("Principle of least privilege",
         "DB user has only SELECT/INSERT on needed tables; no DROP/CREATE."),
        ("WAF (Web Application Firewall)",
         "Detect and block known SQL injection patterns at network level."),
        ("Error handling",
         "Never expose DB error messages to users — they reveal schema."),
    ]
    for cm, desc in cms:
        print(f"  ✓ {cm}: {desc}")

    os.unlink(db_path)


# ── Demo ──────────────────────────────────────────════════════════════════════

def demo():
    simulate_arp_spoofing()
    simulate_dns_poisoning()
    simulate_sql_injection()

    print("\n" + "=" * 60)
    print("SUMMARY: Attack Categories & Defences")
    print("=" * 60)
    rows = [
        ("ARP Spoofing",    "Layer 2 / LAN",   "MITM, sniff traffic",     "DAI, Static ARP, VPN/TLS"),
        ("DNS Poisoning",   "DNS (UDP/53)",     "Redirect to fake servers","DNSSEC, DoH, DoT"),
        ("SQL Injection",   "Application (DB)", "Auth bypass, data theft", "Parameterised queries, PoLP"),
    ]
    print(f"\n  {'Attack':<18} {'Layer':<18} {'Impact':<27} Countermeasure")
    print(f"  {'-'*18} {'-'*18} {'-'*27} {'-'*30}")
    for a, l, i, c in rows:
        print(f"  {a:<18} {l:<18} {i:<27} {c}")


if __name__ == "__main__":
    demo()
