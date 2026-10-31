"""Build .ipynb files for all 12 ISP labs from the existing .py files."""
import json, re, os

LAB_DIR = os.path.dirname(os.path.abspath(__file__))

LABS = [
    ("exp01_classical_ciphers.py",    "Exp 1 – Classical Ciphers (Caesar, Affine, Playfair, Hill)"),
    ("exp02_des.py",                  "Exp 2 – DES (Data Encryption Standard)"),
    ("exp03_aes.py",                  "Exp 3 – AES-128 with Round-wise Analysis"),
    ("exp04_rc4.py",                  "Exp 4 – RC4 Stream Cipher"),
    ("exp05_block_cipher_modes.py",   "Exp 5 – Block Cipher Modes (ECB/CBC/CFB/OFB/CTR)"),
    ("exp06_rsa.py",                  "Exp 6 – RSA Algorithm"),
    ("exp07_dss.py",                  "Exp 7 – Digital Signature Standard (DSS/DSA)"),
    ("exp08_sha512.py",               "Exp 8 – SHA-512 Cryptographic Hash Function"),
    ("exp09_needham_schroeder.py",    "Exp 9 – Needham-Schroeder Authentication Protocol"),
    ("exp10_shamir_secret_sharing.py","Exp 10 – Shamir's Secret Sharing Scheme"),
    ("exp11_paillier.py",             "Exp 11 – Paillier Partially Homomorphic Encryption"),
    ("exp12_attacks_demo.py",         "Exp 12 – Real-World Attacks & Countermeasures"),
]

def nb_cell(cell_type, source, **extra):
    base = {
        "cell_type": cell_type,
        "metadata": {},
        "source": source if isinstance(source, list) else [source],
    }
    if cell_type == "code":
        base.update({"outputs": [], "execution_count": None})
    base.update(extra)
    return base

def split_py_to_cells(src: str, title: str):
    """
    Splits Python source into notebook cells:
    - Module docstring → markdown title cell
    - Top-level section comments (# ══ or # ──) → markdown header cells
    - Everything else → code cells (grouped by blank lines between logical blocks)
    """
    cells = []

    # 1. Title markdown cell
    cells.append(nb_cell("markdown", f"# {title}\n\n---"))

    # 2. Extract module docstring as markdown objective cell
    doc_m = re.match(r'"""(.*?)"""', src, re.DOTALL)
    if doc_m:
        doctext = doc_m.group(1).strip()
        cells.append(nb_cell("markdown", f"**Objective:** {doctext}"))
        src = src[doc_m.end():].lstrip('\n')

    # 3. Split into logical blocks separated by the section divider comments
    # Section header pattern: # ── ... ── or # ══ ... ══
    section_pat = re.compile(r'^# [─═]{2,}.*[─═]{2,}.*$', re.MULTILINE)

    # Split around section headers
    parts = section_pat.split(src)
    headers = section_pat.findall(src)

    # First part (before any section header) goes into one code cell
    first = parts[0].strip()
    if first:
        cells.append(nb_cell("code", first))

    for header, body in zip(headers, parts[1:]):
        # Convert section header comment to markdown
        label = re.sub(r'^#\s*[─═]+\s*', '', header).strip()
        label = re.sub(r'\s*[─═]+\s*$', '', label).strip()
        if label:
            cells.append(nb_cell("markdown", f"## {label}"))
        body = body.strip()
        if body:
            cells.append(nb_cell("code", body))

    # 4. Final "Run demo" cell
    cells.append(nb_cell("markdown", "## Run Demo"))
    cells.append(nb_cell("code", "demo()"))

    return cells

def make_notebook(cells):
    return {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3"
            },
            "language_info": {
                "name": "python",
                "version": "3.x"
            }
        },
        "cells": cells
    }

for py_file, title in LABS:
    py_path = os.path.join(LAB_DIR, py_file)
    nb_path = os.path.join(LAB_DIR, py_file.replace(".py", ".ipynb"))
    with open(py_path, encoding="utf-8") as f:
        src = f.read()
    # Remove the if __name__ == "__main__" block (we add explicit demo() cell)
    src = re.sub(r'\nif __name__ == ["\']__main__["\']:\s*\n\s+demo\(\)\n?', '\n', src)
    cells = split_py_to_cells(src, title)
    nb = make_notebook(cells)
    with open(nb_path, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1, ensure_ascii=False)
    print(f"Created: {os.path.basename(nb_path)}")

print("\nDone — 12 notebooks created.")
