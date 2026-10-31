"""
Execute all .ipynb notebooks by running their code cells in sequence.
Captures stdout/stderr and writes outputs back into each notebook.
No external dependencies — pure stdlib.
"""
import json, sys, os, io, traceback, glob

LAB_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, LAB_DIR)

NOTEBOOKS = sorted(glob.glob(os.path.join(LAB_DIR, "exp*.ipynb")))

def run_notebook(nb_path: str) -> bool:
    with open(nb_path, encoding="utf-8") as f:
        nb = json.load(f)

    name = os.path.basename(nb_path)
    print(f"\n{'='*60}")
    print(f"Running: {name}")
    print('='*60)

    # Shared execution namespace across all cells
    # Seed __file__ and sys.path so cross-module imports work
    import sys as _sys
    _sys.path.insert(0, LAB_DIR)
    ns = {"__file__": nb_path}
    exec_count = 1
    all_ok = True

    for cell in nb["cells"]:
        if cell["cell_type"] != "code":
            continue
        src = "".join(cell["source"]).strip()
        if not src:
            continue

        # Capture stdout + stderr
        old_stdout, old_stderr = sys.stdout, sys.stderr
        buf = io.StringIO()
        sys.stdout = sys.stderr = buf

        error_output = None
        try:
            exec(compile(src, "<cell>", "exec"), ns)
        except Exception:
            error_output = traceback.format_exc()
            all_ok = False
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        captured = buf.getvalue()
        if captured:
            print(captured, end="")
        if error_output:
            print(error_output)

        # Build notebook output objects
        outputs = []
        if captured:
            outputs.append({
                "output_type": "stream",
                "name": "stdout",
                "text": [captured]
            })
        if error_output:
            outputs.append({
                "output_type": "stream",
                "name": "stderr",
                "text": [error_output]
            })

        cell["outputs"] = outputs
        cell["execution_count"] = exec_count
        exec_count += 1

    # Save notebook with outputs
    with open(nb_path, "w", encoding="utf-8") as f:
        json.dump(nb, f, indent=1, ensure_ascii=False)

    status = "✓ PASSED" if all_ok else "✗ FAILED"
    print(f"\n  {status}: {name}")
    return all_ok


results = {}
for nb_path in NOTEBOOKS:
    ok = run_notebook(nb_path)
    results[os.path.basename(nb_path)] = ok

print(f"\n{'='*60}")
print("SUMMARY")
print('='*60)
passed = sum(results.values())
for nb, ok in results.items():
    print(f"  {'✓' if ok else '✗'}  {nb}")
print(f"\n  {passed}/{len(results)} notebooks passed.")

if passed < len(results):
    sys.exit(1)
