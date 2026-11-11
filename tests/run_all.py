# -*- coding: utf-8 -*-
"""Run every test suite in this directory (standalone scripts, fail-closed:
non-zero exit = failure) and write logs/run_all.json with per-suite status.

Usage: python tests/run_all.py [suite ...]     (no args = all 18 suites)
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SUITES = sorted(f for f in os.listdir(HERE)
                if f.startswith("test_") and f.endswith(".py"))


def main():
    sel = [a if a.endswith(".py") else a + ".py" for a in sys.argv[1:]] \
        or SUITES
    results, fails = {}, 0
    t0 = time.time()
    for name in sel:
        print(f"== {name} ", flush=True)
        t1 = time.time()
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        p = subprocess.run([sys.executable, "-I", os.path.join(HERE, name)],
                           capture_output=True, text=True,
                           encoding="utf-8", errors="replace", cwd=ROOT,
                           env=env)
        ok = p.returncode == 0
        fails += not ok
        tail = (p.stdout or "").strip().splitlines()[-1:] or ["<no output>"]
        results[name] = {"pass": ok, "exit": p.returncode,
                         "elapsed_s": round(time.time() - t1, 1),
                         "last_line": tail[0]}
        print(f"   [{'PASS' if ok else 'FAIL'}] {tail[0]} "
              f"({results[name]['elapsed_s']}s)", flush=True)
        if not ok:
            print((p.stderr or p.stdout or "")[-2000:], flush=True)
    summary = {"suites": len(results), "passed": len(results) - fails,
               "failed": fails, "elapsed_s": round(time.time() - t0, 1),
               "results": results}
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)
    with open(os.path.join(ROOT, "logs", "run_all.json"), "w",
              encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    print(f"\n=== run_all: {summary['passed']}/{summary['suites']} suites PASS "
          f"in {summary['elapsed_s']}s ===")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
