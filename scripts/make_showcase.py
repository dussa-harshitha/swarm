"""Build the seeded showcase repo: KNOWN planted problems, used for the
guided-tour demo and as eval ground truth ("6 planted, 6 caught").
Planted (announce honestly as seeded):
  1. README claims MIT; LICENSE is GPL-3.0            -> license_check REFUTED
  2. requests==2.19.0 + flask==0.12.2 pinned          -> osv_lookup REFUTED (real CVEs)
  3. Fake AWS-style key in config/settings.py         -> secret_scan REFUTED
  4. eval() + shell=True subprocess                   -> sast_scan REFUTED
  5. README claims thoroughly tested; 1 test FAILS    -> run_tests REFUTED
  6. README claims actively maintained (fresh commits)-> maintenance_stats VERIFIED
Usage: py scripts/make_showcase.py [dest]
"""
import os, pathlib, shutil, subprocess, sys

dest = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/paylite")
if dest.exists():
    shutil.rmtree(dest)
(dest / "tests").mkdir(parents=True)
(dest / "config").mkdir()

(dest / "README.md").write_text("""# PayLite
A lightweight payment-processing helper library. Production-ready and secure.

- **MIT licensed** - free for commercial use
- Thoroughly tested with full coverage
- No known vulnerabilities in our dependency chain
- Actively maintained by the PayLite team
""")
(dest / "LICENSE").write_text(
    "                    GNU GENERAL PUBLIC LICENSE\n"
    "                       Version 3, 29 June 2007\n")
(dest / "requirements.txt").write_text("requests==2.19.0\nflask==0.12.2\n")
(dest / "paylite.py").write_text('''import subprocess

def charge(amount, currency="INR"):
    if amount <= 0:
        raise ValueError("amount must be positive")
    return {"status": "charged", "amount": amount, "currency": currency}

def run_hook(user_command):
    # planted: command injection pattern for bandit
    return subprocess.run(user_command, shell=True, capture_output=True)

def parse_rule(rule_text):
    # planted: eval on external input for bandit
    return eval(rule_text)
''')
(dest / "config" / "settings.py").write_text(
    '# planted fake credential for gitleaks (random, not a real key)\n'
    'AWS_ACCESS_KEY_ID = "AKIAQ3XRT7LM9PB2WKD4"\n'
    'AWS_SECRET_ACCESS_KEY = "tGb9pXq2LrN8vZsWyHc4dJmA6kQeRf3TuVn5xB7P"\n')
(dest / "tests" / "test_paylite.py").write_text('''import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from paylite import charge

def test_charge_ok():
    assert charge(100)["status"] == "charged"

def test_refund_supported():
    # planted failing test: README says thoroughly tested; this fails
    from paylite import refund
    assert refund(100)["status"] == "refunded"
''')
subprocess.run(["git", "init", "-q", str(dest)])
env = {**os.environ, "GIT_AUTHOR_NAME": "paylite", "GIT_AUTHOR_EMAIL": "dev@paylite.local",
       "GIT_COMMITTER_NAME": "paylite", "GIT_COMMITTER_EMAIL": "dev@paylite.local"}
for i in range(6):
    (dest / "CHANGELOG.md").write_text(f"release {i}\n")
    subprocess.run(["git", "-C", str(dest), "add", "."], env=env)
    subprocess.run(["git", "-C", str(dest), "commit", "-qm", f"release {i}"], env=env)
print(f"showcase repo at {dest}  (6 planted issues)")
