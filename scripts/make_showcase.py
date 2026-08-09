"""Build the seeded showcase repo 'PayLite' with KNOWN planted problems.
Planted issues (announce honestly as seeded):
  1. README claims MIT; LICENSE is GPL-3.0                 -> license_check REFUTED
  2. poetry.lock transitive deps with real CVEs            -> osv_lookup REFUTED (transitive)
  3. Fake AWS-style key in config/settings.py             -> secret_scan REFUTED
  4. Python eval()+shell=True AND JS eval()+XSS           -> sast_scan REFUTED (bandit + semgrep)
  5. README claims thoroughly tested; a test FAILS         -> run_tests REFUTED
  6. GPL-3.0 dependency declared under (claimed) MIT       -> license_compat REFUTED
  + README claims actively maintained (fresh commits)      -> maintenance_stats VERIFIED
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
- All dependency licenses are compatible with our MIT license
- Actively maintained by the PayLite team
""")
(dest / "LICENSE").write_text(
    "                    GNU GENERAL PUBLIC LICENSE\n"
    "                       Version 3, 29 June 2007\n")
(dest / "requirements.txt").write_text("requests==2.19.0\nflask==0.12.2\ngpl-charting-lib==1.0\n")
(dest / "poetry.lock").write_text("""[[package]]
name = "requests"
version = "2.19.0"

[[package]]
name = "urllib3"
version = "1.24.1"

[[package]]
name = "flask"
version = "0.12.2"

[[package]]
name = "jinja2"
version = "2.10"

[[package]]
name = "werkzeug"
version = "0.14.1"
""")
(dest / ".license-manifest.json").write_text(
    '{"gpl-charting-lib": "GPL-3.0", "requests": "Apache-2.0", "flask": "BSD-3-Clause"}')
(dest / "package.json").write_text(
    '{"name":"paylite","version":"1.0.0","dependencies":{"express":"4.16.0","lodash":"4.17.4"}}')
(dest / "paylite.py").write_text('''import subprocess

def charge(amount, currency="INR"):
    if amount <= 0:
        raise ValueError("amount must be positive")
    return {"status": "charged", "amount": amount, "currency": currency}

def run_hook(user_command):
    return subprocess.run(user_command, shell=True, capture_output=True)  # planted

def parse_rule(rule_text):
    return eval(rule_text)  # planted
''')
(dest / "server.js").write_text('''const express = require('express');
const app = express();

app.get('/run', (req, res) => {
  const result = eval(req.query.expr);        // planted: eval on user input
  res.send(String(result));
});

app.get('/page', (req, res) => {
  res.send('<div>' + req.query.name + '</div>');  // planted: reflected XSS
});

app.listen(3000);
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
    from paylite import refund   # planted: refund doesn't exist -> fails
    assert refund(100)["status"] == "refunded"
''')
subprocess.run(["git", "init", "-q", str(dest)])
env = {**os.environ, "GIT_AUTHOR_NAME": "paylite", "GIT_AUTHOR_EMAIL": "dev@paylite.local",
       "GIT_COMMITTER_NAME": "paylite", "GIT_COMMITTER_EMAIL": "dev@paylite.local"}
for i in range(6):
    (dest / "CHANGELOG.md").write_text(f"release {i}\n")
    subprocess.run(["git", "-C", str(dest), "add", "."], env=env)
    subprocess.run(["git", "-C", str(dest), "commit", "-qm", f"release {i}"], env=env)
print(f"showcase repo at {dest}  (6 planted, transitive deps + JS + license conflict)")
