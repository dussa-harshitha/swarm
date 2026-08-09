"""Cross-platform sample target repo (Windows-friendly replacement for make_fixture.sh).
Usage: py scripts/make_fixture.py   (or python3 scripts/make_fixture.py)"""
import pathlib, shutil, sys

dest = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/swarm_sample_repo")
if dest.exists():
    shutil.rmtree(dest)
(dest / "tests").mkdir(parents=True)
(dest / "README.md").write_text(
    "# SampleLib\nA tiny utility library. **MIT licensed.** Fully tested. No known vulnerabilities.\n")
(dest / "LICENSE").write_text(
    "                                 Apache License\n"
    "                           Version 2.0, January 2004\n")
(dest / "samplelib.py").write_text("def add(a, b):\n    return a + b\n")
(dest / "tests" / "test_add.py").write_text(
    "import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))\n"
    "from samplelib import add\n\ndef test_add():\n    assert add(2, 3) == 5\n")
(dest / "requirements.txt").write_text("requests==2.19.0\n")
print(f"fixture at {dest}")
