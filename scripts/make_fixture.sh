#!/bin/bash
# Sample target repo: claims MIT but ships Apache license (refutation demo), tests pass.
set -e
DEST=${1:-/tmp/swarm_sample_repo}
rm -rf "$DEST" && mkdir -p "$DEST/tests"
cat > "$DEST/README.md" << 'R'
# SampleLib
A tiny utility library. **MIT licensed.** Fully tested. No known vulnerabilities.
R
cat > "$DEST/LICENSE" << 'R'
                                 Apache License
                           Version 2.0, January 2004
R
cat > "$DEST/samplelib.py" << 'R'
def add(a, b):
    return a + b
R
cat > "$DEST/tests/test_add.py" << 'R'
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
from samplelib import add
def test_add():
    assert add(2, 3) == 5
R
cat > "$DEST/requirements.txt" << 'R'
requests==2.19.0
R
echo "fixture at $DEST"
