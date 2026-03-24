#!/usr/bin/env bash
# Package the skill folder into dist/vault-client-usage-analyzer.skill (a zip with the
# skill directory at its root). Runs the tests first so a broken build is never shipped.
set -euo pipefail

cd "$(dirname "$0")"
SKILL=vault-client-usage-analyzer
OUT="dist/$SKILL.skill"

python3 -m unittest discover -s tests -q

mkdir -p dist
rm -f "$OUT"
zip -qr "$OUT" "$SKILL" -x '*.DS_Store' '*__pycache__*' '*.pyc'
unzip -l "$OUT"
