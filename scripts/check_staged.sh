#!/usr/bin/env bash
# Refuse to commit capture data, key material or environment files.
#
# This is a safety net, not the primary control -- .gitignore is. It exists
# because a single `git add -f` or a renamed capture is enough to publish
# somebody's mail traffic. See SECURITY.md.
set -euo pipefail

staged="$(git diff --cached --name-only --diff-filter=ACMR)"
if [[ -z "$staged" ]]; then
  echo "check_staged: nothing staged."
  exit 0
fi

fail=0
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  case "$path" in
    *.pcap|*.pcapng|*.cap|*.erf|*.snoop)
      echo "REFUSED: capture file staged: $path"; fail=1 ;;
    *.pem|*.key|*.p12|*.pfx|*.jks|*.keystore)
      echo "REFUSED: key material staged: $path"; fail=1 ;;
    .env|.env.*)
      [[ "$path" == ".env.example" ]] || { echo "REFUSED: environment file staged: $path"; fail=1; } ;;
    *sslkeylog*|*keylog*)
      echo "REFUSED: TLS key log staged: $path"; fail=1 ;;
    tests/fixtures/generated/*)
      echo "REFUSED: generated fixture staged: $path"; fail=1 ;;
  esac
done <<< "$staged"

if [[ "$fail" -ne 0 ]]; then
  echo
  echo "Unstage these files. Captures and secrets must never enter git history."
  exit 1
fi
echo "check_staged: no capture data, key material or environment files staged."
