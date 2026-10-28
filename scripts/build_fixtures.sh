#!/usr/bin/env bash
# ============================================================================
# build_fixtures.sh - rebuild every test fixture from the raw CloudTrail logs.
#
#   1. extract_fixtures.py   pulls each rule's should-fire records, plus a
#                            benign set with same-service near-misses
#   2. sanitize_fixtures.py  replaces account IDs, key IDs, IPs and emails,
#                            and refuses to write anything that still leaks
#
# Identifiers no regex can recognize (my SSO session name, my Identity Center
# user ID, instance ID and identity-store ID) are found in the unsanitized
# userIdentity blocks and passed to the sanitizer as --redact values. Other
# session names (filebeat, Stratus, AWS services) are kept: the sanitizer
# replaces --redact values everywhere, so a word like "filebeat" would also be
# rewritten inside role names. Extra values can be listed one per
# line in captures/raw/redact.txt, which is git-ignored.
#
# Usage:  ./scripts/build_fixtures.sh       (run from the repo root)
# ============================================================================
set -euo pipefail

[[ -d captures/raw && -f infra/lab.env ]] || { echo "Run from the repo root." >&2; exit 2; }
# shellcheck source=/dev/null
source infra/lab.env
[[ -n "${LAB_ACCOUNT_ID:-}" ]] || { echo "LAB_ACCOUNT_ID is not set in infra/lab.env" >&2; exit 2; }

rm -rf captures/raw/extracted
python3 scripts/extract_fixtures.py

# Values to redact: every GUID, Identity Center instance ID (ssoins-) and
# identity-store ID (d-) inside userIdentity, plus captures/raw/redact.txt.
# Only userIdentity is searched, so eventID/requestID GUIDs are kept.
mapfile -t REDACT < <(
  { python3 - <<'PY_FIND'
import json, re
from pathlib import Path
pat = re.compile(r"ssoins-[0-9a-f]{16}|\bd-[0-9a-f]{10}\b|"
                 r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
found = set()
for f in Path("captures/raw/extracted").rglob("*.jsonl"):
    for line in f.open(encoding="utf-8"):
        if line.strip():
            found.update(pat.findall(json.dumps(json.loads(line).get("userIdentity") or {})))
print("\n".join(sorted(found)))
PY_FIND
    [[ -f captures/raw/redact.txt ]] && grep -v '^\s*\(#\|$\)' captures/raw/redact.txt
  } | sort -u | awk 'length >= 8 && tolower($0) !~ /detlab/'
)
ARGS=()
for v in "${REDACT[@]}"; do ARGS+=(--redact "$v"); done
echo -e "\nRedacting ${#REDACT[@]} identifier(s) found in the raw records.\n"

python3 scripts/sanitize_fixtures.py --account-id "$LAB_ACCOUNT_ID" "${ARGS[@]}" \
  --map-out captures/raw/fixture_map.json

# The rules' scoping must survive sanitizing, or they won't match their fixtures.
echo -e "\nScope check:"
python3 - <<'PY'
import json, sys
checks = {
    "aws_s3_log_bucket_tampering": ("bucketName", str.startswith, "detlab-cloudtrail-"),
    "aws_sqs_log_queue_tampering": ("queueUrl", str.endswith, "/detlab-cloudtrail-events"),
}
bad = 0
for rule, (field, test, value) in checks.items():
    with open(f"captures/fixtures/{rule}/should_fire.jsonl") as fh:
        for line in fh:
            actual = (json.loads(line).get("requestParameters") or {}).get(field, "")
            if not test(actual, value):
                print(f"  BROKEN {rule}: {field}={actual}"); bad += 1
print("  ok" if not bad else f"  {bad} record(s) no longer match their rule")
sys.exit(1 if bad else 0)
PY
