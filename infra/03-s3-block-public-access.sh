#!/usr/bin/env bash
# ============================================================================
# 03-s3-block-public-access.sh - turn on S3 Block Public Access for the account.
#
#   All four settings on: block and ignore public ACLs, block public bucket
#   policies, and restrict buckets that already have a public policy.
#
# Why: rule aws_s3_bucket_policy_external_account does not cover "*"
# principals (it cannot tell an Allow "*" from a Deny "*"), so public
# exposure is prevented here instead. Found off on 2026-11-01.
#
# Safe to re-run: changes nothing when all four settings are already on.
#
# Usage:  ./infra/03-s3-block-public-access.sh             apply
#         DRY_RUN=1 ./infra/03-s3-block-public-access.sh   show what would change
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

load_config
require_tools aws grep tr sed mktemp
verify_account

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

WANT="True True True True"
SETTINGS="BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Prints the four settings as "True True True True", or "not set" if the
# account has never had a configuration.
read_settings() {
    local out
    if out="$(aws s3control get-public-access-block --account-id "$ACCOUNT" \
            --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' \
            --output text 2> "$WORK_DIR/err")"; then
        printf '%s\n' "$out" | tr -s '[:space:]' ' ' | sed 's/ $//'
    elif grep -q NoSuchPublicAccessBlockConfiguration "$WORK_DIR/err"; then
        echo "not set"
    else
        mask_ids < "$WORK_DIR/err" >&2
        die "Could not read S3 Block Public Access. Check permissions and connectivity."
    fi
}

# ---------------------------------------------------------------------------
# 1. Compare the current settings with what we want
# ---------------------------------------------------------------------------
log "Checking account-level S3 Block Public Access"
current="$(read_settings)"
if [[ "$current" == "$WANT" ]]; then
    ok "all four settings already on"
    exit 0
fi

# ---------------------------------------------------------------------------
# 2. Turn them on, then confirm
# ---------------------------------------------------------------------------
change "current: $current  ->  want: all four on"
apply aws s3control put-public-access-block --account-id "$ACCOUNT" \
    --public-access-block-configuration "$SETTINGS"

if is_dry_run; then
    exit 0
fi
[[ "$(read_settings)" == "$WANT" ]] || die "Settings did not apply as expected."
ok "all four settings on"