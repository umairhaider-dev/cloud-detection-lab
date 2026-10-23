#!/usr/bin/env bash
# lib.sh - shared helpers for the infra/ scripts.
# This file is sourced by the other scripts; it is not run on its own.

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------- output helpers ----------------------------------------------------
log()    { printf '\n==> %s\n' "$*"; }
ok()     { printf '    ok      %s\n' "$*"; }
change() { printf '    CHANGE  %s\n' "$*"; }
warn()   { printf 'WARNING: %s\n' "$*" >&2; }
die()    { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# Masks the middle of any 12-digit number (AWS account IDs) in its input.
mask_ids() { sed -E 's/([0-9]{4})[0-9]{4}([0-9]{4})/\1****\2/g'; }

# ---------- dry-run support ---------------------------------------------------
# DRY_RUN=1 ./infra/01-cloudtrail.sh   -> reports what it would change, changes nothing.
is_dry_run() { [[ "${DRY_RUN:-0}" == "1" ]]; }

# Runs a command that changes AWS, or only describes it in dry-run mode.
apply() {
    if is_dry_run; then
        printf '    [dry-run] would run: %s\n' "$*" | mask_ids >&2
        return 0
    fi
    "$@"
}

# ---------- configuration -----------------------------------------------------
# Settings come from infra/lab.env (git-ignored), so no account ID is committed.
load_config() {
    local env_file="$LIB_DIR/lab.env"
    if [[ -f "$env_file" ]]; then
        # shellcheck source=/dev/null
        source "$env_file"
    fi

    : "${LAB_ACCOUNT_ID:?Set LAB_ACCOUNT_ID in infra/lab.env (copy infra/lab.env.example)}"
    [[ "$LAB_ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || die "LAB_ACCOUNT_ID must be exactly 12 digits."

    LAB_REGION="${LAB_REGION:-ap-southeast-2}"
    TRAIL_NAME="${TRAIL_NAME:-detlab-trail}"
    QUEUE_NAME="${QUEUE_NAME:-detlab-cloudtrail-events}"
    BUCKET_PREFIX="${BUCKET_PREFIX:-detlab-cloudtrail}"
    QUEUE_RETENTION_SECONDS="${QUEUE_RETENTION_SECONDS:-1209600}"   # 14 days
    NOTIFICATION_ID="${NOTIFICATION_ID:-cloudtrail-new-log-file}"

    # Every aws call in these scripts uses the lab Region.
    export AWS_REGION="$LAB_REGION" AWS_DEFAULT_REGION="$LAB_REGION" AWS_PAGER=""
}

require_tools() {
    local tool
    for tool in "$@"; do
        command -v "$tool" > /dev/null || die "Required tool not found: $tool"
    done
}

# ---------- safety check ------------------------------------------------------
# Refuses to continue unless the credentials belong to the lab account.
# Sets ACCOUNT on success.
verify_account() {
    local identity account arn
    log "Checking AWS identity"
    identity="$(aws sts get-caller-identity --query '[Account,Arn]' --output text)" \
        || die "Could not reach AWS. If your session expired, run: aws login --remote --profile lab-login"
    read -r account arn <<< "$identity"

    printf '    caller  %s\n' "$arn" | mask_ids
    if [[ "$account" != "$LAB_ACCOUNT_ID" ]]; then
        die "Wrong AWS account ($(printf '%s' "$account" | mask_ids)). No changes were made."
    fi
    # shellcheck disable=SC2034  # used by the scripts that source this file
    ACCOUNT="$account"
    ok "lab account verified"
    if is_dry_run; then
        printf '    DRY RUN: nothing will be changed\n'
    fi
}

# ---------- CloudTrail discovery ----------------------------------------------
# Sets TRAIL_BUCKET and TRAIL_ARN; both are empty if the trail does not exist.
# shellcheck disable=SC2034  # TRAIL_ARN is used by the scripts that source this file
describe_trail() {
    local out
    out="$(aws cloudtrail describe-trails --trail-name-list "$TRAIL_NAME" \
            --query 'trailList[0].[S3BucketName,TrailARN]' --output text)" \
        || die "Could not query CloudTrail. Check permissions and connectivity."
    read -r TRAIL_BUCKET TRAIL_ARN <<< "$out"
    if [[ -z "${TRAIL_BUCKET:-}" || "$TRAIL_BUCKET" == "None" ]]; then
        TRAIL_BUCKET=""
        TRAIL_ARN=""
    fi
}

# ---------- JSON helper -------------------------------------------------------
# Prints JSON in a canonical form (sorted keys, no whitespace) so two policies
# can be compared as strings. Prints nothing for empty input or "None".
json_canon() {
    python3 -c '
import json, sys
raw = sys.argv[1]
if raw and raw != "None":
    print(json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":")))
' "$1"
}
