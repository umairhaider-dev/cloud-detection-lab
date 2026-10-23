#!/usr/bin/env bash
# ============================================================================
# 01-cloudtrail.sh - make sure the lab's CloudTrail trail exists and is right.
#
#   Bucket  : private S3 bucket that only this trail may write to
#   Trail   : multi-Region + global service events (needed to see IAM/STS,
#             which AWS records in us-east-1) + log file validation
#   Logging : on
#
# Safe to re-run: it creates what is missing, repairs what has drifted, and
# changes nothing when everything is already correct. Re-runs therefore don't
# create CloudTrail events that would trip our own log-tampering detections.
#
# Usage:  ./infra/01-cloudtrail.sh             apply
#         DRY_RUN=1 ./infra/01-cloudtrail.sh   show what would change
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

load_config
require_tools aws python3 sed
verify_account

# ---------------------------------------------------------------------------
# 1. Find the trail (if it already exists, keep using its bucket)
# ---------------------------------------------------------------------------
log "Looking for trail '$TRAIL_NAME'"
describe_trail

if [[ -n "$TRAIL_BUCKET" ]]; then
    TRAIL_EXISTS=1
    BUCKET="$TRAIL_BUCKET"
    ok "trail exists, writing to bucket $(printf '%s' "$BUCKET" | mask_ids)"
else
    TRAIL_EXISTS=0
    BUCKET="${BUCKET_PREFIX}-${ACCOUNT}-${LAB_REGION}"
    TRAIL_ARN="arn:aws:cloudtrail:${LAB_REGION}:${ACCOUNT}:trail/${TRAIL_NAME}"
    change "trail not found; it will be created with bucket $(printf '%s' "$BUCKET" | mask_ids)"
fi

# ---------------------------------------------------------------------------
# 2. Log bucket
# ---------------------------------------------------------------------------
log "Log bucket"
BUCKET_EXISTS=1
if aws s3api head-bucket --bucket "$BUCKET" > /dev/null 2>&1; then
    ok "bucket exists"
else
    BUCKET_EXISTS=0
    change "creating bucket"
    if [[ "$LAB_REGION" == "us-east-1" ]]; then
        apply aws s3api create-bucket --bucket "$BUCKET" > /dev/null
    else
        apply aws s3api create-bucket --bucket "$BUCKET" \
            --create-bucket-configuration "LocationConstraint=$LAB_REGION" > /dev/null
    fi
fi

# ---------------------------------------------------------------------------
# 3. Bucket policy: only THIS trail may write (aws:SourceArn stops a
#    "confused deputy" where CloudTrail is tricked into writing for someone else)
# ---------------------------------------------------------------------------
log "Bucket policy"
DESIRED_BUCKET_POLICY="$(python3 - "$BUCKET" "$ACCOUNT" "$TRAIL_ARN" <<'PYTHON'
import json, sys
bucket, account, trail_arn = sys.argv[1:4]
policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:GetBucketAcl",
            "Resource": f"arn:aws:s3:::{bucket}",
            "Condition": {"StringEquals": {"aws:SourceArn": trail_arn}},
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/*",
            "Condition": {"StringEquals": {
                "s3:x-amz-acl": "bucket-owner-full-control",
                "aws:SourceArn": trail_arn,
            }},
        },
    ],
}
print(json.dumps(policy, sort_keys=True, separators=(",", ":")))
PYTHON
)"

CURRENT_BUCKET_POLICY=""
if [[ "$BUCKET_EXISTS" == "1" ]]; then
    # No policy at all returns an error, which we treat as "empty".
    CURRENT_BUCKET_POLICY="$(json_canon "$(aws s3api get-bucket-policy --bucket "$BUCKET" \
        --query Policy --output text 2> /dev/null || true)")"
fi

if [[ "$CURRENT_BUCKET_POLICY" == "$DESIRED_BUCKET_POLICY" ]]; then
    ok "policy already correct"
else
    change "applying bucket policy"
    apply aws s3api put-bucket-policy --bucket "$BUCKET" --policy "$DESIRED_BUCKET_POLICY"
fi

# ---------------------------------------------------------------------------
# 4. Trail settings
# ---------------------------------------------------------------------------
log "Trail settings"
if [[ "$TRAIL_EXISTS" == "0" ]]; then
    change "creating trail (multi-Region, global service events, log file validation)"
    apply aws cloudtrail create-trail --name "$TRAIL_NAME" --s3-bucket-name "$BUCKET" \
        --is-multi-region-trail --include-global-service-events \
        --enable-log-file-validation > /dev/null
else
    read -r MULTI GLOBAL VALIDATION <<< "$(aws cloudtrail describe-trails \
        --trail-name-list "$TRAIL_NAME" \
        --query 'trailList[0].[IsMultiRegionTrail,IncludeGlobalServiceEvents,LogFileValidationEnabled]' \
        --output text)"

    if [[ "$MULTI" == "True" && "$GLOBAL" == "True" && "$VALIDATION" == "True" ]]; then
        ok "multi-Region, global service events and log file validation all on"
    else
        warn "trail settings drifted: multi-Region=$MULTI global-events=$GLOBAL validation=$VALIDATION"
        change "restoring trail settings"
        apply aws cloudtrail update-trail --name "$TRAIL_NAME" \
            --is-multi-region-trail --include-global-service-events \
            --enable-log-file-validation > /dev/null
    fi
fi

# ---------------------------------------------------------------------------
# 5. Logging on
# ---------------------------------------------------------------------------
log "Logging status"
if [[ "$TRAIL_EXISTS" == "0" ]] && is_dry_run; then
    change "would start logging on the new trail"
else
    IS_LOGGING="$(aws cloudtrail get-trail-status --name "$TRAIL_NAME" \
        --query IsLogging --output text 2> /dev/null || echo "False")"
    if [[ "$IS_LOGGING" == "True" ]]; then
        ok "logging is on"
    else
        # If you didn't stop it yourself, treat this as a possible incident.
        [[ "$TRAIL_EXISTS" == "1" ]] && warn "logging was OFF on an existing trail. Investigate who stopped it."
        change "starting logging"
        apply aws cloudtrail start-logging --name "$TRAIL_NAME"
    fi

    DELIVERY_ERROR="$(aws cloudtrail get-trail-status --name "$TRAIL_NAME" \
        --query LatestDeliveryError --output text 2> /dev/null || true)"
    if [[ -n "$DELIVERY_ERROR" && "$DELIVERY_ERROR" != "None" ]]; then
        warn "CloudTrail reports a delivery error: $DELIVERY_ERROR"
    fi
fi

log "Done. Trail '$TRAIL_NAME' -> bucket $(printf '%s' "$BUCKET" | mask_ids)"
