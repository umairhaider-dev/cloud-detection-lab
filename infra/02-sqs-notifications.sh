#!/usr/bin/env bash
# ============================================================================
# 02-sqs-notifications.sh - connect the CloudTrail bucket to an SQS queue.
#
#   Queue        : holds "new log file" messages for Filebeat (14-day retention,
#                  so a stopped SIEM can catch up instead of losing logs)
#   Queue policy : only our bucket, in our account, may send to it
#   Notification : the bucket announces new CloudTrail log files only
#                  (the prefix filter skips CloudTrail-Digest/ files)
#
# Safe to re-run: it creates what is missing, repairs what has drifted, and
# changes nothing when everything is already correct.
#
# Usage:  ./infra/02-sqs-notifications.sh             apply
#         DRY_RUN=1 ./infra/02-sqs-notifications.sh   show what would change
# Run 01-cloudtrail.sh first.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

load_config
require_tools aws python3 sed mktemp
verify_account

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# ---------------------------------------------------------------------------
# 1. Find the trail's bucket
# ---------------------------------------------------------------------------
log "Looking for trail '$TRAIL_NAME'"
describe_trail
[[ -n "$TRAIL_BUCKET" ]] || die "Trail '$TRAIL_NAME' not found. Run infra/01-cloudtrail.sh first."
BUCKET="$TRAIL_BUCKET"
ok "bucket $(printf '%s' "$BUCKET" | mask_ids)"

# ---------------------------------------------------------------------------
# 2. Queue
# ---------------------------------------------------------------------------
log "Queue '$QUEUE_NAME'"
QUEUE_URL="$(aws sqs get-queue-url --queue-name "$QUEUE_NAME" \
    --query QueueUrl --output text 2> /dev/null || true)"

if [[ -z "$QUEUE_URL" || "$QUEUE_URL" == "None" ]]; then
    change "creating queue"
    if is_dry_run; then
        log "Dry run stops here: the remaining steps need the queue to exist."
        exit 0
    fi
    QUEUE_URL="$(aws sqs create-queue --queue-name "$QUEUE_NAME" \
        --attributes "MessageRetentionPeriod=$QUEUE_RETENTION_SECONDS" \
        --query QueueUrl --output text)"
else
    ok "queue exists"
fi

QUEUE_ARN="$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" \
    --attribute-names QueueArn --query Attributes.QueueArn --output text)"
[[ -n "$QUEUE_ARN" && "$QUEUE_ARN" != "None" ]] || die "Could not read the queue ARN."

# ---------------------------------------------------------------------------
# 3. Retention (a shortened retention would silently drop logs)
# ---------------------------------------------------------------------------
log "Message retention"
RETENTION="$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" \
    --attribute-names MessageRetentionPeriod \
    --query Attributes.MessageRetentionPeriod --output text)"

if [[ "$RETENTION" == "$QUEUE_RETENTION_SECONDS" ]]; then
    ok "retention is $RETENTION seconds"
else
    warn "retention drifted: $RETENTION seconds (expected $QUEUE_RETENTION_SECONDS)"
    change "restoring retention"
    apply aws sqs set-queue-attributes --queue-url "$QUEUE_URL" \
        --attributes "MessageRetentionPeriod=$QUEUE_RETENTION_SECONDS"
fi

# ---------------------------------------------------------------------------
# 4. Queue policy: only our bucket, in our account, may send messages
# ---------------------------------------------------------------------------
log "Queue policy"
DESIRED_QUEUE_POLICY="$(python3 - "$QUEUE_ARN" "$BUCKET" "$ACCOUNT" <<'PYTHON'
import json, sys
queue_arn, bucket, account = sys.argv[1:4]
policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "AllowS3FromDetlabBucket",
        "Effect": "Allow",
        "Principal": {"Service": "s3.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue_arn,
        "Condition": {
            "ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"},
            "StringEquals": {"aws:SourceAccount": account},
        },
    }],
}
print(json.dumps(policy, sort_keys=True, separators=(",", ":")))
PYTHON
)"

CURRENT_QUEUE_POLICY="$(json_canon "$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" \
    --attribute-names Policy --query Attributes.Policy --output text)")"

if [[ "$CURRENT_QUEUE_POLICY" == "$DESIRED_QUEUE_POLICY" ]]; then
    ok "policy already correct"
else
    change "applying queue policy"
    # SQS wants the policy as a JSON *string* inside the Policy attribute.
    python3 -c 'import json, sys; print(json.dumps({"Policy": sys.argv[1]}))' \
        "$DESIRED_QUEUE_POLICY" > "$WORK_DIR/queue-attrs.json"
    apply aws sqs set-queue-attributes --queue-url "$QUEUE_URL" \
        --attributes "file://$WORK_DIR/queue-attrs.json"
fi

# ---------------------------------------------------------------------------
# 5. Bucket notification: new CloudTrail log files -> queue
#    put-bucket-notification-configuration REPLACES the whole configuration,
#    so we merge: keep any other notifications, replace only ours.
# ---------------------------------------------------------------------------
log "Bucket notification"
aws s3api get-bucket-notification-configuration --bucket "$BUCKET" \
    --output json > "$WORK_DIR/current-notif.json"

NOTIF_STATE="$(python3 - "$WORK_DIR/current-notif.json" "$WORK_DIR/desired-notif.json" \
    "$QUEUE_ARN" "$ACCOUNT" "$NOTIFICATION_ID" <<'PYTHON'
import json, sys
current_path, desired_path, queue_arn, account, notif_id = sys.argv[1:6]

with open(current_path, encoding="utf-8") as f:
    raw = f.read().strip()
current = json.loads(raw) if raw else {}
current.pop("ResponseMetadata", None)

ours = {
    "Id": notif_id,
    "QueueArn": queue_arn,
    "Events": ["s3:ObjectCreated:*"],
    "Filter": {"Key": {"FilterRules": [
        {"Name": "Prefix", "Value": f"AWSLogs/{account}/CloudTrail/"},
    ]}},
}

def canon(cfg):
    # AWS may return keys like "Prefix" vs "prefix"; compare case-insensitively.
    rules = cfg.get("Filter", {}).get("Key", {}).get("FilterRules", [])
    return (
        cfg.get("QueueArn"),
        tuple(sorted(cfg.get("Events", []))),
        tuple(sorted((r["Name"].lower(), r["Value"]) for r in rules)),
    )

queues = current.get("QueueConfigurations", [])
existing = [q for q in queues if q.get("Id") == notif_id]
in_sync = len(existing) == 1 and canon(existing[0]) == canon(ours)

desired = dict(current)
desired["QueueConfigurations"] = [q for q in queues if q.get("Id") != notif_id] + [ours]
with open(desired_path, "w", encoding="utf-8") as f:
    json.dump(desired, f)

print("in-sync" if in_sync else "differs")
PYTHON
)"

if [[ "$NOTIF_STATE" == "in-sync" ]]; then
    ok "notification already correct"
else
    change "applying bucket notification"
    apply aws s3api put-bucket-notification-configuration --bucket "$BUCKET" \
        --notification-configuration "file://$WORK_DIR/desired-notif.json"
fi

# ---------------------------------------------------------------------------
# 6. Read everything back and fail loudly if anything is still wrong
# ---------------------------------------------------------------------------
if is_dry_run; then
    log "Dry run complete. Nothing was changed."
    exit 0
fi

log "Verifying"
FINAL_RETENTION="$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" \
    --attribute-names MessageRetentionPeriod \
    --query Attributes.MessageRetentionPeriod --output text)"
FINAL_POLICY="$(json_canon "$(aws sqs get-queue-attributes --queue-url "$QUEUE_URL" \
    --attribute-names Policy --query Attributes.Policy --output text)")"
FINAL_NOTIF="$(aws s3api get-bucket-notification-configuration --bucket "$BUCKET" \
    --query "QueueConfigurations[?Id=='$NOTIFICATION_ID'].QueueArn | [0]" --output text)"

[[ "$FINAL_RETENTION" == "$QUEUE_RETENTION_SECONDS" ]] || die "retention check failed ($FINAL_RETENTION)"
[[ "$FINAL_POLICY" == "$DESIRED_QUEUE_POLICY" ]]       || die "queue policy check failed"
[[ "$FINAL_NOTIF" == "$QUEUE_ARN" ]]                   || die "bucket notification check failed"

ok "retention $FINAL_RETENTION seconds"
ok "queue policy restricts senders to our bucket and account"
ok "bucket notifies the queue about new CloudTrail log files"
log "Done. Queue: $(printf '%s' "$QUEUE_URL" | mask_ids)"
