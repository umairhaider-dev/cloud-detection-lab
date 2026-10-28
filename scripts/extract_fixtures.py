#!/usr/bin/env python3

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

# What each rule targets. Mirrors the `selection` blocks in rules/*.yml.
TARGETS = {
    "aws_cloudtrail_stop_or_delete": {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": {"StopLogging", "DeleteTrail"},
    },
    "aws_ec2_getpassworddata_sweep": {
        "eventSource": "ec2.amazonaws.com",
        "eventName": {"GetPasswordData"},
    },
    "aws_cloudtrail_config_weakened": {
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": {"UpdateTrail", "PutEventSelectors"},
    },
    "aws_s3_log_bucket_tampering": {
        "eventSource": "s3.amazonaws.com",
        "eventName": {"PutBucketNotification", "PutBucketPolicy", "DeleteBucketPolicy",
                      "PutBucketLifecycle", "DeleteBucketLifecycle", "DeleteBucket"},
        # requestParameters.bucketName|startswith
        "scope": ("bucketName", "startswith", "detlab-cloudtrail-"),
    },
    "aws_sqs_log_queue_tampering": {
        "eventSource": "sqs.amazonaws.com",
        "eventName": {"DeleteQueue", "PurgeQueue", "SetQueueAttributes"},
        # requestParameters.queueUrl|endswith
        "scope": ("queueUrl", "endswith", "/detlab-cloudtrail-events"),
    },
}

# Services whose non-target events make the most useful "near miss" negatives:
# same service as a rule, different API call. Sampled first.
NEAR_MISS_SOURCES = {"cloudtrail.amazonaws.com", "ec2.amazonaws.com",
                     "s3.amazonaws.com", "sqs.amazonaws.com"}

# Harmless calls on the same services as the rules. Always included in the
# benign set (up to NEAR_MISS_PER_CALL of each), because they are the negatives
# most likely to catch a rule that matches too broadly.
NEAR_MISS_CALLS = {
    ("s3.amazonaws.com", "GetBucketAcl"),
    ("cloudtrail.amazonaws.com", "DescribeTrails"),
    ("cloudtrail.amazonaws.com", "GetTrailStatus"),
    ("sqs.amazonaws.com", "GetQueueAttributes"),
    ("sqs.amazonaws.com", "CreateQueue"),
}
NEAR_MISS_PER_CALL = 3


def iter_log_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if "extracted" in path.relative_to(root).parts:
            continue  # never re-read our own output
        if path.name.endswith(".json.gz") or path.name.endswith(".json"):
            yield path


def read_records(path: Path) -> list[dict]:
    opener = gzip.open if path.name.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  ! skipping unreadable file {path}: {exc}", file=sys.stderr)
        return []
    if not isinstance(data, dict) or not isinstance(data.get("Records"), list):
        return []  # e.g. a digest file or something that isn't a log file
    return data["Records"]


def matches(record: dict, target: dict) -> bool:
    if not (record.get("eventSource") == target["eventSource"]
            and record.get("eventName") in target["eventName"]):
        return False
    if "scope" not in target:
        return True
    field, how, value = target["scope"]
    actual = str((record.get("requestParameters") or {}).get(field, ""))
    return actual.startswith(value) if how == "startswith" else actual.endswith(value)


def sort_key(record: dict):
    return (record.get("eventTime", ""), record.get("eventID", ""))


def stratified_sample(records: list[dict], size: int) -> list[dict]:
    """Deterministic sample covering as many distinct API calls as possible.

    Groups records by (eventSource, eventName) and takes one from each group in
    turn, near-miss services first, until `size` is reached. No randomness, so
    re-running produces the same fixture and git diffs stay clean.
    """
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for rec in sorted(records, key=sort_key):
        groups[(rec.get("eventSource", ""), rec.get("eventName", ""))].append(rec)

    order = sorted(groups, key=lambda k: (k[0] not in NEAR_MISS_SOURCES, k))
    picked: list[dict] = []
    depth = 0
    while len(picked) < size:
        took_any = False
        for key in order:
            if depth < len(groups[key]):
                picked.append(groups[key][depth])
                took_any = True
                if len(picked) == size:
                    break
        if not took_any:
            break
        depth += 1
    return sorted(picked, key=sort_key)


def write_ndjson(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", type=Path, default=Path("captures/raw"))
    ap.add_argument("--output", type=Path, default=Path("captures/raw/extracted"))
    ap.add_argument("--benign-size", type=int, default=50,
                    help="how many normal records to sample (default 50)")
    ap.add_argument("--keep-stratus", action="store_true",
                    help="allow Stratus Red Team setup/cleanup calls in the benign set")
    args = ap.parse_args()

    if "raw" not in args.output.parts:
        print("Refusing: --output must be inside captures/raw/ (git-ignored), "
              "because extracted records are not sanitized yet.", file=sys.stderr)
        return 2

    files = list(iter_log_files(args.input))
    if not files:
        print(f"No CloudTrail files found under {args.input}", file=sys.stderr)
        return 1

    seen_ids: set[str] = set()
    hits: dict[str, list[dict]] = {name: [] for name in TARGETS}
    others: list[dict] = []
    total = dupes = 0

    for path in files:
        for rec in read_records(path):
            total += 1
            eid = rec.get("eventID")
            if eid:
                if eid in seen_ids:
                    dupes += 1
                    continue
                seen_ids.add(eid)

            hit = False
            for name, target in TARGETS.items():
                if matches(rec, target):
                    hits[name].append(rec)
                    hit = True
            if hit:
                continue
            ua = str(rec.get("userAgent", ""))
            if not args.keep_stratus and "stratus-red-team" in ua:
                continue
            others.append(rec)

    near_groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for rec in sorted(others, key=sort_key):
        key = (rec.get("eventSource", ""), rec.get("eventName", ""))
        if key in NEAR_MISS_CALLS and len(near_groups[key]) < NEAR_MISS_PER_CALL:
            near_groups[key].append(rec)
    near = [r for recs in near_groups.values() for r in recs]
    near_ids = {id(r) for r in near}
    rest = [r for r in others if id(r) not in near_ids]
    benign = sorted(near + stratified_sample(rest, max(args.benign_size - len(near), 0)),
                    key=sort_key)

    out_files = {
        name: args.output / name / "should_fire.jsonl" for name in TARGETS
    }
    out_files["benign"] = args.output / "benign" / "should_not_fire.jsonl"
    for name, recs in hits.items():
        write_ndjson(out_files[name], sorted(recs, key=sort_key))
    write_ndjson(out_files["benign"], benign)

    # ---- Summary -----------------------------------------------------------
    print(f"Read {len(files)} files, {total} records ({dupes} duplicates skipped)\n")

    stop = hits["aws_cloudtrail_stop_or_delete"]
    print(f"StopLogging/DeleteTrail: {len(stop)} record(s) -> {out_files['aws_cloudtrail_stop_or_delete']}")
    for rec in sorted(stop, key=sort_key):
        print(f"  {rec.get('eventTime')}  {rec.get('eventName')}  "
              f"errorCode={rec.get('errorCode', '-')}")

    gpd = hits["aws_ec2_getpassworddata_sweep"]
    print(f"\nGetPasswordData: {len(gpd)} record(s) -> {out_files['aws_ec2_getpassworddata_sweep']}")
    if gpd:
        gpd_sorted = sorted(gpd, key=sort_key)
        instances = {(r.get("requestParameters") or {}).get("instanceId") for r in gpd}
        identities = {(r.get("userIdentity") or {}).get("arn") for r in gpd}
        errors = {r.get("errorCode", "-") for r in gpd}
        print(f"  distinct instanceIds: {len(instances - {None})}")
        print(f"  distinct identities:  {len(identities - {None})}")
        print(f"  first/last:           {gpd_sorted[0].get('eventTime')} .. {gpd_sorted[-1].get('eventTime')}")
        print(f"  errorCodes:           {', '.join(sorted(errors))}")

    for name in ("aws_cloudtrail_config_weakened", "aws_s3_log_bucket_tampering",
                 "aws_sqs_log_queue_tampering"):
        recs = sorted(hits[name], key=sort_key)
        print(f"\n{name}: {len(recs)} record(s) -> {out_files[name]}")
        for rec in recs:
            rp = rec.get("requestParameters") or {}
            target = rp.get("bucketName") or rp.get("queueUrl") or rp.get("name") \
                or rp.get("trailName") or "-"
            print(f"  {rec.get('eventTime')}  {rec.get('eventName'):24} {target}  "
                  f"errorCode={rec.get('errorCode', '-')}")

    print("\nNear-misses in the benign set:")
    for key in sorted(NEAR_MISS_CALLS):
        print(f"  {key[1]:20} {len(near_groups.get(key, []))}")

    sources = {(r.get("eventSource"), r.get("eventName")) for r in benign}
    print(f"\nBenign sample: {len(benign)} of {len(others)} normal records, "
          f"{len(sources)} distinct API calls -> {out_files['benign']}")

    missing = [n for n, r in hits.items() if not r]
    if missing:
        print(f"\nWARNING: nothing found for {', '.join(missing)}. "
              "Check you downloaded the right day and regions.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
