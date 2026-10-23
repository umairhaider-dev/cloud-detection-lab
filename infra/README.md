# infra/ — rebuild the lab's AWS logging pipeline

Two idempotent scripts create (or repair) everything the lab needs in AWS:

| Script | What it ensures |
| --- | --- |
| `01-cloudtrail.sh` | A private log bucket that only this trail may write to; a **multi-Region** trail with global service events (needed to see IAM/STS) and log file validation; logging on. |
| `02-sqs-notifications.sh` | An SQS queue with 14-day retention; a queue policy that only accepts messages from our bucket and account; a bucket notification for new CloudTrail log files only. |

## Run it

```bash
cp infra/lab.env.example infra/lab.env    # then put your account ID in it
DRY_RUN=1 ./infra/01-cloudtrail.sh        # preview: changes nothing
./infra/01-cloudtrail.sh
./infra/02-sqs-notifications.sh
```

`infra/lab.env` is git-ignored, so the account ID is never committed.

## Design choices

- **Idempotent and drift-aware.** Each run compares the live configuration with
  the desired one and only writes what is missing or wrong. A clean re-run makes
  zero API changes, so the scripts never trip the lab's own log-pipeline
  tampering detections.
- **Drift is reported, not silently fixed.** If the trail was switched to
  single-Region, logging was stopped, or queue retention was shortened, the
  script warns before repairing it, because in a real environment that drift
  could be an attacker.
- **Safety first.** Every script refuses to run unless the credentials belong
  to the lab account, and masks account IDs in its output.
- **Doesn't clobber.** S3 replaces the whole notification configuration on
  every write, so `02` merges: it keeps any other notifications and replaces
  only its own.
- **Tested.** Verified against a simulated AWS for: fresh build, no-op re-run,
  repair of five kinds of drift, dry run, wrong account, missing config, and
  preserving unrelated notifications. Linted with `shellcheck`.
