# Attack plan

Mapped to ATT&CK v20. v19 split Defense Evasion into Stealth and Defense Impairment; cloud log tampering moved from T1562.008 to T1685.002.

## Run with Stratus

1. ec2-get-password-data: Credential Access, T1552. 30 calls, all denied. Detected by aws_ec2_getpassworddata_sweep.
2. iam-create-backdoor-role: Persistence, T1098.003. Succeeded, but had a DenyAll boundary. Detected by aws_iam_trust_policy_external_account and aws_iam_admin_policy_attached.
3. iam-backdoor-role: Persistence, T1098.003. Succeeded. The role had admin and no boundary. Detected by aws_iam_trust_policy_external_account; the warmup's admin attach is caught by aws_iam_admin_policy_attached.
4. secretsmanager-retrieve-secrets: Credential Access, T1555.006. 20 secrets in 8 seconds. Detected by aws_secretsmanager_bulk_retrieval.
5. s3-backdoor-bucket-policy: Exfiltration, T1537. Succeeded, not blocked. Detected by aws_s3_bucket_policy_external_account.
6. ec2-share-ebs-snapshot: Exfiltration, T1537. Succeeded. Detected by aws_ec2_snapshot_shared_external.
7. iam-create-admin-user: Persistence, T1136.003, T1098.003 and T1098.001. Succeeded, not blocked. Detected by aws_iam_admin_policy_attached and aws_iam_access_key_created. CreateUser itself (T1136.003) has no rule yet.

## Emulated with my own actions (Defense Impairment, T1685.002)

- StopLogging (denied). Detected by aws_cloudtrail_stop_or_delete.
- UpdateTrail. Detected by aws_cloudtrail_config_weakened.
- Log bucket changes (PutBucketNotification, DeleteBucket). Detected by aws_s3_log_bucket_tampering.
- Log queue changes (SetQueueAttributes). Detected by aws_sqs_log_queue_tampering.

## Not run

- console-login-without-mfa and iam-update-user-login-profile: login profiles are blocked on this account.
- s3-ransomware: needs S3 data events, and the trail records management events only.
- ec2-steal-instance-credentials and ec2-enumerate-from-instance: need an EC2 instance.
- iam-backdoor-user: not run yet.
- GuardDuty: not available on this account type.

## Gaps

- No Initial Access, Discovery or Impact coverage.
- CreateUser (T1136.003) has no rule.
- DeleteTrail has a rule but no real fixture yet.
- Public S3 exposure is prevented but not detected.