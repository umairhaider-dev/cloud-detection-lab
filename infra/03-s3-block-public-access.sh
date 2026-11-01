#!/usr/bin/env bash
# Account-level S3 Block Public Access. Safe to re-run.
# Added 2026-11-01: found disabled while checking rule
# aws_s3_bucket_policy_external_account, which relies on it for public exposure.
set -euo pipefail
ACCT=$(aws sts get-caller-identity --query Account --output text)
aws s3control put-public-access-block --account-id "$ACCT" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3control get-public-access-block --account-id "$ACCT"
