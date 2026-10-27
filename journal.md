# Build Journal: Week 1
**AWS account and CloudTrail**
My trail was created in Sydney, but AWS records global services like IAM and STS in us-east-1. A single-Region trail outside us-east-1 never receives those events, so my trail was blind to all IAM activity. I fixed it with aws cloudtrail update-trail --name detlab-trail --is-multi-region-trail --include-global-service-events. This matters because attacks like creating a backdoor user or access key happen in IAM. Without these events, persistence and privilege escalation would be invisible. Lesson: check visibility before writing detections. You can’t detect what you don’t log.

**S3 → SQS notifications**
Making Filebeat scan the whole bucket again and again would be wasteful. Instead, S3 posts a message to an SQS queue for every new file, and Filebeat reads the queue. I set retention to 14 days because Filebeat only started reading on Day 4. If messages expired first, those log files would never reach the SIEM. It also means nothing is lost when Filebeat is stopped or my session expires.
The scariest finding: if an attacker deletes the bucket notification, CloudTrail keeps logging and its status still says true, but S3 stops telling the queue and the SIEM goes quiet. It’s a silent killer, because my StopLogging and DeleteTrail rules would never fire.
I found the event name for this change, PutBucketNotification, with aws cloudtrail lookup-events in my own logs. It differs from the API name, PutBucketNotificationConfiguration, so I take event names from real data, not from memory.

**Elastic SIEM and GitHub repo**
My first Elastic install failed silently. It left an empty folder with no containers and no error log, so it most likely stopped early. Another Docker project (watchpost) was also using memory, so as a precaution I paused it, cleaned up, and reran the installer with tee to capture all output. It worked: Elasticsearch 9.5.5 on a trial license.
I downloaded and read the install script before running it rather than piping it into sh, so I knew what it would do before trusting it.
I couldn’t find the Security app at first because my Kibana space used the Elasticsearch solution view, which hides Security features. Switching the space to the Security view fixed it.
When I copied files from Windows, Zone.Identifier files appeared. They record where a file was downloaded from, so I deleted them, added them to .gitignore, and now copy files with cp from the Linux side. Secrets are protected by a gitleaks pre-commit hook and GitHub push protection, with .gitignore as the first layer.

**Filebeat**
Filebeat got its own role instead of my admin session. It can only consume one SQS queue and read CloudTrail log files in one bucket folder. I proved the limits with three commands: get-caller-identity worked, but listing buckets and stopping CloudTrail were both denied.
Filebeat first refused to start because line 6 of aws.yml had 5 spaces instead of 4, which made the whole file unreadable. filebeat test config still said “Config OK” because it doesn’t check module files. A test only proves what it actually covers.
Then Filebeat printed Cannot fork. Filebeat runs inside seccomp, a Linux feature that limits which system calls a process may make, and it blocks starting new processes. My credentials came from credential_process, which needs to launch the AWS CLI, so it was blocked. I didn’t disable seccomp, because it stops an attacker from launching a shell if Filebeat is ever exploited by a malicious log. Instead I set credential_profile_name: lab-login, so Filebeat reads my aws login session natively, and role_arn, so it assumes the limited role itself. Result: 1,030 CloudTrail events searchable in Kibana.

**First attack (smoke test)**
I ran Stratus Red Team’s ec2-get-password-data, a real credential-access technique that tries to steal EC2 Windows passwords. It cost nothing: it creates one IAM role and makes denied calls against made-up instance IDs, so no EC2 instance is launched. In Kibana I found 30 GetPasswordData calls in 9 seconds from the Stratus-created role, all denied with Client.UnauthorizedOperation, and the AssumeRole event just before, which is when the attacker became that role.
Earlier I had expected the denied StopLogging attempt to show AccessDeniedException, but CloudTrail recorded AccessDenied. Lesson: make a hypothesis, then verify it against real data. Different services also spell “denied” differently, so rules must account for that.
For a detection, “≥5 distinct instance IDs in 2 minutes” beats “≥8 calls,” because an admin retrying on one instance won’t trip it while an attacker sweeping many instances will. The realistic false positive is automation, which I’d handle by excluding that tool’s specific role.

**First Sigma rules**
My rule passed `sigma check` and converted cleanly, but found nothing in Kibana. Sigma rules for CloudTrail use the raw CloudTrail field names (`eventSource`, `eventName`), but on the way into Elastic, Filebeat renames them to the ECS standard (`event.provider`, `event.action`). Without a processing pipeline to translate them, the query looked for fields that don't exist and silently matched nothing. A broken rule looks exactly like "no attacks." Lesson: never trust a rule until you've seen it fire on real attack data.

**Test data from real attack logs**
I downloaded the 126 CloudTrail log files from the day of my attack and wrote two scripts. The first extracts the records each rule targets: the `StopLogging` event, the 30 `GetPasswordData` calls, and 50 normal events as a "should not fire" set. The second sanitizes them. It replaces account IDs, key IDs, IPs and emails with safe placeholders, keeps each placeholder consistent across files so correlation still works, and runs a leak check before writing anything. Then I committed the fixtures and pushed them to GitHub.
A review afterwards found my personal role session ID and Identity Center IDs still in one benign record. I redacted them, rewrote the commit, and confirmed they appear nowhere in the repo's history. Lesson: automated checks catch patterns, but identifiers like session names still need a human review.
