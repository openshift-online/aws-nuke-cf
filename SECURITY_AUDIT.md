# Security Audit — aws-nuke-cf

> **Audit Date:** 2026-05-01  
> **Auditor:** Automated adversarial security agent  
> **Scope:** Full repository static analysis — CloudFormation template, Containerfile, Makefile, nuke-config examples

---

## ⚠️ Special Risk Context

This repository implements a tool whose sole purpose is to **irreversibly delete AWS resources at scale**. A single misconfiguration or successful attack against this system can result in permanent destruction of production infrastructure, data, and service availability. Every finding in this report must be evaluated with that blast radius in mind.

---

## Summary

The audit identified **4 CRITICAL**, **6 HIGH**, **5 MEDIUM**, and **4 LOW** findings. The critical findings — broken account validation, an arbitrary `CONFIG_URL` parameter, an unpinned `:latest` container image, and an `AdministratorAccess` IAM policy — individually represent paths to complete infrastructure destruction. Together they represent an unacceptable risk profile for a system this destructive.

---

## Findings

### CRITICAL

---

**[CRITICAL] Account Blocklist Validation Uses Substring Grep — Trivially Bypassed**

- **File:** `template.yaml` (line 321)
- **Category:** Application — Safety Logic
- **Issue:** The account validation that is supposed to prevent aws-nuke from targeting accounts not in the config uses a plain substring `grep`:

  ```bash
  if ! grep -q "$ACCOUNT" /tmp/user-config.yml; then
  ```

  This is a substring match, not an exact match. If the current AWS account ID is `111111111111` and the config file contains the string `1111111111110` (a different account) in any field — a comment, a resource name filter, a tag value — the check passes. Similarly, if account `999999999999` appears anywhere in the file as part of a longer string, the blocklist is bypassed.

  Additionally, account IDs appear in many places in aws-nuke configs (resource filters, tag values, ARN patterns) unrelated to the `accounts:` block — a malicious or accidentally crafted config could cause false positives in either direction.

- **Attack Vector:**
  1. Attacker crafts a nuke config where the current account ID appears only as a substring of another value (e.g., as part of an S3 bucket ARN in a filter)
  2. The `grep -q` check passes because the substring is found
  3. aws-nuke runs against the wrong account, interpreting the account config incorrectly
  
  Or inversely: a blocklisted account ID appears as a substring of the current account, causing the check to fail when it should pass.

- **Impact:** **Complete infrastructure destruction in a wrong or production AWS account** due to a broken safety check that is the first line of defense against mistargeting.

- **Recommendation:** Replace the grep with proper YAML parsing that extracts only the keys from the `accounts:` map and matches the current account ID exactly:

  ```bash
  YAML_ACCOUNTS=$(python3 -c "
  import yaml, sys
  with open('/tmp/user-config.yml') as f:
      cfg = yaml.safe_load(f)
  accts = list(cfg.get('accounts', {}).keys())
  print('\n'.join(str(a) for a in accts))
  ")
  if ! echo "$YAML_ACCOUNTS" | grep -qx "$ACCOUNT"; then
      echo "ERROR: Account $ACCOUNT not found in config accounts map"
      exit 1
  fi
  ```

---

**[CRITICAL] `CONFIG_URL` Parameter Accepts Arbitrary Untrusted URLs Without Integrity Verification**

- **File:** `template.yaml` (lines 66–72, 315–317)
- **Category:** Supply Chain — Configuration Management
- **Issue:** The CloudFormation parameter `ConfigSourceUrl` is passed as `CONFIG_URL` to the build, where it is fetched unconditionally:

  ```bash
  if [ -n "$CONFIG_URL" ]; then
      echo "Downloading config from: $CONFIG_URL"
      curl -fsSL "$CONFIG_URL" -o /tmp/user-config.yml
  fi
  ```

  There is:
  - No allowlist of trusted domains or URL prefixes
  - No cryptographic integrity verification (no checksum, no GPG signature)
  - No certificate pinning
  - No validation that the URL is an S3 URL within the same account

  An attacker who can control the value of `CONFIG_URL` (by compromising the AWS account enough to update a CloudFormation parameter, or by compromising the URL's DNS or hosting) can serve any nuke configuration file — including one that removes the blocklist, targets additional accounts, or removes all resource filters.

- **Attack Vector:**
  1. Attacker performs DNS hijacking or BGP hijacking against the domain in `CONFIG_URL`
  2. Returns a malicious nuke config targeting the production account with no filters
  3. The only safety check (the broken substring grep) passes because the account ID is in the config
  4. aws-nuke deletes the entire account

  Alternative: attacker with minimal AWS access (e.g., read-only + cloudformation:UpdateStack) updates the `ConfigSourceUrl` parameter to point to their server.

- **Impact:** **Complete infrastructure destruction** with attacker-controlled scope. Any resource type, any account reachable from this tool can be targeted.

- **Recommendation:** Remove the `CONFIG_URL` parameter entirely and require config to be stored in the dedicated S3 bucket created by this stack. If external config sources are required, require:
  1. The URL must be an S3 URL in the same account (`s3://`)
  2. A mandatory `CONFIG_URL_SHA256` parameter whose value is verified after download
  3. OR: GPG signature verification against a known key embedded in the container

---

**[CRITICAL] Container Image Pinned to `:latest` — Mutable Supply Chain Attack Surface**

- **File:** `template.yaml` (line 42)
- **Category:** Supply Chain — Unpinned Image Tag
- **Issue:** The container image that executes aws-nuke is specified as:

  ```yaml
  Default: quay.io/rrp-dev-ci/aws-nuke-cf:latest
  ```

  The `:latest` tag is mutable. Any push to this tag changes the code that runs on the next CodeBuild execution. This is not a hypothetical risk — supply chain attacks against container registries are documented and recurring.

- **Attack Vector:**
  1. Attacker compromises the Quay.io organization account (`rrp-dev-ci`) via credential theft, phishing, or a compromised CI/CD pipeline that pushes images
  2. Pushes a malicious image tagged `:latest` that either: (a) calls aws-nuke with no filters in live mode, or (b) exfiltrates the `AdministratorAccess` credentials available in the CodeBuild environment
  3. Next scheduled run (or manually triggered run) pulls the poisoned image
  4. Infrastructure is destroyed or credentials are exfiltrated

- **Impact:** **Complete infrastructure destruction** or **full AWS account credential compromise** (the CodeBuild role has `AdministratorAccess`). This attack requires only compromising the image registry.

- **Recommendation:** Pin to a specific immutable SHA256 digest:
  ```yaml
  Default: quay.io/rrp-dev-ci/aws-nuke-cf@sha256:<full-verified-digest>
  ```
  Update the digest only via a reviewed PR. Consider using a private registry with image signing (cosign/Sigstore) and enforce signature verification in the buildspec.

---

**[CRITICAL] CodeBuild Role Has `AdministratorAccess` as Primary Permission Grant**

- **File:** `template.yaml` (line 139)
- **Category:** Infrastructure — IAM / Least Privilege
- **Issue:** The CodeBuild execution role attaches the AWS managed `AdministratorAccess` policy (`Action: *`, `Resource: *`), then adds deny statements to restrict specific actions. This is a defense-in-depth inversion: the allow is maximally broad, and safety depends entirely on deny statements being correct and complete.

  Any gap in the deny statements — a missing resource ARN, a typo, a new AWS service not covered — results in full admin access. The deny statements cannot protect against actions not anticipated at deploy time.

- **Attack Vector:**
  1. Attacker compromises the CodeBuild environment (via poisoned container image, malicious build commands, or network-based attack)
  2. Uses the `AdministratorAccess` permissions to: create new IAM users/access keys for persistent access, disable CloudTrail, modify S3 bucket policies to exfiltrate data, or assume other roles
  3. Even if the deny statements block specific targeted attacks, the admin access enables lateral movement via paths not covered by the denies

- **Impact:** **Full AWS account compromise** from a single CodeBuild environment breach. An attacker can establish persistent access, disable logging, exfiltrate all data, and perform arbitrary AWS API calls.

- **Recommendation:** Replace `AdministratorAccess` with a minimal allow list of only the specific actions aws-nuke requires (list/describe/delete for each supported resource type). Maintain the deny statements as a secondary defense. Reference aws-nuke's documentation for the minimum required IAM permissions.

---

### HIGH

---

**[HIGH] aws-nuke Binary Checksum Verified But Checksum File Is Not Signed**

- **File:** `Containerfile` (lines 40–48)
- **Category:** Supply Chain — Binary Integrity
- **Issue:** The aws-nuke binary download verifies a checksum:

  ```dockerfile
  curl -fsSLO "${NUKE_BASE}/checksums.txt" && \
  grep "  ${NUKE_TAR}$" checksums.txt | sha256sum -c -
  ```

  But `checksums.txt` itself is downloaded from the same location without GPG signature verification. An attacker who can MITM the download (or compromise the GitHub release) can serve both a malicious binary and a matching `checksums.txt`. The checksum verification becomes a false assurance.

- **Attack Vector:** MITM attack on the GitHub release download serves a modified aws-nuke binary with a matching pre-computed checksum in a modified `checksums.txt`. The verification passes. The malicious binary runs with `AdministratorAccess` permissions.

- **Recommendation:** Verify the `checksums.txt` GPG signature before trusting it:
  ```dockerfile
  curl -fsSLO "${NUKE_BASE}/checksums.txt.sig"
  gpg --verify checksums.txt.sig checksums.txt
  ```
  Embed the upstream GPG public key in the Containerfile rather than fetching from a keyserver.

---

**[HIGH] No Minimum Age Filter Documented or Enforced — Recently Created Resources Are Deleted**

- **File:** `examples/nuke-config.yml`
- **Category:** Application — Safety Configuration
- **Issue:** The example configuration does not demonstrate or recommend `minimum-age` filters. aws-nuke supports age-based filters to prevent deleting resources created within a time window (e.g., last 7 days). Without this, resources created minutes or hours before a nuke run are deleted immediately.

  This is especially dangerous during incident response or active deployments, where critical resources may be created and then immediately destroyed.

- **Attack Vector:** Operational mistake: an engineer deploys new infrastructure to a sandbox account. Before they add the new resources to the config's filter list, the scheduled nuke run fires and deletes them. No attacker needed — the missing safety is sufficient.

- **Recommendation:** Add minimum-age examples to the config and consider making it a required field enforced by a pre-flight check:
  ```yaml
  filters:
    EC2Instance:
      - type: age
        property: LaunchTime
        minimum-age: 7  # days
  ```

---

**[HIGH] S3 Config Bucket Missing MFA Delete**

- **File:** `template.yaml` (lines 88–107)
- **Category:** Infrastructure — S3 Data Protection
- **Issue:** The S3 bucket storing the nuke configuration has versioning enabled but lacks MFA Delete protection:

  ```yaml
  VersioningConfiguration:
    Status: Enabled
  # No MFADelete: Enabled
  ```

  The nuke config is the authoritative document controlling what gets deleted. An attacker with temporary AWS credentials (e.g., from the CodeBuild role) can immediately modify or delete it without any additional authentication factor.

- **Attack Vector:** Attacker with stolen temporary credentials uploads a modified nuke config to S3 that removes all filters and targets the production account. Next nuke run uses the poisoned config. Resources are destroyed.

- **Recommendation:** Enable MFA Delete on the bucket. For operations that cannot use MFA Delete (automated workflows), use S3 Object Lock in governance mode with a minimum retention period.

---

**[HIGH] YAML Self-Protection Injection Uses Fragile Shell Text Manipulation**

- **File:** `template.yaml` (lines 335–394)
- **Category:** Application — Safety Logic
- **Issue:** The self-protection preset (which prevents aws-nuke from deleting its own resources) is injected into the user config using `sed`, `awk`, and `grep` pattern matching against YAML structure. If the user's YAML uses unusual-but-valid formatting (e.g., inline sequences, multi-line strings, different quoting), the injection may:
  - Fail silently (the success message is printed regardless)
  - Inject the preset at the wrong indentation level (breaking YAML)
  - Not be linked into the `accounts` block's preset list

- **Attack Vector:** A user provides a validly-formatted but structurally unusual YAML config (e.g., using `presets: {_self_protection: {...}}` inline map syntax instead of block style). The awk pattern doesn't match. Self-protection is not applied. aws-nuke deletes its own CloudFormation stack, IAM roles, and S3 bucket while running.

- **Impact:** Destruction of the aws-nuke infrastructure itself during a run, loss of future ability to run scheduled cleanup.

- **Recommendation:** Replace shell-based YAML manipulation with a proper YAML parser. A small Python script using `pyyaml` can merge presets and verify application before proceeding. Add an explicit post-injection validation that fails the build if `_self_protection` is not found in the final config.

---

**[HIGH] EventBridge Schedule Expression Has No Minimum Frequency Constraint**

- **File:** `template.yaml` (lines 18–24)
- **Category:** Infrastructure — Operations
- **Issue:** The `ScheduleExpression` parameter accepts any valid EventBridge expression:

  ```yaml
  ScheduleExpression:
    Type: String
    Default: cron(0 3 ? * SUN *)
  ```

  No `AllowedPattern` or minimum interval is enforced. An attacker (or a user making a typo) can set `rate(1 minute)`, causing aws-nuke to run every minute. In live mode, this would continuously delete all unprotected resources as fast as the AWS APIs allow.

- **Attack Vector:** Attacker with `cloudformation:UpdateStack` on this stack changes the schedule to `rate(1 minute)` with `DryRun=false`. Complete infrastructure destruction within minutes.

- **Recommendation:** Add `AllowedPattern` to restrict to at least hourly schedules:
  ```yaml
  AllowedPattern: '^(cron\(.+\)|rate\([1-9][0-9]*\s+(hour|hours|day|days)\))$'
  ```

---

**[HIGH] CodeBuild VPC Configuration Not Specified — Runs in Default VPC**

- **File:** `template.yaml` (lines 275–279)
- **Category:** Infrastructure — Network Isolation
- **Issue:** The CodeBuild project does not specify a VPC configuration. It runs in AWS CodeBuild's default managed environment, which has outbound internet access and uses default security groups.

- **Attack Vector:** A compromised CodeBuild environment can make outbound connections to attacker-controlled infrastructure to exfiltrate the `AdministratorAccess` credentials available in the environment. There are no network controls preventing this.

- **Recommendation:** Deploy CodeBuild in a private VPC subnet with no internet gateway. Use VPC endpoints for all required AWS API calls. This eliminates the outbound exfiltration channel.

---

### MEDIUM

---

**[MEDIUM] Makefile Confirmation Gate Bypassable with `YES=1`**

- **File:** `Makefile` (line 90)
- **Category:** CI/CD — Operations
- **Issue:**

  ```makefile
  if [ -n "$(YES)" ]; then true; else read -p "Deploy? [y/N] " confirm ...; fi
  ```

  The interactive confirmation gate can be bypassed by setting the `YES` environment variable. This is intended for CI/CD but makes it trivially easy to skip the confirmation in interactive sessions via `make deploy YES=1 DRY_RUN=false`.

- **Recommendation:** For `DRY_RUN=false` deployments, always require interactive confirmation regardless of the `YES` flag. The `YES` bypass should only apply to dry-run deployments. Document this explicitly.

---

**[MEDIUM] CloudWatch Logs May Contain Sensitive Account Information — Retention Too Long**

- **File:** `template.yaml` (lines 46–50)
- **Category:** Infrastructure — Logging
- **Issue:** Default log retention is 30 days. Build logs include account IDs, resource IDs, IAM role names, S3 bucket names, and Lambda function names. An attacker who gains `logs:GetLogEvents` access to this log group acquires a detailed inventory of the account's resources over the past month.

- **Recommendation:** Reduce default retention to 7 days. Encrypt the log group with a KMS key with a restricted key policy. Monitor log group access in CloudTrail.

---

**[MEDIUM] No Audit Trail of Which Config Version Was Used for Each Run**

- **File:** `template.yaml`
- **Category:** Infrastructure — Auditability
- **Issue:** The config is downloaded from S3 at the start of each run, but the specific S3 object version ID used is not recorded in CloudWatch Logs. If the config is modified between runs, there is no way to determine which exact config was used for a destructive operation.

- **Recommendation:** Log the S3 object version ID immediately after downloading the config:
  ```bash
  VERSION_ID=$(aws s3api head-object --bucket $BUCKET --key nuke-config.yml --query VersionId --output text)
  echo "Using config version: $VERSION_ID"
  ```

---

**[MEDIUM] CodeBuild Role ARN Exposed in CloudFormation Stack Outputs**

- **File:** `template.yaml` (lines 538–540)
- **Category:** Infrastructure — Information Disclosure
- **Issue:** The IAM role ARN with `AdministratorAccess` is published as a CloudFormation stack output readable by anyone with `cloudformation:DescribeStacks`. Exposing this ARN helps attackers enumerate the role for privilege escalation attempts.

- **Recommendation:** Remove the output or restrict it. Store the ARN in Secrets Manager with a tight key policy if it needs to be referenced by other systems.

---

**[MEDIUM] No Enforcement That Dry-Run Succeeds Before Live Mode Is Enabled**

- **File:** `template.yaml`, `README.md`
- **Category:** Operations — Safety Procedure
- **Issue:** The README recommends running in dry-run mode first, but there is no infrastructure-level enforcement. A user can deploy with `DryRun=false` on the very first deployment. The entire safety model for "verify before deleting" is advisory.

- **Recommendation:** Add a CloudFormation Condition or Lambda custom resource that requires a successful dry-run execution (verified via CloudWatch Logs or a parameter stored after the first dry run) before `DryRun=false` is accepted.

---

### LOW

---

**[LOW] Build Timeout Default of 120 Minutes Is Unnecessarily Long**

- **File:** `template.yaml` (lines 52–57)
- **Category:** Operations
- **Issue:** Default timeout is 120 minutes. Typical aws-nuke runs complete in 5–30 minutes. An excessively long timeout means stuck or compromised builds run for hours, increasing the window for damage.

- **Recommendation:** Change default to `30`. Document that most runs complete in under 10 minutes.

---

**[LOW] No Build Artifacts Retained for Post-Incident Forensics**

- **File:** `template.yaml` (line 416)
- **Category:** Operations — Auditability
- **Issue:** `Artifacts: Type: NO_ARTIFACTS`. The only audit trail is CloudWatch Logs with a 30-day retention. After 30 days, there is no record of which resources were deleted by which run.

- **Recommendation:** Upload the full aws-nuke output to the S3 config bucket at the end of each run, with a 90-day retention policy.

---

**[LOW] EventBridge Target Has No Dead Letter Queue**

- **File:** `template.yaml` (lines 461–464)
- **Category:** Infrastructure — Operations
- **Issue:** If CodeBuild fails to start (quota exceeded, role issues, service limits), the EventBridge event is silently dropped with no notification.

- **Recommendation:** Add a Dead Letter Queue (SQS) to the EventBridge target and alarm on messages appearing in the DLQ.

---

**[LOW] GPG Key Fetched from External Keyserver During Container Build**

- **File:** `Containerfile` (line 27)
- **Category:** Supply Chain — Binary Integrity
- **Issue:**
  ```dockerfile
  gpg --keyserver keyserver.ubuntu.com --recv-keys FB5DB77FD5C118B80511ADA8A6310ACC4672475C
  ```
  Keyserver availability is not guaranteed. A keyserver outage causes container builds to fail. More critically, keyserver integrity cannot be fully verified — a compromised keyserver could return a wrong key.

- **Recommendation:** Embed the AWS CLI signing public key directly in the Containerfile (obtained once from a trusted source and verified by multiple team members). This eliminates the keyserver dependency and provides a deterministic build.

