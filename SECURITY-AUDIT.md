# Security Audit — aws-nuke-cf

**Audit Date:** 2026-06-15
**Auditor:** security-audit-agent (automated)
**Scope:** Full static analysis of CloudFormation template, Containerfile, Makefile, example configs
**Previous PRs:** #11, #12, #13 (superseded by this report)

> This PR supersedes all previous security audit PRs (#11, #12, #13). No previous user comments dismissed any findings, so all carry-over findings remain active. Findings that were new in prior audits and remain unaddressed are marked **(carry-over, unresolved)**.

---

## CRITICAL Findings

### CRIT-1 — CodeBuild Role Has `AdministratorAccess` — Entire Account Rests on Deny-List Completeness **(carry-over, unresolved)**

**File:** `template.yaml` lines 138–142

```yaml
ManagedPolicyArns:
  - !Sub arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess
```

**Risk:** The protection model is inverted: the role can do everything by default, and safety depends entirely on an explicit deny list that must be exhaustive. AWS adds new IAM actions regularly. Any newly added action not in the deny list is immediately available to the CodeBuild role.

**Attack vectors:**
1. A new AWS IAM action (e.g., `organizations:RegisterDelegatedAdministrator`) is added by AWS and omitted from the deny list. Arbitrary code running in CodeBuild can call it.
2. Any code execution path in the build (compromised nuke binary, malicious container image, injected config) operates with full administrative access with no capability constraints.
3. A developer with `codebuild:StartBuild` permission triggers a live run — the role's `AdministratorAccess` means the nuke job can delete anything in the account.

**What to mitigate:** Replace `AdministratorAccess` with an explicit allow list of only the IAM actions aws-nuke requires: `Describe*`, `List*`, `Get*`, `Delete*`, and `Terminate*` on specific resource types. AWS Access Analyzer with policy generation (from CloudTrail) can derive the minimum required set.

---

### CRIT-2 — Missing `iam:PassRole` Denial Enables Privilege Escalation Out of the aws-nuke Sandbox **(carry-over, unresolved)**

**File:** `template.yaml` `DenyDangerousActions` (lines ~193–230)

**Risk:** `iam:PassRole` is absent from the deny list. Any code running in the CodeBuild build that has a shell (aws-nuke config embeds shell commands; the base image has bash) can:

1. Create an AWS Lambda function (`lambda:CreateFunction` is not denied).
2. Pass the CodeBuild role to that Lambda using `iam:PassRole`.
3. Invoke the Lambda with arbitrary code.
4. The Lambda executes with `AdministratorAccess` — **outside the aws-nuke process, immune to aws-nuke's own filters**.

**What to mitigate:** Add to the deny policy:
```yaml
- Sid: DenyPrivilegeEscalation
  Effect: Deny
  Action:
    - iam:PassRole
    - lambda:CreateFunction
    - lambda:UpdateFunctionCode
    - glue:CreateJob
  Resource: "*"
```

---

### CRIT-3 — TOCTOU Race: Config Is Validated Then Modified In-Place Before Execution **(carry-over, unresolved)**

**File:** `template.yaml` buildspec (validation at ~line 321, modification ~lines 379–393, execution ~line 406)

**Risk:** The buildspec (1) validates the config by grep-checking it, then (2) modifies it in-place with `sed -i` and `awk`, then (3) executes aws-nuke against the modified file. A write to `/tmp/nuke-config.yml` between steps 2 and 3 (possible from a second process in the same CodeBuild environment) could substitute an umodified or malicious config after protection filters are injected.

**What to mitigate:** After injecting the self-protection preset, write the config to a new file in a mode-700 temporary directory. Never modify the original in-place. Execute aws-nuke only against the immutable, post-injection copy stored in a directory inaccessible to other processes.

---

## HIGH Findings

### HIGH-1 — Default Container Image Pinned to `:latest` — Combined with AdministratorAccess This Is Supply Chain Critical **(carry-over, unresolved)**

**File:** `template.yaml` lines 41–44

```yaml
ContainerImage:
  Type: String
  Default: quay.io/rrp-dev-ci/aws-nuke-cf:latest
```

**Risk:** The default image uses a mutable `:latest` tag. Combined with `AdministratorAccess`, a compromised push to `quay.io/rrp-dev-ci/aws-nuke-cf` allows an attacker to run arbitrary code with full account admin access at the next scheduled build.

**Attack vector:** Attacker compromises the `rrp-dev-ci` quay.io organization credential (credential stuffing, phishing, token theft), pushes a malicious image, waits for the next Sunday 3am EventBridge trigger. Malicious code runs with `AdministratorAccess`.

**What to mitigate:** Pin the default to a SHA256 digest: `quay.io/rrp-dev-ci/aws-nuke-cf@sha256:<hash>`. Add an `AllowedPattern` to the parameter enforcing digest-only references. The `Containerfile` itself properly pins binary checksums — apply the same rigor to the CloudFormation parameter default.

---

### HIGH-2 — `ConfigSourceUrl` Fetches Arbitrary URLs Without Integrity Verification **(carry-over, unresolved)**

**File:** `template.yaml` buildspec (`curl -fsSL "$CONFIG_URL"`)

**Risk:** When `ConfigSourceUrl` is set, the buildspec fetches that URL and executes it as an aws-nuke configuration with no HTTPS enforcement, no content signature, and no checksum verification. An attacker who can MITM the URL, poison DNS for the target hostname, or redirect via an HTTP redirect chain can substitute a malicious config that targets production resources.

**Attack vectors:**
1. HTTP `ConfigSourceUrl` (no HTTPS enforcement): MITM attack substitutes config targeting production resources.
2. DNS poisoning of the target hostname: Even HTTPS URLs can be targeted if the attacker can serve a valid certificate for the domain.
3. CloudFormation parameter injection: Any operator with `cloudformation:UpdateStack` can change `ConfigSourceUrl` to point at an attacker-controlled YAML file.

**What to mitigate:** Enforce HTTPS in the buildspec (`if [[ ! "$CONFIG_URL" =~ ^https:// ]]; then exit 1; fi`). Add a `ConfigSourceSHA256` parameter: after downloading, verify `sha256sum -c` before using the file.

---

### HIGH-3 — `SelfProtectionDenyPolicy` Does Not Block IAM Role Trust Policy Updates **(NEW)**

**File:** `template.yaml` `SelfProtectionDenyPolicy`

**Risk:** The deny policy blocks `iam:Create*`, `iam:Put*`, and `iam:Attach*` — but does NOT deny:
- `iam:UpdateAssumeRolePolicy` — modifies which principals can assume a role
- `iam:UpdateRole` — modifies role description and max session duration  
- `iam:SetDefaultPolicyVersion` — could activate a previously unused policy version

Any code running in the CodeBuild build can call `iam:UpdateAssumeRolePolicy` on the `${NamePrefix}-codebuild-role` itself and add a new trusted principal (e.g., a role in an external account), enabling persistent backdoor access even if the CloudFormation stack is later cleaned up.

**What to mitigate:** Add to the `DenyDangerousActions` policy:
```yaml
- iam:UpdateAssumeRolePolicy
- iam:UpdateRole
- iam:SetDefaultPolicyVersion
- sts:GetFederationToken
- sts:GetSessionToken
```

---

### HIGH-4 — Sensitive Data Exfiltration Not Blocked: Secrets, SSM Parameters, S3 Writes **(carry-over, unresolved)**

**File:** `template.yaml` `SelfProtectionDenyPolicy`

**Risk:** The deny policy prevents aws-nuke from deleting its own infrastructure but does NOT prevent:
- `secretsmanager:GetSecretValue` — reads all Secrets Manager secrets in the account
- `ssm:GetParameter`, `ssm:GetParametersByPath` — reads all SSM parameters (including SecureString)
- `s3:PutObject` on arbitrary buckets — can exfiltrate data to any S3 bucket (including attacker-controlled cross-account buckets)
- `ec2:CreateSnapshot`, `ec2:CopySnapshot` — enables EBS data exfiltration

Code running in the CodeBuild environment (compromised container, malicious nuke config embedding shell) can call these actions to exfiltrate all account secrets and data.

**What to mitigate:** Add explicit denies for these actions in the `SelfProtectionDenyPolicy`. For `s3:PutObject`, deny all except the config bucket. For `secretsmanager` and `ssm`, add blanket denies.

---

## MEDIUM Findings

### MED-1 — SNS Topic Policy Lacks `aws:SourceArn` Condition **(NEW)**

**File:** `template.yaml` `FailureNotificationTopicPolicy`

```yaml
- Sid: AllowEventBridgePublish
  Effect: Allow
  Principal:
    Service: events.amazonaws.com
  Action: sns:Publish
  Resource: !Ref FailureNotificationTopic
```

**Risk:** This policy allows **any EventBridge rule in any AWS account or region** with access to this SNS topic to publish to it. Without an `aws:SourceArn` condition scoping it to the specific EventBridge rule, other EventBridge rules in the account (or cross-account via resource-based policies) could spam or inject messages into the failure notification topic.

**What to mitigate:** Add a source ARN condition:
```yaml
Condition:
  ArnLike:
    aws:SourceArn: !Sub arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:rule/${NamePrefix}-*
```

---

### MED-2 — `ScheduleExpression` Parameter Has No Rate Limit Validation **(NEW)**

**File:** `template.yaml` lines 22–28

**Risk:** The `ScheduleExpression` parameter accepts any EventBridge schedule expression with no validation that the rate is reasonable. An operator with `cloudformation:UpdateStack` permission could set `rate(1 minute)`, causing aws-nuke to run 1,440 times per day. Even in dry-run mode this is wasteful; in live mode with any account resources it could cause rapid resource exhaustion.

**What to mitigate:** Add parameter validation or documentation warning against sub-hourly schedules. Consider adding a CloudFormation stack policy preventing parameter updates to DryRun and ScheduleExpression without explicit override.

---

### MED-3 — Buildspec Inlines Entire Execution Logic — No Defense Against Config Injection Into Bash Here-Docs **(NEW)**

**File:** `template.yaml` buildspec (inline `cat > /tmp/prebuild.sh << 'PREBUILDEOF' ... PREBUILDEOF`)

**Risk:** The buildspec writes bash scripts to disk using heredocs. The content of these scripts is fully static (no user variables interpolated), which is correct. However, the self-protection injection section uses:
```bash
echo "          value: \"$STACK_NAME\""
echo "          value: \"$NAME_PREFIX-*\""
```
If `$STACK_NAME` or `$NAME_PREFIX` contain YAML special characters (quotes, colons, newlines), the injected YAML will be malformed. While the `NamePrefix` parameter has an `AllowedPattern` constraint (`^[a-z][a-z0-9-]{1,20}$`), `$STACK_NAME` could differ from `$NAME_PREFIX` if the stack was deployed with a non-default name, and CloudFormation stack names allow characters that break the echo-based YAML injection.

**What to mitigate:** Use `python3 -c` or `yq` to inject values as proper YAML scalars rather than shell echoes.
