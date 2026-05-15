# Security Audit — aws-nuke-cf

**Audit Date:** 2026-05-15  
**Auditor:** security-audit-agent  
**Severity Labels:** CRITICAL / HIGH / MEDIUM / LOW

---

## Finding 1 — CRITICAL: CodeBuild Role Has `AdministratorAccess` — Full Account Deletion is One Trigger Away

**File:** `template.yaml:138-142`

```yaml
CodeBuildRole:
  Type: AWS::IAM::Role
  Properties:
    ManagedPolicyArns:
      - !Sub arn:${AWS::Partition}:iam::aws:policy/AdministratorAccess
```

**Risk:**  
The CodeBuild execution role has `AdministratorAccess` attached, which grants unrestricted access to all AWS services and resources. While `SelfProtectionDenyPolicy` adds deny statements as a defense-in-depth measure, the combination is still extremely dangerous:

1. **Deny policies can be circumvented:** IAM evaluation order means explicit denies from `SelfProtectionDenyPolicy` take precedence, but the SelfProtectionDenyPolicy does **not** deny `cloudformation:CreateStack`, `iam:AssumeRole`, `ec2:RunInstances`, or most other creation/modification operations — only specific deletion and modification of the self-managed resources. An attacker who triggers a build can delete arbitrary non-protected resources.

2. **The deny policy has gaps:** `SelfProtectionDenyPolicy` denies `iam:Create*`, `iam:Put*`, `iam:Attach*` — but NOT `iam:UpdateRole`, `iam:UpdateAssumeRolePolicy`, `iam:SetDefaultPolicyVersion`, or `iam:UpdateRolePolicies`. These omissions could allow an attacker to modify existing roles to add trust relationships.

3. **The deny on `sts:AssumeRole` only applies at the policy boundary:** The CodeBuild role itself can still perform actions that aren't explicitly denied, including reading all secrets, accessing all S3 buckets, and calling any AWS API.

**Attack Vectors:**

**A. Unauthorized build trigger:**  
Any principal with `codebuild:StartBuild` on the CodeBuild project ARN can trigger a mass-deletion event. The IAM policy for who can call `codebuild:StartBuild` is not defined in this CloudFormation template — it depends on the account's IAM configuration. If the CodeBuild project ARN is discoverable (it is — it follows the `${NamePrefix}-job` pattern), a compromised account with even limited IAM permissions could escalate by triggering a build.

**B. Config file manipulation:**  
As described in Finding 2, if `ConfigSourceUrl` or the S3 nuke config can be modified, the attacker controls what aws-nuke targets for deletion. With `AdministratorAccess`, there is no IAM barrier to prevent deletion of any resource not in the self-protection filters.

**C. DryRun parameter change:**  
Any principal with `cloudformation:UpdateStack` can change `DryRun` from `"true"` to `"false"` and then trigger a build, causing real resource deletion across the account.

**What to Mitigate:**

1. **Replace `AdministratorAccess` with a purpose-built policy.** aws-nuke needs `Describe*`, `List*`, `Delete*`, and `Get*` permissions — not `Create*`, `Put*`, `Update*`, `Patch*`, or `Attach*`. A custom policy scoped to deletion operations would dramatically reduce blast radius.

2. **Require MFA or approval before live runs.** Add a CodePipeline approval gate that requires manual approval before `DryRun=false` builds are triggered.

3. **Restrict `codebuild:StartBuild` via resource-based policy or IAM.** Explicitly document and enforce who can trigger the job.

4. **Fill the gaps in SelfProtectionDenyPolicy:** Add denies for `iam:UpdateRole`, `iam:UpdateAssumeRolePolicy`, `iam:SetDefaultPolicyVersion`, `iam:CreatePolicyVersion`.

---

## Finding 2 — HIGH: Default Container Image Pinned to `:latest` — Supply Chain Risk with Admin Credentials

**File:** `template.yaml:41-44`

```yaml
ContainerImage:
  Type: String
  Default: quay.io/rrp-dev-ci/aws-nuke-cf:latest
```

**Risk:**  
The default container image uses `:latest`, which is a mutable tag. Because CodeBuild pulls this image with `ImagePullCredentialsType: CODEBUILD`, any change to the `:latest` image on `quay.io/rrp-dev-ci/aws-nuke-cf` is automatically picked up on the next build trigger.

Combined with the `AdministratorAccess` IAM role (Finding 1), a compromised image registry means an attacker can execute arbitrary code with full account admin privileges.

**Attack Vector:**
1. Attacker compromises the `rrp-dev-ci` organization on quay.io (e.g., via stolen credentials, OAuth token leakage, or social engineering).
2. Pushes a malicious image as `:latest` that exfiltrates AWS credentials or performs targeted resource deletion.
3. Next scheduled EventBridge trigger (or a manual `StartBuild`) pulls the malicious image and executes it with `AdministratorAccess`.

**What to Mitigate:**
- Pin the default to a specific digest: `quay.io/rrp-dev-ci/aws-nuke-cf@sha256:<digest>`
- Add an `AllowedPattern` to the `ContainerImage` parameter that requires a digest-pinned reference
- Use CodeBuild's capability to verify image signatures if the registry supports it

---

## Finding 3 — HIGH: `ConfigSourceUrl` Fetches Arbitrary URLs Without Integrity Verification

**File:** `template.yaml:66-72` and buildspec at line 315-317

```yaml
ConfigSourceUrl:
  Type: String
  Default: ""
  Description: >
    Optional URL to download the aws-nuke config from (e.g., a raw GitHub URL).
    When set, the config is fetched from this URL at runtime instead of S3.
```

```sh
if [ -n "$CONFIG_URL" ]; then
  echo "Downloading config from: $CONFIG_URL"
  curl -fsSL "$CONFIG_URL" -o /tmp/user-config.yml
fi
```

**Risk:**  
When `ConfigSourceUrl` is set, the buildspec downloads a YAML file from an arbitrary URL with no signature verification, no content hash check, and no allowlist validation. This file then controls what aws-nuke targets for deletion.

**Attack Vectors:**

**A. Deployment pipeline compromise:**  
If the CI/CD system that deploys or updates the CloudFormation stack is compromised, an attacker can change `ConfigSourceUrl` to a URL they control. Their config file can include the account ID (required by aws-nuke) and target critical production resources for deletion while bypassing the `_self_protection` preset by not referencing it.

**B. DNS hijacking:**  
If the URL points to a hostname that can be DNS-hijacked (e.g., a GitHub Pages URL that expires, or a raw CDN URL), an attacker who controls the DNS resolution can serve a malicious config.

**C. SSRF from config URL:**  
If the CodeBuild environment has access to AWS metadata endpoints or internal services, `CONFIG_URL` could be set to `http://169.254.169.254/latest/meta-data/iam/security-credentials/...` or other internal URLs to probe the environment. However, `curl -fsSL` would follow redirects, making this less of an immediate risk.

**What to Mitigate:**
- Require a content hash parameter alongside `ConfigSourceUrl`: `ConfigSourceUrlSHA256`
- Validate the downloaded content against the hash before using it
- Or restrict `ConfigSourceUrl` to allowed domain patterns via `AllowedPattern`
- Strongly recommend using the S3 bucket approach (default) as it provides access logging, versioning, and IAM-controlled write access

---

## Finding 4 — HIGH: YAML Configuration Injection via Shell Variable Expansion

**File:** `template.yaml` buildspec (lines ~326-376)

```sh
echo '      IAMRole:'
echo '        - type: glob'
echo "          value: \"$NAME_PREFIX-*\""
# ...
echo '      CloudFormationStack:'
echo '        - type: exact'
echo "          value: \"$STACK_NAME\""
```

**Risk:**  
The self-protection filter YAML is generated by `echo`-ing shell variables (`$NAME_PREFIX` and `$STACK_NAME`) directly into YAML without sanitization. While `NamePrefix` has an `AllowedPattern` constraint (`^[a-z][a-z0-9-]{1,20}$`) that prevents special characters, `$STACK_NAME` is the CloudFormation stack name which includes the `NamePrefix` — but CloudFormation stack names can be influenced by the deployer.

More critically, the `STACK_NAME` value is derived from `!Ref AWS::StackName`, which includes whatever the deployer named the stack. If a future deployment automation sets the stack name to a value containing YAML special characters (`:`, `{`, `}`, `[`, `]`, `#`, `*`, `&`, etc.), the generated YAML could be malformed or interpreted differently than intended.

**Attack Vector:**  
A deployer (or a compromised deployment pipeline) creates the CloudFormation stack with a name like `aws-nuke: {corrupted}`. This corrupts the self-protection YAML, potentially causing the `_self_protection` preset to fail to load, leaving the CodeBuild job with no self-protection filters active — combined with `AdministratorAccess`, this means the next `DryRun=false` run deletes the aws-nuke infrastructure itself.

**What to Mitigate:**
- Use a YAML library to generate the self-protection config file rather than shell `echo` concatenation
- Or sanitize `$STACK_NAME` and `$NAME_PREFIX` by stripping all non-alphanumeric characters before interpolation
- Add a `yamllint` or YAML parse validation step before running aws-nuke

---

## Finding 5 — MEDIUM: SNS Topic Policy Allows Any EventBridge Rule to Publish (Missing Source Condition)

**File:** `template.yaml:515-521`

```yaml
FailureNotificationTopicPolicy:
  PolicyDocument:
    Statement:
      - Sid: AllowEventBridgePublish
        Effect: Allow
        Principal:
          Service: events.amazonaws.com
        Action: sns:Publish
        Resource: !Ref FailureNotificationTopic
```

**Risk:**  
The SNS topic policy allows any EventBridge rule in the account (or potentially cross-account if EventBridge bus policies are permissive) to publish to the failure notification topic. There is no `aws:SourceArn` condition to restrict this to the specific EventBridge rule created by this stack.

**Attack Vector:**  
Any EventBridge rule in the account that targets this SNS topic ARN can publish arbitrary messages to subscribers. An attacker who can create EventBridge rules (a common permission in many dev/ops roles) can spam the notification email with fake failure alerts, causing alert fatigue, or potentially exploiting SNS subscriber endpoints if the subscriber is a webhook (not just email).

**What to Mitigate:**
Add a `Condition` to the SNS policy statement:
```yaml
Condition:
  ArnLike:
    aws:SourceArn: !GetAtt FailureNotificationRule.Arn
```

---

## Finding 6 — MEDIUM: No Secondary Approval Gate for Live Deletion Mode

**File:** `template.yaml:32-38` (DryRun parameter)

```yaml
DryRun:
  Type: String
  Default: "true"
  AllowedValues: ["true", "false"]
  Description: >
    When true, aws-nuke lists resources but does NOT delete them.
    Set to false to enable actual deletion. USE WITH CAUTION.
```

**Risk:**  
The `DryRun` parameter can be changed from `"true"` to `"false"` via a single CloudFormation stack update with no additional confirmation, approval gate, or MFA requirement. Any principal with `cloudformation:UpdateStack` on this stack can enable live deletion mode and immediately trigger a build.

Combined with the `AdministratorAccess` policy (Finding 1), this represents a one-step path to large-scale resource deletion in the account.

**What to Mitigate:**
- Add a CloudFormation stack policy that prevents updates to the `DryRun` parameter without explicit override
- Or implement a CodePipeline approval stage before live runs
- Or use AWS Config Rules to detect and alert when `DryRun=false` is set
- At minimum, require MFA in the IAM policy for `cloudformation:UpdateStack` on this specific stack
