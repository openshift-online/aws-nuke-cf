# aws-nuke-cf

Automated periodic AWS account cleanup using [aws-nuke](https://github.com/ekristen/aws-nuke), deployed as a single CloudFormation stack.

## Architecture

```
EventBridge Rule (cron/rate)
        |
        v
CodeBuild Project
        |
        +-- Downloads aws-nuke binary
        +-- Downloads your config from S3
        +-- Injects self-protection filters
        +-- Runs aws-nuke (dry-run by default)
        +-- Logs to CloudWatch
```

## Prerequisites

- AWS CLI v2 configured with credentials
- Target account must have an **account alias** configured:
  ```bash
  aws iam create-account-alias --account-alias my-sandbox
  ```
- GNU Make (optional, for Makefile helpers)

## Quick Start

```bash
# 1. Clone
git clone https://github.com/typeid/aws-nuke-cf.git
cd aws-nuke-cf

# 2. Edit the example config with your account ID and filters
cp examples/nuke-config.yml my-config.yml
# Edit my-config.yml: set your account ID, blocklist, regions, filters

# 3. Deploy (dry-run mode by default)
make deploy CONFIG=my-config.yml

# 4. Trigger a manual run to verify
make run
make logs
```

## Configuration

### CloudFormation Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `NamePrefix` | `aws-nuke` | Prefix for all resource names |
| `ScheduleExpression` | `cron(0 3 ? * SUN *)` | EventBridge schedule (`cron(0 2 ? * MON-FRI *)`, `rate(1 day)`, etc.) |
| `ScheduleState` | `ENABLED` | `ENABLED` or `DISABLED` |
| `DryRun` | `true` | `true` = list only, `false` = actually delete resources |
| `AwsNukeVersion` | `v3.64.1` | [aws-nuke release version](https://github.com/ekristen/aws-nuke/releases) |
| `LogRetentionDays` | `30` | CloudWatch Logs retention (days) |
| `BuildTimeoutMinutes` | `120` | CodeBuild timeout (max 480) |
| `NotificationEmail` | *(empty)* | Email for failure alerts (creates SNS topic if set) |

### Passing Parameters

```bash
# Via Makefile
make deploy CONFIG=my-config.yml DRY_RUN=false

# Via AWS CLI directly
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name aws-nuke \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ScheduleExpression="cron(0 3 ? * SUN *)" \
    DryRun=false \
    NotificationEmail=team@example.com
```

### Default Tags

Pass tags via the Makefile or AWS CLI. These propagate to all taggable resources:

```bash
# Via Makefile
make deploy TAGS="Team=Platform Environment=sandbox CostCenter=12345"

# Via AWS CLI
aws cloudformation deploy \
  --template-file template.yaml \
  --stack-name aws-nuke \
  --capabilities CAPABILITY_NAMED_IAM \
  --tags Team=Platform Environment=sandbox
```

## Writing Your Nuke Config

See [`examples/nuke-config.yml`](examples/nuke-config.yml) for a full example.

Key sections:

```yaml
# Accounts that must NEVER be nuked
blocklist:
  - "999999999999"  # production

# Regions to scan
regions:
  - us-east-1
  - global

# Per-account config
accounts:
  "123456789012":  # your sandbox account ID
    filters:
      EC2Instance:
        - property: tag:Name
          value: "keep-this-instance"
```

**You do NOT need to add self-protection filters.** The system automatically injects a `_self_protection` preset at runtime that prevents aws-nuke from deleting the stack's own resources.

Full config reference: https://ekristen.github.io/aws-nuke/config/

### Updating the Config

After changing your config file, re-upload it:

```bash
make upload-config CONFIG=my-config.yml
```

No stack update needed -- the config is read from S3 at each run.

## Self-Protection

Three layers prevent the job from deleting its own infrastructure:

### Layer 1: Config Filters (Application Level)
A `_self_protection` preset is auto-injected at runtime with:
- `__global__` filters matching the `aws-nuke:managed` tag
- Resource-specific name filters for IAM roles, S3 buckets, CodeBuild projects, EventBridge rules, etc.

### Layer 2: IAM Deny (AWS Level)
The CodeBuild role includes explicit deny statements on ARN patterns matching `${NamePrefix}-*` for IAM roles/policies, S3 config bucket, CodeBuild projects, EventBridge rules, CloudWatch log groups, SNS topics, and the CloudFormation stack itself.

Even if a bug in aws-nuke bypasses config filters, IAM prevents deletion.

### Layer 3: Resource Tagging
All stack resources are tagged with `aws-nuke:managed=true`, linking Layers 1 and 2.

## Operations

```bash
make help           # Show all available commands
make validate       # Validate the CloudFormation template
make deploy         # Deploy/update stack + upload config
make upload-config  # Upload config only (no stack update)
make run            # Manually trigger a build
make logs           # Tail the latest build logs
make status         # Show stack and latest build status
make destroy        # Delete the stack (S3 bucket retained)
```

### Going Live (Disabling Dry-Run)

1. Deploy in dry-run mode first and verify the output:
   ```bash
   make deploy CONFIG=my-config.yml
   make run
   make logs  # Review what WOULD be deleted
   ```

2. Once satisfied, switch to live mode:
   ```bash
   make deploy DRY_RUN=false
   ```

3. To revert to dry-run:
   ```bash
   make deploy DRY_RUN=true
   ```

## Security

- **IAM**: The CodeBuild role uses AdministratorAccess so aws-nuke can discover and delete any resource type. Self-managed resources are protected by explicit ARN-based deny statements that override the admin policy.
- **S3**: Config bucket is encrypted (AES256), versioned, and blocks all public access
- **Logging**: All aws-nuke output goes to CloudWatch Logs with configurable retention
- **Dry-run default**: No resources are deleted until you explicitly set `DryRun=false`

### Security Audit

A full adversary security scan is available at [`security/adversary.md`](security/adversary.md). Key findings and recommendations:

| Severity | Finding | Status |
|----------|---------|--------|
| **CRITICAL** | AdministratorAccess on CodeBuild role — full account blast radius if build is compromised | Known trade-off (required for aws-nuke) |
| **CRITICAL** | Self-protection deny policy does not prevent credential creation on arbitrary IAM resources | Open |
| **HIGH** | Default container image uses `:latest` tag — mutable, supply-chain risk | Open |
| **HIGH** | CodeBuild `ImagePullCredentialsType: CODEBUILD` may not work with quay.io | Open |
| **HIGH** | AWS CLI download in Containerfile lacks integrity verification | Open |
| **HIGH** | S3 config can define `_self_protection` preset to override injected filters | Open |
| **MEDIUM** | Containerfile runs as root (no `USER` directive) | Open |
| **MEDIUM** | SNS failure topic not encrypted with KMS | Open |
| **MEDIUM** | CloudWatch Logs not encrypted with KMS | Open |
| **MEDIUM** | Unquoted `$FLAGS` variable in build script | Open |
| **LOW** | Dependabot only covers Docker ecosystem | Open |

### Hardening Recommendations

Before going to production, consider:

1. **Pin the container image** to a digest (`@sha256:...`) instead of `:latest`
2. **Add integrity verification** for the AWS CLI download in the Containerfile
3. **Reject user configs** that contain `_self_protection` to prevent filter override
4. **Add a non-root USER** to the Containerfile
5. **Enable KMS encryption** on SNS topics and CloudWatch Logs
6. **Add IAM deny** for `iam:CreateAccessKey` and `iam:CreateLoginProfile` on `*` to prevent credential creation if the build is compromised

## Cost

Estimated monthly cost for a weekly run (~30 min each):

| Resource | Cost |
|----------|------|
| CodeBuild (4x 30min, small instance) | ~$0.60 |
| S3 (config storage) | < $0.01 |
| CloudWatch Logs (30 day retention) | ~$0.50 |
| EventBridge | Free tier |
| **Total** | **~$1-2/month** |

## Uninstalling

```bash
make destroy
```

The S3 config bucket is retained (to prevent accidental config loss). To fully remove:

```bash
BUCKET=$(aws cloudformation describe-stacks --stack-name aws-nuke \
  --query 'Stacks[0].Outputs[?OutputKey==`ConfigBucketName`].OutputValue' --output text)
aws s3 rb s3://$BUCKET --force
```

## License

Apache License 2.0. See [LICENSE](LICENSE).
