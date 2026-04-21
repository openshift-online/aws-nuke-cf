# aws-nuke-cf

This project deploys a periodic [aws-nuke](https://github.com/ekristen/aws-nuke) job into AWS accounts using **CloudFormation**.

## Key Files

- `template.yaml` — Single CloudFormation template containing all resources (S3, CodeBuild, IAM, EventBridge, SNS)
- `Makefile` — Deployment helpers (`make deploy`, `make run`, `make logs`, etc.)
- `Containerfile` — Container image build (UBI9 base, aws-nuke + AWS CLI)
- `examples/nuke-config.yml` — Example aws-nuke configuration
- `security/adversary.md` — Security audit report (adversary scan findings)
- `aws-nuke/` — Git submodule of [ekristen/aws-nuke](https://github.com/ekristen/aws-nuke) (for analysis)

## Architecture

EventBridge Rule (cron) → CodeBuild Project → aws-nuke (downloaded binary)

- CodeBuild uses a custom container image (default: `quay.io/rrp-dev-ci/ci-image`) with aws-nuke and AWS CLI pre-installed
- User's nuke config is stored in S3 and downloaded at runtime
- A shell script (sed/awk) auto-injects self-protection filters before running aws-nuke

## Self-Protection (3 layers)

1. **Config filters** — `_self_protection` preset injected at runtime with `__global__` tag filters + resource-specific name filters
2. **IAM deny** — Explicit deny policy on ARN patterns matching `${NamePrefix}-*` for IAM, S3, CodeBuild, EventBridge, Logs, SNS, and CloudFormation
3. **Resource tagging** — All resources tagged with `aws-nuke:managed=true`

## Validation

```bash
aws cloudformation validate-template --template-body file://template.yaml
```

## Deployment

```bash
make deploy CONFIG=examples/nuke-config.yml
make run    # manual trigger
make logs   # view logs
```

## Security Audit

A security audit report is maintained at `security/adversary.md`. It covers:

- IAM permission scope and self-protection deny policy gaps
- Container image pinning and supply chain integrity
- S3 config trust boundary and self-protection bypass vectors
- Encryption at rest for SNS and CloudWatch Logs
- Container runtime security (root user, image pull credentials)

### Known Security Considerations

- **AdministratorAccess** is attached to the CodeBuild role — required for aws-nuke but high blast radius if the build environment is compromised
- **Container image** (`ContainerImage` parameter) defaults to `:latest` tag — should be pinned to a digest for production use
- **AWS CLI download** in the Containerfile lacks checksum/signature verification (unlike the aws-nuke binary which is checksum-verified)
- **S3 config poisoning** — a malicious config could define its own `_self_protection` preset to override the injected one; the prebuild script should reject configs containing that key
- **Self-protection deny policy** does not cover IAM instance profiles or prevent credential creation (`iam:CreateAccessKey`) on arbitrary resources
- **SNS topic and CloudWatch Logs** are not encrypted with KMS
- **Containerfile** runs as root (no `USER` directive)
