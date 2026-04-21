## Security Review

**Files Reviewed:** 7 (2 critical, 3 high risk)

| Risk | Files |
|------|-------|
| Critical | `template.yaml` (IAM, CodeBuild, self-protection), `examples/nuke-config.yml` |
| High | `Containerfile`, `Makefile`, `.github/dependabot.yml` |
| Medium | `.gitmodules` |
| Low | `README.md`, `LICENSE`, `OWNERS` |

### Findings

---

**[CRITICAL] AdministratorAccess attached to CodeBuild role**

- **File:** `template.yaml:128`
- **Category:** `Infrastructure - Overly Permissive IAM`
- **Issue:** The CodeBuild execution role has the AWS-managed `AdministratorAccess` policy attached. While this is functionally required for aws-nuke to discover and delete arbitrary resource types, it grants unrestricted `*:*` permissions to the build environment.
- **Impact:** If the build environment is compromised (e.g., via a malicious container image or tampered nuke config), the attacker gains full admin access to the AWS account. The self-protection deny policy only protects the stack's own resources — all other account resources are fully exposed.
- **Recommendation:** Consider scoping the allow policy to only the resource types you actually intend to nuke (`ec2:*`, `s3:*`, `lambda:*`, etc.), or at minimum add explicit deny statements for the most dangerous actions (`iam:CreateUser`, `iam:CreateAccessKey`, `sts:AssumeRole` to external accounts, `organizations:*`). If full admin is truly required, add a condition key restricting usage to the CodeBuild source IP range or VPC.

---

**[CRITICAL] Self-protection deny policy does not cover IAM instance profiles**

- **File:** `template.yaml:182-187`
- **Category:** `Infrastructure - Self-Protection Bypass`
- **Issue:** The `DenyIAMSelf` statement covers `arn:...iam::ACCOUNT:role/${NamePrefix}-*` and `arn:...iam::ACCOUNT:policy/${NamePrefix}-*`, but does not cover `arn:...iam::ACCOUNT:instance-profile/${NamePrefix}-*`. More critically, it does not prevent `iam:PutRolePolicy`, `iam:AttachRolePolicy`, or `iam:DetachRolePolicy` on roles outside the `${NamePrefix}-*` pattern. aws-nuke could delete IAM policies or roles that are not name-prefixed but are still critical to the account.
- **Impact:** If aws-nuke's config filter injection fails or is bypassed, the deny policy has gaps that could allow deletion of account-critical IAM resources not matching the name prefix.
- **Recommendation:** The IAM deny uses `iam:*` which is broad and correct for the matching resources. However, consider adding a deny for `iam:CreateAccessKey` and `iam:CreateLoginProfile` on `*` (all resources) to prevent credential creation even if the build is compromised.

---

**[HIGH] Unpinned container image — `:latest` tag as default**

- **File:** `template.yaml:42`
- **Category:** `Container - Image Pinning`
- **Issue:** The `ContainerImage` parameter defaults to `quay.io/rrp-dev-ci/ci-image:latest`. The `:latest` tag is mutable — anyone with push access to that registry can replace it with a malicious image that runs arbitrary code with AdministratorAccess.
- **Impact:** A supply-chain attack on the container registry gives an attacker full admin access to the AWS account. Since CodeBuild pulls this image before every build, a poisoned image would be picked up on the next scheduled or manual run.
- **Recommendation:** Pin the default to a specific digest:
  ```yaml
  Default: quay.io/rrp-dev-ci/ci-image@sha256:<digest>
  ```
  Or at minimum pin to a versioned tag (e.g., `ci-image:v1.2.3`). The Containerfile already pins its base image by digest — apply the same discipline here.

---

**[HIGH] CodeBuild uses `CODEBUILD` image pull credentials for external registry**

- **File:** `template.yaml:251`
- **Category:** `Infrastructure - Container Pull Authentication`
- **Issue:** `ImagePullCredentialsType: CODEBUILD` is designed for ECR and Docker Hub. The default image is on `quay.io`, which is an external registry. If `quay.io` requires authentication or the image is private, pulls will fail silently or fall back to an unexpected public image.
- **Impact:** Build failures or, worse, pulling an unintended public image with the same name from a different registry namespace.
- **Recommendation:** If using a private quay.io image, switch to `ImagePullCredentialsType: SERVICE_ROLE` and store registry credentials in Secrets Manager, referenced via `RegistryCredential`. If the image is public, document this explicitly and consider mirroring to ECR for reliability.

---

**[HIGH] AWS CLI download in Containerfile lacks integrity verification**

- **File:** `Containerfile:24-27`
- **Category:** `Container - Supply Chain`
- **Issue:** The AWS CLI v2 zip is downloaded via `curl` and installed without any checksum or signature verification. The aws-nuke binary download on lines 38-40 correctly verifies checksums, but the AWS CLI installation does not.
- **Impact:** A MITM or compromised CDN could inject a trojanized AWS CLI into the container image. Since this CLI runs with AdministratorAccess, the blast radius is full account compromise.
- **Recommendation:** Verify the AWS CLI download using the `.sig` file and AWS's PGP key:
  ```dockerfile
  RUN curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${AWS_ARCH}-${AWS_CLI_VERSION}.zip.sig" -o "awscliv2.zip.sig" && \
      gpg --verify awscliv2.zip.sig awscliv2.zip
  ```
  Or use the SHA256 checksum published by AWS.

---

**[HIGH] S3 config poisoning can bypass self-protection**

- **File:** `template.yaml:285-292`
- **Category:** `Application - Trust Boundary`
- **Issue:** The nuke config is downloaded from S3 at runtime (`aws s3 cp "s3://${CONFIG_BUCKET}/nuke-config.yml"`). The self-protection preset is injected by appending to this config and using `awk` to add `_self_protection` to each account's presets list. However, if a malicious actor with S3 write access crafts a config that defines its own `_self_protection` preset (overriding the injected one) or uses YAML anchors/aliases to suppress the injected filters, the protection can be neutralized.
- **Impact:** A compromised S3 config could disable self-protection filters, causing aws-nuke (running with admin access) to delete the stack's own infrastructure, leading to loss of the scheduled job and its safety controls.
- **Recommendation:** The prebuild script should validate that no user-supplied `_self_protection` preset exists in the downloaded config before injection. Add a check:
  ```bash
  if grep -q '_self_protection' /tmp/user-config.yml; then
    echo "ERROR: Config must not define _self_protection preset"
    exit 1
  fi
  ```

---

**[MEDIUM] Containerfile runs as root**

- **File:** `Containerfile:1-44`
- **Category:** `Container - Least Privilege`
- **Issue:** The Containerfile never sets a `USER` directive. The container runs all processes (including aws-nuke) as root. By contrast, the upstream aws-nuke Dockerfile (`aws-nuke/Dockerfile:19`) correctly sets `USER aws-nuke`.
- **Impact:** If there is a container escape vulnerability, the attacker gains root on the host. Running as a non-root user limits the blast radius.
- **Recommendation:** Add a non-root user and switch to it:
  ```dockerfile
  RUN useradd -r -s /sbin/nologin aws-nuke
  USER aws-nuke
  ```

---

**[MEDIUM] SNS topic not encrypted**

- **File:** `template.yaml:436-440`
- **Category:** `Infrastructure - Encryption at Rest`
- **Issue:** The `FailureNotificationTopic` SNS topic does not specify a `KmsMasterKeyId`. Messages (which may contain build failure details including account IDs and resource names) are not encrypted at rest.
- **Impact:** Sensitive account metadata in failure notifications is stored unencrypted in SNS.
- **Recommendation:** Add KMS encryption:
  ```yaml
  KmsMasterKeyId: alias/aws/sns
  ```

---

**[MEDIUM] CloudWatch Logs not encrypted**

- **File:** `template.yaml:104-111`
- **Category:** `Infrastructure - Encryption at Rest`
- **Issue:** The `LogGroup` does not specify a `KmsKeyId`. Build logs, which contain full aws-nuke output listing all discovered resources and their deletion status, are stored with default encryption only.
- **Impact:** Detailed inventory of all AWS resources in the account is available in unencrypted logs. This is sensitive reconnaissance data.
- **Recommendation:** Add a KMS key:
  ```yaml
  KmsKeyId: !GetAtt LogEncryptionKey.Arn
  ```

---

**[MEDIUM] Build script uses unquoted variable expansion**

- **File:** `template.yaml:371`
- **Category:** `Application - Shell Injection`
- **Issue:** `aws-nuke run --config /tmp/nuke-config.yml $FLAGS` uses unquoted `$FLAGS`. While `FLAGS` is set internally and not from user input, this is a shell best-practice violation. If `FLAGS` ever contains spaces or glob characters, word splitting could cause unexpected behavior.
- **Impact:** Low in current form (FLAGS is hardcoded), but fragile if modified.
- **Recommendation:** Quote the variable: `aws-nuke run --config /tmp/nuke-config.yml "$FLAGS"` — or better, use an array.

---

**[LOW] Dependabot only covers Docker ecosystem**

- **File:** `.github/dependabot.yml:1-6`
- **Category:** `Supply Chain - Incomplete Coverage`
- **Issue:** Dependabot is configured only for the `docker` ecosystem. If GitHub Actions workflows are added in the future, they won't be covered by dependency update scanning.
- **Impact:** Minimal currently since there are no GitHub Actions workflows. Future risk only.
- **Recommendation:** Add a `github-actions` ecosystem entry when workflows are added.

---

### Domains Not Analyzed

| Domain | Reason |
|--------|--------|
| Kubernetes | No K8s manifests found |
| Agent/Skill | No agent definitions found |
| OpenSSF Scorecard | API returned 404 for `ekristen/aws-nuke` — project not indexed |

### Summary

| Severity | Count |
|----------|-------|
| CRITICAL | 2 |
| HIGH | 4 |
| MEDIUM | 4 |
| LOW | 1 |

The most significant risks center on the **AdminAccess + unpinned container image** combination — a supply-chain compromise of the container image grants full account admin. The self-protection deny policy is well-designed but has **bypassable gaps** via S3 config poisoning. The Containerfile's AWS CLI download lacks integrity verification, unlike the aws-nuke binary download which correctly checks checksums.
