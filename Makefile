STACK_NAME     ?= aws-nuke
TEMPLATE       ?= template.yaml
CONFIG         ?= examples/nuke-config.yml
REGION         ?= $(shell aws configure get region 2>/dev/null || echo us-east-1)
TAGS           ?=
DRY_RUN        ?= true
SCHEDULE       ?= cron(0 3 ? * SUN *)
IMAGE          ?=
YES            ?=
CONFIG_URL     ?=
CAPABILITIES   := CAPABILITY_NAMED_IAM

# Build --tags flag from TAGS variable (space-separated Key=Value pairs)
# Usage: make deploy TAGS="Team=Platform Environment=sandbox"
ifdef TAGS
  CFN_TAGS := --tags $(TAGS)
else
  CFN_TAGS :=
endif

.PHONY: help validate deploy upload-config run logs status destroy

help: ## Show available targets
	@echo "Usage: make <target> [VAR=value ...]"
	@echo ""
	@echo "\033[1mLifecycle\033[0m"
	@echo "  \033[36mdeploy\033[0m            Deploy the stack and upload the nuke config"
	@echo "  \033[36mdestroy\033[0m           Delete the stack (S3 bucket is retained)"
	@echo ""
	@echo "\033[1mOperations\033[0m"
	@echo "  \033[36mupload-config\033[0m     Upload the nuke config to S3 (no stack update)"
	@echo "  \033[36mrun\033[0m               Manually trigger the aws-nuke job"
	@echo "  \033[36mlogs\033[0m              Tail the latest build logs"
	@echo "  \033[36mstatus\033[0m            Show stack and latest build status"
	@echo ""
	@echo "\033[1mDevelopment\033[0m"
	@echo "  \033[36mvalidate\033[0m          Validate the CloudFormation template"
	@echo ""
	@echo "\033[1mOverrides\033[0m"
	@echo "  STACK_NAME=name      Stack name              (default: $(STACK_NAME))"
	@echo "  CONFIG=path          Nuke config file        (default: $(CONFIG))"
	@echo "  REGION=region        AWS region              (default: $(REGION))"
	@echo "  DRY_RUN=bool         Dry-run mode            (default: $(DRY_RUN))"
	@echo "  SCHEDULE=expr        Run schedule            (default: $(SCHEDULE))"
	@echo "  CONFIG_URL=url       Fetch config from URL   (default: use S3)"
	@echo "  TAGS='K=V ...'       Stack tags              (default: none)"
	@echo ""
	@echo "\033[1mExamples\033[0m"
	@echo "  make deploy CONFIG=my-config.yml"
	@echo "  make deploy DRY_RUN=false TAGS=\"Team=Platform Environment=sandbox\""
	@echo "  make deploy SCHEDULE=\"cron(0 3 ? * SUN *)\" REGION=eu-west-1"
	@echo "  make run"
	@echo "  make deploy CONFIG_URL=https://raw.githubusercontent.com/org/repo/main/nuke-config.yaml"
	@echo "  make logs"

validate: ## Validate the CloudFormation template
	@aws cloudformation validate-template \
		--template-body file://$(TEMPLATE) \
		--region $(REGION) > /dev/null
	@echo "Template is valid."

deploy: validate ## Deploy the stack and upload the nuke config
	@IDENTITY=$$(aws sts get-caller-identity --region $(REGION) --output json) && \
	ACCOUNT=$$(echo "$$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])") && \
	ARN=$$(echo "$$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])") && \
	ALIAS=$$(aws iam list-account-aliases --query 'AccountAliases[0]' --output text 2>/dev/null || echo "") && \
	if [ -z "$$ALIAS" ] || [ "$$ALIAS" = "None" ]; then \
		echo ""; \
		echo "  Account:  $$ACCOUNT"; \
		echo "  Identity: $$ARN"; \
		echo ""; \
		echo "  ERROR: This account has no account alias set."; \
		echo "  aws-nuke requires an account alias as a safety measure — it refuses"; \
		echo "  to nuke accounts without one. Set an alias with:"; \
		echo ""; \
		echo "    aws iam create-account-alias --account-alias my-sandbox"; \
		echo ""; \
		exit 1; \
	fi && \
	echo "" && \
	echo "  Account:  $$ACCOUNT ($$ALIAS)" && \
	echo "  Identity: $$ARN" && \
	echo "  Region:   $(REGION)" && \
	echo "" && \
	echo "  Stack:    $(STACK_NAME)" && \
	$(if $(CONFIG_URL),echo "  Config:   $(CONFIG_URL) (URL)",echo "  Config:   $(CONFIG) (S3)") && \
	echo "  Schedule: $(SCHEDULE)" && \
	echo "  Dry run:  $(DRY_RUN)" && \
	echo "" && \
	if [ -n "$(YES)" ]; then true; else read -p "Deploy? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1; fi
	@aws cloudformation deploy \
		--template-file $(TEMPLATE) \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--capabilities $(CAPABILITIES) \
		--parameter-overrides \
			DryRun=$(DRY_RUN) \
			ScheduleExpression="$(SCHEDULE)" \
			$(if $(IMAGE),ContainerImage=$(IMAGE)) \
			ConfigSourceUrl="$(CONFIG_URL)" \
		$(CFN_TAGS) \
		--no-fail-on-empty-changeset
ifdef CONFIG_URL
	@echo "Stack deployed. Config will be fetched from URL at runtime."
else
	@echo "Stack deployed. Uploading nuke config..."
	@$(MAKE) --no-print-directory upload-config
endif

upload-config: ## Upload the nuke config to S3
	@URL=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--query 'Stacks[0].Parameters[?ParameterKey==`ConfigSourceUrl`].ParameterValue | [0]' \
		--output text 2>/dev/null) && \
	if [ -n "$$URL" ] && [ "$$URL" != "None" ]; then \
		echo "ERROR: Stack is configured to fetch config from a URL:"; \
		echo "  $$URL"; \
		echo "Uploading to S3 would have no effect. Update the config at the source URL,"; \
		echo "or redeploy without CONFIG_URL to switch back to S3 mode."; \
		exit 1; \
	fi
	@BUCKET=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--query 'Stacks[0].Outputs[?OutputKey==`ConfigBucketName`].OutputValue' \
		--output text) && \
	echo "Uploading $(CONFIG) to s3://$$BUCKET/nuke-config.yml" && \
	aws s3 cp $(CONFIG) "s3://$$BUCKET/nuke-config.yml" --region $(REGION) > /dev/null && \
	echo "Config uploaded."

run: ## Manually trigger the aws-nuke job
	@PROJECT=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--query 'Stacks[0].Outputs[?OutputKey==`CodeBuildProjectName`].OutputValue' \
		--output text) && \
	echo "Starting build for $$PROJECT..." && \
	BUILD_ID=$$(aws codebuild start-build \
		--project-name "$$PROJECT" \
		--region $(REGION) \
		--query 'build.id' --output text) && \
	echo "Build started: $$BUILD_ID" && \
	echo "Run 'make logs' to follow progress."

logs: ## Tail the latest build logs
	@PROJECT=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--query 'Stacks[0].Outputs[?OutputKey==`CodeBuildProjectName`].OutputValue' \
		--output text) && \
	BUILD_ID=$$(aws codebuild list-builds-for-project \
		--project-name "$$PROJECT" \
		--region $(REGION) \
		--query 'ids[0]' --output text) && \
	START_TIME=$$(aws codebuild batch-get-builds \
		--ids "$$BUILD_ID" \
		--region $(REGION) \
		--query 'builds[0].startTime' --output text) && \
	LOG_GROUP=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--query 'Stacks[0].Outputs[?OutputKey==`LogGroupName`].OutputValue' \
		--output text) && \
	echo "Build: $$BUILD_ID" && \
	echo "---" && \
	aws logs tail "$$LOG_GROUP" \
		--since "$$START_TIME" \
		--follow \
		--format short \
		--region $(REGION) 2>/dev/null || \
		echo "No logs yet. The build may still be starting."

status: ## Show stack and latest build status
	@echo "=== Stack ==="
	@aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--query 'Stacks[0].{Status:StackStatus,Created:CreationTime,Updated:LastUpdatedTime}' \
		--output table 2>/dev/null || echo "Stack not found."
	@echo ""
	@echo "=== Latest Build ==="
	@PROJECT=$$(aws cloudformation describe-stacks \
		--stack-name $(STACK_NAME) \
		--region $(REGION) \
		--query 'Stacks[0].Outputs[?OutputKey==`CodeBuildProjectName`].OutputValue' \
		--output text 2>/dev/null) && \
	[ -n "$$PROJECT" ] && [ "$$PROJECT" != "None" ] && \
	BUILD_ID=$$(aws codebuild list-builds-for-project \
		--project-name "$$PROJECT" \
		--region $(REGION) \
		--query 'ids[0]' --output text 2>/dev/null) && \
	[ -n "$$BUILD_ID" ] && [ "$$BUILD_ID" != "None" ] && \
	aws codebuild batch-get-builds \
		--ids "$$BUILD_ID" \
		--region $(REGION) \
		--query 'builds[0].{Status:buildStatus,Start:startTime,End:endTime}' \
		--output table 2>/dev/null || \
	echo "No builds yet."

destroy: ## Delete the stack (S3 bucket is retained)
	@echo "WARNING: This will delete the aws-nuke stack '$(STACK_NAME)'."
	@echo "The S3 config bucket will be RETAINED (you must delete it manually)."
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ] || exit 1
	@aws cloudformation delete-stack \
		--stack-name $(STACK_NAME) \
		--region $(REGION)
	@echo "Stack deletion initiated. Run 'make status' to check progress."
