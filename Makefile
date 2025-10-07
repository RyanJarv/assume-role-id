init: bootstrap deploy

bootstrap:
	JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1 cdk bootstrap --region us-east-1

deploy:
	JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1 cdk deploy --region us-east-1

test:
	AWS_ACCESS_KEY_ID= AWS_SECRET_ACCESS_KEY= AWS_SESSION_TOKEN= AWS_REGION=us-east-1 AWS_PROFILE=$(PROFILE) BUCKET=assumeroleidstack-fnbucket241dca00-glnkhaluessv SANDBOX_ROLE_ARN=arn:aws:iam::137068222704:role/assume-role-id-sandbox SECRET_NAME=/assume-role-id/secret SUPER_SECRET_PATH_PREFIX=b3ecdefe-1166-4c93-818f-982d17726fed ACCOUNT_ID=$$(aws --profile $(PROFILE) sts get-caller-identity --query Account --out text) DEBUG=1 go run -C web main.go
