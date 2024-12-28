PROFILE=assume-role-id

bootstrap:
	cdk bootstrap --region us-east-1 --profile $(PROFILE)

deploy:
	cdk deploy --profile $(PROFILE)

test:
	AWS_ACCESS_KEY_ID= AWS_SECRET_ACCESS_KEY= AWS_SESSION_TOKEN= AWS_REGION=us-east-1 AWS_PROFILE=$(PROFILE) BUCKET=assumeroleidstack-fnbucket241dca00-glnkhaluessv SANDBOX_ROLE_ARN=arn:aws:iam::137068222704:role/assume-role-id-sandbox SECRET_NAME=/assume-role-id/secret SUPER_SECRET_PATH_PREFIX=2b49e1d3-4303-4eac-a8e3-998512d3dca2 ACCOUNT_ID=$$(aws --profile $(PROFILE) sts get-caller-identity --query Account --out text) DEBUG=1 go run -C web main.go
