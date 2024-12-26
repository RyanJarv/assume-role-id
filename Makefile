PROFILE=assume-role-id

bootstrap:
	cdk bootstrap --region us-east-1 --profile $(PROFILE)

deploy:
	cdk deploy --profile $(PROFILE)

test:
	AWS_REGION=us-east-1 AWS_PROFILE=$(PROFILE) BUCKET=assumeroleidstack-fnbucket241dca00-glnkhaluessv ACCOUNT_ID=$$(aws --profile $(PROFILE) sts get-caller-identity --query Account --out text) DEBUG=1 go run -C web main.go