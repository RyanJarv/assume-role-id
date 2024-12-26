PROFILE=assume-role-id

bootstrap:
	cdk bootstrap --region us-east-1 --profile $(PROFILE)

deploy:
	cdk deploy --profile $(PROFILE)

test:
	account_id="$(aws --profile assume-role-id sts get-caller-identity --query Account --out text)"
	AWS_PROFILE=$(PROFILE) BUCKET=unused-bucket-af8940ijn28 ACCOUNT_ID="$account_id" DEBUG=1 go run -C web main.go