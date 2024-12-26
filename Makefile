PROFILE=assume-role-id

bootstrap:
	cdk bootstrap --region us-east-1 --profile $(PROFILE)

deploy:
	cdk deploy --profile $(PROFILE)
