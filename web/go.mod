module github.com/ryanjarv/assume-role-id/web

go 1.23.1

require (
	github.com/aws/aws-lambda-go v1.47.0
	github.com/aws/aws-sdk-go-v2 v1.32.7
	github.com/aws/aws-sdk-go-v2/config v1.28.7
	github.com/aws/aws-sdk-go-v2/credentials v1.17.48
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.46.4
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.198.1
	github.com/aws/aws-sdk-go-v2/service/iam v1.38.3
	github.com/aws/aws-sdk-go-v2/service/s3control v1.52.1
	github.com/aws/aws-sdk-go-v2/service/ssm v1.56.2
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.3
	github.com/aws/smithy-go v1.22.1
	golang.org/x/sync v0.11.0
)

require (
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.22 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.26 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.18.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.8 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.7 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
)
