module github.com/ryanjarv/assume-role-id

go 1.24.0

//replace (
//	github.com/ryanjarv/assume-role-id/web => ./web
//)

require (
	github.com/aws/aws-cdk-go/awscdk/v2 v2.223.0
	github.com/aws/aws-cdk-go/awscdklambdagoalpha/v2 v2.223.0-alpha.0
	github.com/aws/aws-sdk-go-v2 v1.39.7-0.20251111114342-a5136d59e67b
	github.com/aws/aws-sdk-go-v2/service/iam main
	github.com/aws/constructs-go/constructs/v10 v10.4.3
	github.com/aws/jsii-runtime-go v1.119.0
)

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/aws/smithy-go v1.23.2 // indirect
	github.com/cdklabs/awscdk-asset-awscli-go/awscliv1/v2 v2.2.257 // indirect
	github.com/cdklabs/awscdk-asset-node-proxy-agent-go/nodeproxyagentv6/v2 v2.1.0 // indirect
	github.com/cdklabs/cloud-assembly-schema-go/awscdkcloudassemblyschema/v48 v48.18.0 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/yuin/goldmark v1.7.13 // indirect
	golang.org/x/lint v0.0.0-20241112194109-818c5a804067 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/telemetry v0.0.0-20251111211155-bb26e12c2121 // indirect
	golang.org/x/tools v0.38.0 // indirect
	golang.org/x/tools/cmd/godoc v0.1.0-deprecated // indirect
	golang.org/x/tools/godoc v0.1.0-deprecated // indirect
)
