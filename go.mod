module github.com/ryanjarv/assume-role-id

go 1.22.0

toolchain go1.23.1

//replace (
//	github.com/ryanjarv/assume-role-id/web => ./web
//)

require (
	github.com/aws/aws-cdk-go/awscdk/v2 v2.173.2
	github.com/aws/aws-cdk-go/awscdklambdagoalpha/v2 v2.173.2-alpha.0
	github.com/aws/constructs-go/constructs/v10 v10.4.2
	github.com/aws/jsii-runtime-go v1.106.0
)

require (
	github.com/Masterminds/semver/v3 v3.3.1 // indirect
	github.com/cdklabs/awscdk-asset-awscli-go/awscliv1/v2 v2.2.208 // indirect
	github.com/cdklabs/awscdk-asset-kubectl-go/kubectlv20/v2 v2.1.3 // indirect
	github.com/cdklabs/awscdk-asset-node-proxy-agent-go/nodeproxyagentv6/v2 v2.1.0 // indirect
	github.com/cdklabs/cloud-assembly-schema-go/awscdkcloudassemblyschema/v38 v38.0.1 // indirect
	github.com/cdktf/cdktf-provider-cloudflare-go/cloudflare/v11 v11.27.0 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/yuin/goldmark v1.4.13 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
)
