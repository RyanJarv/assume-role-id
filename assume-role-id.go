package main

import (
	cdk "github.com/aws/aws-cdk-go/awscdk/v2"
	iam "github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	lambda "github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	s3 "github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	golambda "github.com/aws/aws-cdk-go/awscdklambdagoalpha/v2"
	"github.com/aws/constructs-go/constructs/v10"
	j "github.com/aws/jsii-runtime-go"
)

type AssumeRoleIdStackProps struct {
	cdk.StackProps
}

func NewAssumeRoleIdStack(scope constructs.Construct, id string, props *AssumeRoleIdStackProps) cdk.Stack {
	var sprops cdk.StackProps
	if props != nil {
		sprops = props.StackProps
	}
	stack := cdk.NewStack(scope, &id, &sprops)

	bucket := s3.NewBucket(stack, j.String("bucket"), &s3.BucketProps{
		AccessControl: s3.BucketAccessControl_PRIVATE,
	})

	function := golambda.NewGoFunction(stack, j.String("function-id"), &golambda.GoFunctionProps{
		Architecture: lambda.Architecture_ARM_64(),
		Entry:        j.String("web"),
		ModuleDir:    j.String("web"),
		Environment: &map[string]*string{
			"ACCOUNT_ID": cdk.Aws_ACCOUNT_ID(),
			"BUCKET":     bucket.BucketName(),
		},
	})

	url := lambda.NewFunctionUrl(stack, j.String("url-id"), &lambda.FunctionUrlProps{
		AuthType:   lambda.FunctionUrlAuthType_NONE,
		InvokeMode: lambda.InvokeMode_RESPONSE_STREAM,
		Function:   function,
	})

	function.AddToRolePolicy(iam.NewPolicyStatement(&iam.PolicyStatementProps{
		Actions: &[]*string{
			j.String("iam:CreateRole"),
			j.String("iam:DeleteRole"),
			j.String("iam:ListRoles"),
		},
		Resources: &[]*string{
			j.String("arn:aws:iam::*:role/assume-role-id/*"),
		},
	}))

	function.AddToRolePolicy(iam.NewPolicyStatement(&iam.PolicyStatementProps{
		Actions: &[]*string{
			j.String("s3:CreateAccessPoint"),
			j.String("s3:DeleteAccessPoint"),
			j.String("s3:GetAccessPointPolicy"),
			j.String("s3:PutAccessPointPolicy"),
		},
		Resources: &[]*string{
			j.String("arn:aws:s3:::accesspoint/assume-role-id-*"),
		},
	}))

	cdk.NewCfnOutput(stack, j.String("UrlOutput"), &cdk.CfnOutputProps{
		Value:      url.Url(),
		ExportName: j.String("Url"),
	})

	cdk.NewCfnOutput(stack, j.String("BucketOutput"), &cdk.CfnOutputProps{
		Value:      bucket.BucketName(),
		ExportName: j.String("Bucket"),
	})

	cdk.NewCfnOutput(stack, j.String("AccountId"), &cdk.CfnOutputProps{
		Value:      cdk.Aws_ACCOUNT_ID(),
		ExportName: j.String("AccountId"),
	})

	return stack
}

func main() {
	defer j.Close()

	app := cdk.NewApp(nil)

	NewAssumeRoleIdStack(app, "AssumeRoleIdStack", &AssumeRoleIdStackProps{
		cdk.StackProps{
			Env: env(),
		},
	})

	app.Synth(nil)
}

// env determines the AWS environment (account+region) in which our stack is to
// be deployed. For more information see: https://docs.aws.amazon.com/cdk/latest/guide/environments.html
func env() *cdk.Environment {
	// If unspecified, this stack will be "environment-agnostic".
	// Account/Region-dependent features and context lookups will not work, but a
	// single synthesized template can be deployed anywhere.
	//---------------------------------------------------------------------------
	return nil

	// Uncomment if you know exactly what account and region you want to deploy
	// the stack to. This is the recommendation for production stacks.
	//---------------------------------------------------------------------------
	// return &cdk.Environment{
	//  Account: jsii.String("123456789012"),
	//  Region:  jsii.String("us-east-1"),
	// }

	// Uncomment to specialize this stack for the AWS Account and Region that are
	// implied by the current CLI configuration. This is recommended for dev
	// stacks.
	//---------------------------------------------------------------------------
	// return &cdk.Environment{
	//  Account: jsii.String(os.Getenv("CDK_DEFAULT_ACCOUNT")),
	//  Region:  jsii.String(os.Getenv("CDK_DEFAULT_REGION")),
	// }
}
