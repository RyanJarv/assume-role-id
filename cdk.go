package main

import (
	"fmt"
	cdk "github.com/aws/aws-cdk-go/awscdk/v2"
	certmgr "github.com/aws/aws-cdk-go/awscdk/v2/awscertificatemanager"
	cloudfront "github.com/aws/aws-cdk-go/awscdk/v2/awscloudfront"
	origins "github.com/aws/aws-cdk-go/awscdk/v2/awscloudfrontorigins"
	iam "github.com/aws/aws-cdk-go/awscdk/v2/awsiam"
	lambda "github.com/aws/aws-cdk-go/awscdk/v2/awslambda"
	route53 "github.com/aws/aws-cdk-go/awscdk/v2/awsroute53"
	s3 "github.com/aws/aws-cdk-go/awscdk/v2/awss3"
	golambda "github.com/aws/aws-cdk-go/awscdklambdagoalpha/v2"
	"github.com/aws/constructs-go/constructs/v10"
	j "github.com/aws/jsii-runtime-go"
	"strconv"
	"strings"
)

const DomainName = "id.assume.ryanjarv.sh"
const ValidationDomain = "ryanjarv.sh"

func NewAssumeRoleIdStack(scope constructs.Construct, id string) cdk.Stack {
	stack := cdk.NewStack(scope, &id, &cdk.StackProps{
		Env: &cdk.Environment{
			// CloudFront certificates have to be deployed to us-east-1, so just deploy everything there.
			Region: j.String("us-east-1"),
		},
	})

	fnDist, zone, bucket := NewAssumeRoleIdFunction(stack)

	cdk.NewCfnOutput(stack, j.String("UrlOutput"), &cdk.CfnOutputProps{
		Value: fnDist.DomainName(),
	})

	for i, _ := range *zone.HostedZoneNameServers() {
		cdk.NewCfnOutput(stack, j.String("NameServer-"+strconv.Itoa(i)), &cdk.CfnOutputProps{
			Value: cdk.Fn_Select(j.Number(i), zone.HostedZoneNameServers()),
		})
	}

	cdk.NewCfnOutput(stack, j.String("BucketOutput"), &cdk.CfnOutputProps{
		Value: bucket.BucketName(),
	})

	cdk.NewCfnOutput(stack, j.String("AccountId"), &cdk.CfnOutputProps{
		Value: cdk.Aws_ACCOUNT_ID(),
	})

	return stack
}

func NewAssumeRoleIdFunction(stack cdk.Stack) (cloudfront.Distribution, route53.HostedZone, s3.Bucket) {
	scope := constructs.NewConstruct(stack, j.String("fn"))

	bucket := s3.NewBucket(scope, j.String("bucket"), &s3.BucketProps{
		AccessControl: s3.BucketAccessControl_PRIVATE,
	})

	cert := certmgr.NewCertificate(scope, j.String("cert"), &certmgr.CertificateProps{
		DomainName: j.String(DomainName),
		Validation: certmgr.CertificateValidation_FromEmail(&map[string]*string{
			DomainName: j.String(ValidationDomain),
		}),
	})

	function := golambda.NewGoFunction(scope, j.String("function-id"), &golambda.GoFunctionProps{
		Architecture: lambda.Architecture_ARM_64(),
		Entry:        j.String("web"),
		ModuleDir:    j.String("web"),
		Environment: &map[string]*string{
			"ACCOUNT_ID": cdk.Aws_ACCOUNT_ID(),
			"BUCKET":     bucket.BucketName(),
		},
		Timeout: cdk.Duration_Seconds(j.Number(60)),
	})
	function.AddToRolePolicy(iam.NewPolicyStatement(&iam.PolicyStatementProps{
		Actions: &[]*string{
			j.String("iam:CreateRole"),
			j.String("iam:TagRole"),
			j.String("iam:DeleteRole"),
			j.String("iam:ListRoles"),
		},
		Resources: &[]*string{
			j.String("arn:aws:iam::*:role/assume-role-id/*"),
		},
	}))
	function.AddToRolePolicy(iam.NewPolicyStatement(&iam.PolicyStatementProps{
		Actions: &[]*string{
			j.String("ec2:DescribeRegions"),
			j.String("cloudtrail:LookupEvents"),
		},
		Resources: &[]*string{
			j.String("*"),
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
			j.String(fmt.Sprintf("arn:aws:s3:%s:%s:accesspoint/assume-role-id-*", *cdk.Aws_REGION(), *cdk.Aws_ACCOUNT_ID())),
		},
	}))

	fnUrl := lambda.NewFunctionUrl(scope, j.String("url-id"), &lambda.FunctionUrlProps{
		AuthType:   lambda.FunctionUrlAuthType_AWS_IAM,
		InvokeMode: lambda.InvokeMode_RESPONSE_STREAM,
		Function:   function,
	})
	fnDist := cloudfront.NewDistribution(scope, j.String("distribution"), &cloudfront.DistributionProps{
		DefaultBehavior: &cloudfront.BehaviorOptions{
			Origin: origins.FunctionUrlOrigin_WithOriginAccessControl(fnUrl, &origins.FunctionUrlOriginWithOACProps{
				OriginAccessControl: cloudfront.NewFunctionUrlOriginAccessControl(scope, j.String("origin-access-control"), &cloudfront.FunctionUrlOriginAccessControlProps{}),
				ReadTimeout:         cdk.Duration_Seconds(j.Number(60)),
			}),
			ViewerProtocolPolicy: cloudfront.ViewerProtocolPolicy_REDIRECT_TO_HTTPS,
			CachePolicy:          cloudfront.CachePolicy_CACHING_DISABLED(),
		},
		Certificate: cert,
		HttpVersion: cloudfront.HttpVersion_HTTP2_AND_3,
		DomainNames: j.Strings(DomainName),
	})

	zoneName := strings.Join(strings.Split(DomainName, ".")[1:], ".")
	zone := route53.NewHostedZone(scope, j.String("hosted-zone"), &route53.HostedZoneProps{
		ZoneName: j.String(zoneName),
	})

	route53.NewCnameRecord(scope, j.String("cname-record"), &route53.CnameRecordProps{
		Zone:       zone,
		Comment:    j.String("Cname for the assume-role-id lambda function url"),
		Ttl:        cdk.Duration_Minutes(j.Number(30)),
		DomainName: fnDist.DomainName(),
		RecordName: j.String(DomainName + "."),
	})

	return fnDist, zone, bucket
}

func main() {
	defer j.Close()

	app := cdk.NewApp(nil)
	NewAssumeRoleIdStack(app, "AssumeRoleIdStack")
	app.Synth(nil)
}
