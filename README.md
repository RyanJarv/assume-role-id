# Assume Role ID

RaaS (Roles as a Service) hosted at [https://id.assume.ryanjarv.sh](https://id.assume.ryanjarv.sh) to help you switch away from IAM Users... or probably more useful for research, or maybe honeypots, whatever you can think of tbh. Anyway, it generates world assumable roles and then poll's CloudTrail for `sts:AssumeRole` API calls to assume them. The service also returns API Actions called on each session, however the frontend doesn't display this yet.

## Usage

Click the generate button to create a new world assumable role. Once created, the page will poll for AssumeRole events in CloudTrail and display the results.

The source principal ARN is generated from the principal ID in the AssumeRole event using the method described [here](https://hackingthe.cloud/aws/enumeration/enumerate_principal_arn_from_unique_id/).

## Details


### Bugs

Ideally you shouldn't be able to view events for roles you didn't generate, however don't rely on this right now. I need to fix the issue of stealing roles when you know the name.

### How it Works

The service uses two AWS accounts, the first is the service account which is defined in [./cdk.go](./cdk.go). The second is a sandbox account that we use to generate world assumable roles which is set up manually.

The only infrastructure in the sandbox account is an IAM Role that the lambda assumes during startup. It is configured [here](https://github.com/RyanJarv/assume-role-id/blob/d986d0347e8eb3795d8305a1e4b42bda8b6cbc07/cdk.go#L23), has a trust policy trusting the service account, and the identity policy can be found in the [#Deploy)[#deploy] section.

The generated roles are tagged with `assume-role-id: true` and should all have the `AWSDenyAll` policy attached (although the role shouldn't have any access to anything either way). If the requested IAM Role exists it is deleted and recreated, but only if it has the right tags on the role. After the role is created a [encrypted token](https://github.com/RyanJarv/assume-role-id/blob/4a71662cc1536ce77e33a74fb162c0df0bbf081d/web/pkg/role_token.go#L14) is returned to the user, which can later be passed to the `/poll/` endpoint to retrieve associated events for the role. The encrypted token contains the role name and the principalId, associated events must match both, this way we don't return older events for an unrelated role with the same name.


### Deploy


Make sure you have two AWS accounts, one to run the service and one with nothing else in it to use as a sandbox.

1. In the sandbox account create an IAM Role trusting the service AWS account and attach the following identity policy:

```
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Condition": {
				"StringEquals": {
					"iam:PolicyARN": "arn:aws:iam::aws:policy/AWSDenyAll",
					"iam:ResourceTag/assume-role-id": "true"
				}
			},
			"Action": [
				"iam:AttachRolePolicy",
				"iam:DetachRolePolicy"
			],
			"Resource": "*",
			"Effect": "Allow"
		},
		{
			"Condition": {
				"StringEquals": {
					"aws:RequestTag/assume-role-id": "true"
				}
			},
			"Action": [
				"iam:CreateRole",
				"iam:TagRole"
			],
			"Resource": "*",
			"Effect": "Allow"
		},
		{
			"Condition": {
				"StringEquals": {
					"iam:ResourceTag/assume-role-id": "true"
				}
			},
			"Action": [
				"iam:DeleteRole",
				"iam:ListAttachedRolePolicies"
			],
			"Resource": "arn:aws:iam::*:role/*",
			"Effect": "Allow"
		},
		{
			"Action": [
				"cloudtrail:LookupEvents",
				"ec2:DescribeRegions",
				"iam:ListRoles",
				"iam:GetRole"
			],
			"Resource": "*",
			"Effect": "Allow"
		}
	]
}
```


2. Update the following in the code:
  * [Makefile](./Makefile)
    * Set [PROFILE](https://github.com/RyanJarv/assume-role-id/blob/4a71662cc1536ce77e33a74fb162c0df0bbf081d/Makefile#L1) to the AWS CLI profile name of the service account.
  * [cdk.go](./cdk.go)
    * Set DomainName and ValidationDomain to the domains you want to use.
      * You'll need to be able to receive emails at ValidationDomain to confirm the TLS certificate request during deployment.
3. Run `make bootstrap && make deploy` to deploy to the service account.
  * This will pause and wait for you to confirm the TLS certificate request sent to one of the admin emails (hostmaster@ and a few others) set up on the ValidationDomain. If you don't have email setup you may be best off updating validation cert validation in [cdk.go](./cdk.go) to use DNS instead.

### Credit

Some of the PrincipalId lookup code was initially borrowed from [ak2-au/awsid](https://github.com/ak2-au/awsid).
