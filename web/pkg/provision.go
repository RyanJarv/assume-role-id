package pkg

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"time"
)

// const KeepRolesFor = time.Hour * 24
const KeepRolesFor = time.Hour * 24

type ProvisionRoleRequest struct {
	RoleName          string `json:"role_name"`
	RequireExternalId bool
}

type ProvisionRoleOutput struct {
	RoleArn string `json:"role_arn"`
}

func ProvisionRole(ctx *Context, client *iam.Client, req *ProvisionRoleRequest) (*ProvisionRoleOutput, error) {
	go func() {
		err := CleanUpOldRoles(ctx, client)
		if err != nil {
			ctx.Error.Println("cleaning up old roles:", err)
		}
	}()

	var policy string
	if req.RequireExternalId {
		policy = `{
			"Version": "2012-10-17",
			"Statement": [	
				{	
					"Effect": "Allow",
					"Principal": {
						"AWS": "*"
					},
					"Action": "sts:AssumeRole"	
				}
			]
		}`
	} else {
		policy = `{
			"Version": "2012-10-17",
			"Statement": [	
				{	
					"Effect": "Allow",
					"Principal": {
						"AWS": "*"
					},
					"Action": "sts:AssumeRole",
					"Condition": {
						"Null": {
							"sts:ExternalId": "false"
						}
					}
				}
			]
		}`
	}
	role, err := client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(req.RoleName),
		Description:              aws.String("role for assume-role-id"),
		AssumeRolePolicyDocument: aws.String(policy),
		Tags: []types.Tag{
			{
				Key:   aws.String("assume-role-id"),
				Value: aws.String("true"),
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating role: %w", err)
	}

	// Shouldn't matter much but just to be safe.
	if _, err := client.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  role.Role.RoleName,
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AWSDenyAll"),
	}); err != nil {
		return nil, fmt.Errorf("attaching policy: %w", err)
	}

	return &ProvisionRoleOutput{
		RoleArn: *role.Role.Arn,
	}, nil
}

func CleanUpOldRoles(ctx *Context, client *iam.Client) error {
	resp, err := client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return fmt.Errorf("listing roles: %w", err)
	}

	cutoff := time.Now().UTC().Add(-KeepRolesFor)
	for _, role := range resp.Roles {
		if IsOurRole(role) && role.CreateDate.UTC().Before(cutoff) {
			ctx.Debug.Printf("deleting role %s", *role.RoleName)

			resp, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			})
			if err != nil {
				return fmt.Errorf("listing attached policies %s: %w", *role.RoleName, err)
			}

			for _, policy := range resp.AttachedPolicies {
				if _, err := client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
					RoleName:  role.RoleName,
					PolicyArn: policy.PolicyArn,
				}); err != nil {
					return fmt.Errorf("detaching policy %s: %w", *policy.PolicyArn, err)
				}
			}

			if _, err := client.DeleteRole(ctx, &iam.DeleteRoleInput{
				RoleName: role.RoleName,
			}); err != nil {
				return fmt.Errorf("deleting role %s: %w", *role.RoleName, err)
			}
		}
	}

	return nil
}

func IsOurRole(role types.Role) bool {
	for _, tag := range role.Tags {
		if *tag.Key == "assume-role-id" && *tag.Value == "true" {
			return true
		}
	}
	return false
}
