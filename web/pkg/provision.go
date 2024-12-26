package pkg

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"time"
)

const AssumeRolePrefix = "/assume-role-id/"

// const KeepRolesFor = time.Hour * 24
const KeepRolesFor = time.Hour * 24

type ProvisionRoleOutput struct {
	RoleArn string `json:"role_arn"`
}

func ProvisionRole(ctx *Context, client *iam.Client) (*ProvisionRoleOutput, error) {
	go func() {
		err := CleanUpOldRoles(ctx, client)
		if err != nil {
			ctx.Error.Println("cleaning up old roles:", err)
		}
	}()

	role, err := client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:    aws.String(RandStringRunes(24)),
		Path:        aws.String(AssumeRolePrefix),
		Description: aws.String("role for assume-role-id"),
		AssumeRolePolicyDocument: aws.String(`{
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
		}`),
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

	return &ProvisionRoleOutput{
		RoleArn: *role.Role.Arn,
	}, nil
}

func CleanUpOldRoles(ctx *Context, client *iam.Client) error {
	roles, err := client.ListRoles(ctx, &iam.ListRolesInput{
		PathPrefix: aws.String(AssumeRolePrefix),
	})
	if err != nil {
		return fmt.Errorf("listing roles: %w", err)
	}

	cutoff := time.Now().UTC().Add(-KeepRolesFor)
	for _, role := range roles.Roles {
		if role.CreateDate.UTC().Before(cutoff) {
			ctx.Debug.Printf("deleting role %s", *role.RoleName)

			if _, err := client.DeleteRole(ctx, &iam.DeleteRoleInput{
				RoleName: role.RoleName,
			}); err != nil {
				return fmt.Errorf("deleting role %s: %w", *role.RoleName, err)
			}
		}
	}

	return nil
}
