package pkg

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"strings"
	"time"
)

const AssumeRolePostfix = "-assume-role-id"

// const KeepRolesFor = time.Hour * 24
const KeepRolesFor = time.Hour * 24

type ProvisionRoleRequest struct {
	RolePrefix string `json:"role_prefix"`
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

	role, err := client.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:    aws.String(req.RolePrefix + RandStringRunes(24) + AssumeRolePostfix),
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
	roles := []types.Role{}
	resp, err := client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return fmt.Errorf("listing roles: %w", err)
	}

	for _, role := range resp.Roles {
		if strings.HasSuffix(*role.RoleName, AssumeRolePostfix) {
			roles = append(roles, role)
		}
	}

	cutoff := time.Now().UTC().Add(-KeepRolesFor)
	for _, role := range roles {
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
