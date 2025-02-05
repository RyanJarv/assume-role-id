package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"time"
)

// const KeepRolesFor = time.Hour * 24
const KeepRolesFor = time.Hour * 24

type CreateRoleRequest struct {
	RoleName          string `json:"role_name"`
	RequireExternalId bool
}

type CreateRoleResponse struct {
	RoleArn string `json:"role_arn"`
	Token   string `json:"token"`
}

func CreateRole(ctx *Context, client *iam.Client, roleName string, requireExternalId bool, secret []byte) (*CreateRoleResponse, error) {
	if roleName == "" {
		roleName = RandStringRunes(16)
	}
	if role, err := client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	}); err != nil {
		var notFoundErr *types.NoSuchEntityException
		if ok := errors.As(err, &notFoundErr); ok {
			ctx.Debug.Printf("IAM role '%s' does not exist.\n", roleName)
		} else {
			return nil, fmt.Errorf("getting role: %w", err)
		}
	} else if !IsOurRole(*role.Role) {
		return nil, fmt.Errorf("forbidden role name: %s", roleName)
	} else {
		// If the role exists, just delete it.
		// TODO: Display an error in the UI if the role is deleted and recreated when polling.
		if err := DeleteRole(ctx, client, roleName); err != nil {
			return nil, fmt.Errorf("deleting role: %w", err)
		}
	}

	return createRole(ctx, client, secret, &CreateRoleRequest{
		RoleName:          roleName,
		RequireExternalId: requireExternalId,
	})
}

func createRole(ctx *Context, client *iam.Client, secret []byte, req *CreateRoleRequest) (*CreateRoleResponse, error) {
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

	// Deny everything except what's allowed.
	if _, err := client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:   role.Role.RoleName,
		PolicyName: aws.String("DenyAllOther"),
		PolicyDocument: aws.String(string(Must(json.Marshal(PolicyDocument{
			Version: "2012-10-17",
			Statement: []PolicyStatement{
				{
					Sid:         "DenyAll",
					Effect:      "Deny",
					NotAction:   "iam:ListAttachedRolePolicies",
					NotResource: *role.Role.Arn,
				},
			},
		})))),
	}); err != nil {
		return nil, fmt.Errorf("attaching policy: %w", err)
	}

	// Some stuff checks the current role for attached policies.
	if _, err := client.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:   role.Role.RoleName,
		PolicyName: aws.String("ListAttachedRolePolicies"),
		PolicyDocument: aws.String(string(Must(json.Marshal(PolicyDocument{
			Version: "2012-10-17",
			Statement: []PolicyStatement{
				{
					Sid:      "AllowSelfListAttachedRolePolicies",
					Effect:   "Allow",
					Action:   "iam:ListAttachedRolePolicies",
					Resource: *role.Role.Arn,
				},
			},
		})))),
	}); err != nil {
		return nil, fmt.Errorf("attaching policy: %w", err)
	}

	// Some stuff just needs SecurityAudit attached, so add that even though it won't do anything here.
	if _, err := client.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  role.Role.RoleName,
		PolicyArn: aws.String("arn:aws:iam::aws:policy/SecurityAudit"),
	}); err != nil {
		return nil, fmt.Errorf("attaching policy: %w", err)
	}

	token, err := CreateRoleToken(*role.Role.RoleName, *role.Role.RoleId, secret)
	if err != nil {
		return nil, fmt.Errorf("generating Token: %w", err)
	}

	ctx.Debug.Printf("issuing token %s for role %s", token, *role.Role.Arn)

	return &CreateRoleResponse{
		RoleArn: *role.Role.Arn,
		Token:   token,
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
