package pkg

import (
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"strings"
)

// CreateRoleToken generates a token for a role and principal ID
//
// The token can be exchanged for *iam.GetRoleOutput if the same role still exists in the future.
// principalId is used to ensure that the same role is retrieved, not some future role with the same name.
func CreateRoleToken(roleName, principalId string, secret []byte) (string, error) {
	return Encrypt(fmt.Sprintf("%s:%s", roleName, principalId), secret)
}

// GetRoleFromToken decrypts a Token and retrieves the role from IAM
func GetRoleFromToken(ctx *Context, client *iam.Client, token string, secret []byte) (*iam.GetRoleOutput, error) {
	plaintext, err := Decrypt(token, secret)
	if err != nil {
		return nil, fmt.Errorf("decrypting Token: %w", err)
	}
	parts := strings.Split(plaintext, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid Token format")
	}
	name, expectedPrincipalId := parts[0], parts[1]

	role, err := client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(name),
	})
	if err != nil {
		return nil, fmt.Errorf("getting role: %v", err)
	} else if !IsOurRole(*role.Role) {
		return nil, fmt.Errorf("forbidden role name: %s", name)
	} else if *role.Role.AssumeRolePolicyDocument != expectedPrincipalId {
		return nil, fmt.Errorf("principal id did not match: %s", name)
	}

	return role, nil
}
