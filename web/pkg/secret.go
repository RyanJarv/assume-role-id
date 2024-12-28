package pkg

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

func GetOrGenerateSecret(ctx *Context, client *ssm.Client, secretName string) ([]byte, error) {
	ctx.Debug.Printf("fetching secret %s", secretName)
	resp, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(secretName),
		WithDecryption: aws.Bool(true),
	})
	if err != nil {
		var notFoundErr *types.ParameterNotFound
		if ok := errors.As(err, &notFoundErr); ok {
			ctx.Info.Printf("creating new secret %s", secretName)
			return CreateSecret(ctx, client, secretName)
		}
		return nil, fmt.Errorf("failed to get parameter: %w", err)
	}

	secret, err := base64.StdEncoding.DecodeString(*resp.Parameter.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Secret: %w", err)
	}

	return secret, nil
}

func CreateSecret(ctx *Context, client *ssm.Client, arn string) ([]byte, error) {
	secret, err := GenerateSecret(32)
	if err != nil {
		return nil, fmt.Errorf("generating random string: %w", err)
	}

	_, err = client.PutParameter(ctx, &ssm.PutParameterInput{
		Name:      aws.String(arn),
		Value:     aws.String(base64.StdEncoding.EncodeToString(secret)),
		Type:      types.ParameterTypeSecureString,
		Overwrite: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to put parameter: %w", err)
	}

	return secret, nil
}

// GenerateSecret generates a secure random string of length i
func GenerateSecret(i int) ([]byte, error) {
	if i <= 0 {
		return nil, fmt.Errorf("length must be greater than 0")
	}

	// Allocate a byte slice to hold the random data
	secret := make([]byte, i)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Trim the encoded string to the desired length
	return secret, nil
}
