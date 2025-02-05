package pkg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	s3controlTypes "github.com/aws/aws-sdk-go-v2/service/s3control/types"
	"github.com/aws/smithy-go"
	"golang.org/x/sync/syncmap"
)

type NewScannerInput struct {
	Config      aws.Config
	Concurrency int
	Bucket      string
	Name        string
	AccountId   string
}

func NewScanner(input *NewScannerInput) (*Scanner, error) {
	scanner := &Scanner{
		s3control:       s3control.NewFromConfig(input.Config),
		AccountId:       input.AccountId,
		Region:          "us-east-1",
		AccessPointName: "assume-role-id",
		BucketName:      input.Bucket,
		cache:           syncmap.Map{},
	}
	if input.Config.Region != "" {
		scanner.Region = input.Config.Region
	}

	return scanner, nil
}

type Scanner struct {
	s3control       *s3control.Client
	AccountId       string
	Region          string
	BucketName      string
	AccessPointName string
	cache           syncmap.Map
}

func (s *Scanner) LookupPrincipalId(ctx *Context, principalId string) (string, error) {
	if cached, ok := s.cache.Load(principalId); ok {
		ctx.Debug.Printf("cache hit: %s", principalId)
		return cached.(string), nil
	}
	ctx.Debug.Printf("cache miss: %s", principalId)

	name := s.AccessPointName + "-" + RandStringRunes(8)
	accesspointArn, err := SetupAccessPoint(ctx, s.s3control, name, s.AccountId, s.BucketName)
	if err != nil {
		return "", err
	}

	defer func() {
		if err := DeleteAccessPoint(ctx, *s.s3control, name, s.AccountId); err != nil {
			ctx.Error.Printf("deleting accesspoint: %s", err)
		}
	}()

	policy, err := json.Marshal(PolicyDocument{
		Version: "2012-10-17",
		Statement: []PolicyStatement{
			{
				Sid:      "testrole",
				Effect:   "Deny",
				Action:   []string{"*"},
				Resource: []string{accesspointArn},
				Principal: &PolicyPrincipal{
					AWS: principalId,
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshalling policy: %w", err)
	}

	if _, err = s.s3control.PutAccessPointPolicy(ctx, &s3control.PutAccessPointPolicyInput{
		AccountId: &s.AccountId,
		Name:      &name,
		Policy:    aws.String(string(policy)),
	}); err != nil {
		return "", fmt.Errorf("updating policy: %w", err)
	}

	resp, err := s.s3control.GetAccessPointPolicy(ctx, &s3control.GetAccessPointPolicyInput{
		AccountId: &s.AccountId,
		Name:      &name,
	})
	if err != nil {
		return "", fmt.Errorf("updating policy: %w", err)
	}
	ctx.Debug.Printf("updated policy: %s", *resp.Policy)

	updatedPolicy := &PolicyDocument{}
	if err := json.Unmarshal([]byte(*resp.Policy), updatedPolicy); err != nil {
		return "", fmt.Errorf("unmarshalling policy: %w", err)
	}

	s.cache.Store(principalId, updatedPolicy.Statement[0].Principal.AWS)

	return updatedPolicy.Statement[0].Principal.AWS, nil
}

func SetupAccessPoint(ctx context.Context, api *s3control.Client, name, account, bucket string) (string, error) {
	accessPoint, err := api.CreateAccessPoint(ctx, &s3control.CreateAccessPointInput{
		Name:            &name,
		AccountId:       &account,
		Bucket:          &bucket,
		BucketAccountId: &account,
		PublicAccessBlockConfiguration: &s3controlTypes.PublicAccessBlockConfiguration{
			BlockPublicAcls:       aws.Bool(true),
			BlockPublicPolicy:     aws.Bool(true),
			IgnorePublicAcls:      aws.Bool(true),
			RestrictPublicBuckets: aws.Bool(true),
		},
	})
	if err != nil {
		oe := &smithy.GenericAPIError{}
		if errors.As(err, &oe) && oe.ErrorCode() == "AccessPointAlreadyOwnedByYou" {
			point, err := api.GetAccessPoint(ctx, &s3control.GetAccessPointInput{
				Name:      &name,
				AccountId: &account,
			})
			if err != nil {
				return "", fmt.Errorf("get accesspoint: %w", err)
			}

			return *point.AccessPointArn, nil
		}

		return "", fmt.Errorf("setup access point: %w", err)
	}

	return *accessPoint.AccessPointArn, nil
}

func DeleteAccessPoint(ctx context.Context, api s3control.Client, name string, account string) error {
	if _, err := api.DeleteAccessPoint(ctx, &s3control.DeleteAccessPointInput{
		Name:      &name,
		AccountId: &account,
	}); err != nil {
		return fmt.Errorf("teardown: %w", err)
	}

	return nil
}
