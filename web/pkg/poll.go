package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"strings"
	"sync"
	"time"
)

type PollEventsOutput struct {
	RoleName string            `json:"role_name"`
	Results  []AssumeRoleEvent `json:"results"`
}

func PollEvents(ctx *Context, client map[string]*cloudtrail.Client, scanner *Scanner, roleName string) (*PollEventsOutput, error) {
	start := time.Now().Add(-1 * time.Hour).UTC()
	ctx.Debug.Printf("looking for role %s since %s", roleName, start.String())

	var allResults []AssumeRoleEvent
	var errors []error

	wg := &sync.WaitGroup{}

	for region, cfg := range client {
		ctx.Debug.Printf("looking in region %s for %s assume role events", region, roleName)
		wg.Add(1)

		go func(region string, cfg *cloudtrail.Client) {
			ctx.Debug.Printf("looking in region %s", region)

			results, err := PollRegionEvents(ctx, cfg, scanner, roleName, start)
			if err != nil {
				ctx.Error.Printf("poll: %v", err)
				errors = append(errors, fmt.Errorf("poll: %w", err))
				return
			}

			if results != nil {
				allResults = append(allResults, results...)
			}

			wg.Done()
		}(region, cfg)
	}
	wg.Wait()

	if len(errors) > 0 {
		return nil, fmt.Errorf("poll: failed to poll all regions")
	}

	ctx.Debug.Printf("results for %s: %s", roleName, TryMarshal(allResults))
	return &PollEventsOutput{
		RoleName: roleName,
		Results:  allResults,
	}, nil
}

type AssumeRoleEvent struct {
	EventId            string             `json:"event_id"`
	Time               time.Time          `json:"time"`
	Region             string             `json:"region"`
	UserAgent          string             `json:"user_agent"`
	SourceIp           string             `json:"source_ip"`
	SourcePrincipalArn string             `json:"source_principal_arn"`
	UserIdentity       UserIdentity       `json:"user_identity"`
	AssumeRoleParams   *RequestParameters `json:"assume_role_params"`
}

func PollRegionEvents(ctx *Context, client *cloudtrail.Client, scanner *Scanner, roleName string, start time.Time) ([]AssumeRoleEvent, error) {
	allResults := []AssumeRoleEvent{}

	var nextToken *string
	for {
		resp, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(start),
			LookupAttributes: []cloudtrailTypes.LookupAttribute{
				{
					AttributeKey:   cloudtrailTypes.LookupAttributeKeyEventName,
					AttributeValue: aws.String("AssumeRole"),
				},
			},
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("looking up events: %w", err)
		}

		results, err := AnalyzeEvents(ctx, resp.Events, roleName, scanner)
		if err != nil {
			return nil, fmt.Errorf("analyzing events: %w", err)
		}

		allResults = append(allResults, results...)
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}

		nextToken = resp.NextToken

		ctx.Debug.Printf("looking up events with next token %s", TryMarshal(nextToken))
	}

	ctx.Debug.Printf("results for %s: %s", roleName, TryMarshal(allResults))

	return allResults, nil
}

func AnalyzeEvents(ctx *Context, events []cloudtrailTypes.Event, roleName string, scanner *Scanner) ([]AssumeRoleEvent, error) {
	suffix := roleName + AssumeRolePostfix
	ctx.Debug.Printf("looking for events to roles with suffix %s", suffix)

	results := []AssumeRoleEvent{}
	for _, event := range events {
		debugEvent, _ := json.Marshal(event)
		ctx.Debug.Printf("got event %s: %s", *event.EventId, debugEvent)
		for _, r := range event.Resources {
			if *r.ResourceType == "AWS::IAM::Role" && strings.HasSuffix(*r.ResourceName, suffix) {
				ctx.Debug.Printf("found matching event: %s", *event.EventId)
				assumeRoleEvent := &Event{}
				if err := json.Unmarshal([]byte(*event.CloudTrailEvent), assumeRoleEvent); err != nil {
					return nil, fmt.Errorf("poll: unmarshalling event: %w", err)
				}

				sourcePrincipalId := strings.Split(assumeRoleEvent.UserIdentity.PrincipalId, ":")[0]

				sourcePrincipalArn, err := scanner.LookupPrincipalId(ctx, sourcePrincipalId)
				if err != nil {
					return nil, fmt.Errorf("scanning arn: %w", err)
				}
				results = append(results, AssumeRoleEvent{
					EventId:            assumeRoleEvent.EventID,
					Time:               assumeRoleEvent.EventTime,
					Region:             assumeRoleEvent.AwsRegion,
					SourceIp:           assumeRoleEvent.SourceIPAddress,
					UserAgent:          assumeRoleEvent.UserAgent,
					UserIdentity:       assumeRoleEvent.UserIdentity,
					SourcePrincipalArn: sourcePrincipalArn,
					AssumeRoleParams:   &assumeRoleEvent.RequestParameters,
				})
			}
		}
	}

	return results, nil
}
