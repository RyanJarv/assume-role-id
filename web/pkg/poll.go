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

func PollEvents(ctx *Context, client map[string]*cloudtrail.Client, scanner *Scanner, roleName string, start time.Time) (*PollEventsOutput, error) {
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
	Events             []string
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

		results := []AssumeRoleEvent{}
		for _, event := range resp.Events {
			if result, err := AnalyzeAssumeRoleEvent(ctx, client, event, roleName, scanner, start); err != nil {
				return nil, fmt.Errorf("analyzing events: %w", err)
			} else if result != nil {
				results = append(results, *result)
			}
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

func AnalyzeAssumeRoleEvent(ctx *Context, client *cloudtrail.Client, event cloudtrailTypes.Event, roleName string, scanner *Scanner, start time.Time) (*AssumeRoleEvent, error) {
	ctx.Debug.Printf("looking for events for role %s", roleName)

	debugEvent, _ := json.Marshal(event)
	ctx.Debug.Printf("got event %s: %s", *event.EventId, debugEvent)
	var found bool
	for _, r := range event.Resources {
		if *r.ResourceType == "AWS::IAM::Role" {
			if eventRoleName, err := GetResourceName(*r.ResourceName); err != nil {
				return nil, fmt.Errorf("getting resource name: %w", err)
			} else if eventRoleName != roleName {
				return nil, nil
			}
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("no role resource found in the AssumeRole event")
	}

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

	var eventNames []string
	var nextToken *string
	for {
		resp, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(start),
			LookupAttributes: []cloudtrailTypes.LookupAttribute{
				{
					AttributeKey:   cloudtrailTypes.LookupAttributeKeyAccessKeyId,
					AttributeValue: aws.String(assumeRoleEvent.ResponseElements.Credentials.AccessKeyId),
				},
			},
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("looking up events: %w", err)
		}
		for _, event := range resp.Events {
			eventNames = append(eventNames, *event.EventName)
		}

		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}

		nextToken = resp.NextToken

		ctx.Debug.Printf("looking up events with next token %s", TryMarshal(nextToken))
	}

	return &AssumeRoleEvent{
		EventId:            assumeRoleEvent.EventID,
		Time:               assumeRoleEvent.EventTime,
		Region:             assumeRoleEvent.AwsRegion,
		SourceIp:           assumeRoleEvent.SourceIPAddress,
		UserAgent:          assumeRoleEvent.UserAgent,
		UserIdentity:       assumeRoleEvent.UserIdentity,
		SourcePrincipalArn: sourcePrincipalArn,
		AssumeRoleParams:   &assumeRoleEvent.RequestParameters,
		Events:             eventNames,
	}, nil

}
