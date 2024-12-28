package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cloudtrailTypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"strings"
	"sync"
	"time"
)

type PollEventsInput struct {
	Token      string                        `json:"token"`
	Iam        *iam.Client                   `json:"-"`
	CloudTrail map[string]*cloudtrail.Client `json:"-"`
	Scanner    *Scanner                      `json:"-"`
	Secret     []byte                        `json:"-"`
}

type PollEventsOutput struct {
	RoleName string            `json:"role_name"`
	Results  []AssumeRoleEvent `json:"results"`
}

func PollEvents(ctx *Context, params *PollEventsInput) (*PollEventsOutput, error) {
	role, err := GetRoleFromToken(ctx, params.Iam, params.Token, params.Secret)
	if err != nil {
		return nil, fmt.Errorf("getting role from Token: %w", err)
	}

	result, err := pollEvents(ctx, params, *role.Role.RoleName, *role.Role.RoleId, role.Role.CreateDate.UTC())
	if err != nil {
		return nil, fmt.Errorf("polling events: %w", err)
	}

	if result == nil {
		return nil, fmt.Errorf("assume role events not found for: %s", *role.Role.RoleName)
	}
	return result, nil
}

func pollEvents(ctx *Context, params *PollEventsInput, roleName, principalId string, start time.Time) (*PollEventsOutput, error) {
	ctx.Debug.Printf("looking for role %s since %s", roleName, start.String())

	var allResults []AssumeRoleEvent
	var errors []error

	wg := &sync.WaitGroup{}

	for region, cfg := range params.CloudTrail {
		ctx.Debug.Printf("looking in region %s for %s assume role events", region, roleName)
		wg.Add(1)

		go func(region string, cfg *cloudtrail.Client) {
			ctx.Debug.Printf("looking in region %s", region)

			results, err := PollRegionEvents(ctx, cfg, params.Scanner, roleName, principalId, start)
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

func PollRegionEvents(ctx *Context, client *cloudtrail.Client, scanner *Scanner, roleName, principalId string, start time.Time) ([]AssumeRoleEvent, error) {
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

		ourAssumeRoleEvents, err := FindOurAssumeRoleEvent(ctx, resp.Events, roleName, principalId)
		if err != nil {
			return nil, fmt.Errorf("checking if event is ours: %w", err)
		}

		results := []AssumeRoleEvent{}
		for _, event := range ourAssumeRoleEvents {
			expiration, err := time.Parse("Jan 2, 2006, 3:04:05 PM", event.ResponseElements.Credentials.Expiration)
			if err != nil {
				return nil, fmt.Errorf("parsing expiration time: %w", err)
			}
			eventNames, err := LookupSessionEvents(ctx, client, roleName, event.RequestParameters.RoleSessionName, principalId, event.ResponseElements.Credentials.AccessKeyId, event.EventTime, expiration)
			if err != nil {
				return nil, fmt.Errorf("analyzing events: %w", err)
			}

			sourcePrincipalId := strings.Split(event.UserIdentity.PrincipalId, ":")[0]
			sourcePrincipalArn, err := scanner.LookupPrincipalId(ctx, sourcePrincipalId)
			if err != nil {
				return nil, fmt.Errorf("scanning arn: %w", err)
			}

			results = append(results, AssumeRoleEvent{
				EventId:            event.EventID,
				Time:               event.EventTime,
				Region:             event.AwsRegion,
				SourceIp:           event.SourceIPAddress,
				UserAgent:          event.UserAgent,
				UserIdentity:       event.UserIdentity,
				SourcePrincipalArn: sourcePrincipalArn,
				AssumeRoleParams:   &event.RequestParameters,
				Events:             eventNames,
			})

		}

		allResults = append(allResults, results...)
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}

		nextToken = resp.NextToken

		ctx.Debug.Printf("looking up events with next Token %s", TryMarshal(nextToken))
	}

	ctx.Debug.Printf("results for %s: %s", roleName, TryMarshal(allResults))

	return allResults, nil
}

// FindOurAssumeRoleEvent finds the AssumeRole event for the role name and principalId.
func FindOurAssumeRoleEvent(ctx *Context, events []cloudtrailTypes.Event, name string, principalId string) ([]Event, error) {
	var results []Event
	for _, event := range events {
		if *event.EventName != "AssumeRole" {
			continue
		}
		ctx.Debug.Printf("found matching event: %s", *event.EventId)
		assumeRoleEvent := &Event{}
		if err := json.Unmarshal([]byte(*event.CloudTrailEvent), assumeRoleEvent); err != nil {
			return nil, fmt.Errorf("poll: unmarshalling event: %w", err)
		}

		if targetRoleName, err := GetResourceNameFromArn(assumeRoleEvent.RequestParameters.RoleArn); err != nil {
			return nil, fmt.Errorf("getting resource name: %w", err)
		} else if targetRoleName != name {
			continue
		}

		targetPrincipalId := strings.Split(assumeRoleEvent.ResponseElements.AssumedRoleUser.AssumedRoleId, ":")[0]
		if targetPrincipalId != principalId {
			continue
		}

		results = append(results, *assumeRoleEvent)
	}

	return results, nil
}

// LookupSessionEvents looks up the events for a session, returns the event names.
func LookupSessionEvents(ctx *Context, client *cloudtrail.Client, roleName, roleSessionName, principalId, accessKeyId string, issueTime, expiration time.Time) ([]string, error) {
	ctx.Debug.Printf("looking for events for role %s since %s", roleName, issueTime.String())

	var eventNames []string
	var nextToken *string
	for {
		resp, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			StartTime: aws.Time(issueTime),
			EndTime:   aws.Time(expiration),
			LookupAttributes: []cloudtrailTypes.LookupAttribute{
				{
					AttributeKey:   cloudtrailTypes.LookupAttributeKeyAccessKeyId,
					AttributeValue: aws.String(accessKeyId),
				},
				{
					AttributeKey:   cloudtrailTypes.LookupAttributeKeyUsername,
					AttributeValue: aws.String(roleSessionName),
				},
			},
			NextToken: nextToken,
		})
		if err != nil {
			return nil, fmt.Errorf("looking up events: %w", err)
		}
		for _, event := range resp.Events {
			var cloudtrailEvent *Event
			if err := json.Unmarshal([]byte(*event.CloudTrailEvent), &cloudtrailEvent); err != nil {
				return nil, fmt.Errorf("unmarshalling event: %w", err)
			}
			if v := cloudtrailEvent.UserIdentity.SessionContext.SessionIssuer.Type; v != "Role" {
				// This really shouldn't happen, would be interested if it does though.
				return nil, fmt.Errorf("principal id did not match (this shouldn't happen): %s != Role", v)
			}
			if v := cloudtrailEvent.UserIdentity.SessionContext.SessionIssuer.PrincipalId; v != principalId {
				// This really shouldn't happen, would be interested if it does though.
				return nil, fmt.Errorf("principal id did not match (this shouldn't happen): %s != %s", v, principalId)
			}

			eventNames = append(eventNames, *event.EventName)
		}

		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}

		nextToken = resp.NextToken

		ctx.Debug.Printf("looking up events with next Token %s", TryMarshal(nextToken))
	}

	return eventNames, nil

}
