package pkg

import "time"

type Event struct {
	EventVersion      string            `json:"eventVersion"`
	UserIdentity      UserIdentity      `json:"userIdentity"`
	EventTime         time.Time         `json:"eventTime"`
	EventSource       string            `json:"eventSource"`
	EventName         string            `json:"eventName"`
	AwsRegion         string            `json:"awsRegion"`
	SourceIPAddress   string            `json:"sourceIPAddress"`
	UserAgent         string            `json:"userAgent"`
	RequestParameters RequestParameters `json:"requestParameters"`
	ResponseElements  struct {
		Credentials struct {
			AccessKeyId  string `json:"accessKeyId"`
			SessionToken string `json:"sessionToken"`
			Expiration   string `json:"expiration"`
		} `json:"credentials"`
		AssumedRoleUser struct {
			AssumedRoleId string `json:"assumedRoleId"`
			Arn           string `json:"arn"`
		} `json:"assumedRoleUser"`
	} `json:"responseElements"`
	RequestID string `json:"requestID"`
	EventID   string `json:"eventID"`
	ReadOnly  bool   `json:"readOnly"`
	Resources []struct {
		AccountId string `json:"accountId"`
		Type      string `json:"type"`
		ARN       string `json:"ARN"`
	} `json:"resources"`
	EventType          string `json:"eventType"`
	ManagementEvent    bool   `json:"managementEvent"`
	RecipientAccountId string `json:"recipientAccountId"`
	SharedEventID      string `json:"sharedEventID"`
	EventCategory      string `json:"eventCategory"`
	TlsDetails         struct {
		TlsVersion               string `json:"tlsVersion"`
		CipherSuite              string `json:"cipherSuite"`
		ClientProvidedHostHeader string `json:"clientProvidedHostHeader"`
	} `json:"tlsDetails"`
}

type RequestParameters struct {
	RoleArn         string `json:"roleArn"`
	RoleSessionName string `json:"roleSessionName"`
	ExternalId      string `json:"externalId,omitempty"`
}

type UserIdentity struct {
	Type        string `json:"type,omitempty"`
	PrincipalId string `json:"principalId,omitempty"`
	AccountId   string `json:"accountId,omitempty"`
	InvokedBy   string `json:"invokedBy,omitempty"`
}
