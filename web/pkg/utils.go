package pkg

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"io"
	"log"
	"math/rand"
	"os"
	"strings"
)

const (
	colorScheme = "pastel28"

	Red   Color = "\033[31m"
	Green Color = "\033[32m"
	Cyan  Color = "\033[36m"
	Gray  Color = "\033[37m"

	ErrorLogLevel LogLevel = iota
	InfoLogLevel
	DebugLogLevel
)

type Color string

func (c Color) Color(s ...string) string {
	return string(c) + strings.Join(s, " ") + "\033[0m"
}

type LogLevel int

func NewContext(parentCtx context.Context) *Context {
	ctx := &Context{
		Context: parentCtx,
		Error:   log.New(os.Stderr, Red.Color("[ERROR] "), 0),
		Info:    log.New(os.Stdout, Green.Color("[INFO] "), 0),
		Debug:   log.New(os.Stdout, Gray.Color("[DEBUG] "), 0),
	}

	ctx.Debug.SetOutput(io.Discard)
	return ctx
}

type Context struct {
	context.Context
	LogLevel LogLevel
	Error    *log.Logger
	Info     *log.Logger
	Debug    *log.Logger
}

func (ctx *Context) SetLoggingLevel(level LogLevel) Context {
	ctx.LogLevel = level

	if int(level) >= int(ErrorLogLevel) {
		ctx.Error = log.New(os.Stderr, Red.Color("[ERROR] "), 0)
	} else {
		ctx.Error.SetOutput(io.Discard)
	}

	if int(level) >= int(InfoLogLevel) {
		ctx.Info = log.New(os.Stderr, Green.Color("[INFO] "), 0)
	} else {
		ctx.Info.SetOutput(io.Discard)
	}

	if int(level) >= int(DebugLogLevel) {
		ctx.Debug = log.New(os.Stderr, Gray.Color("[DEBUG] "), 0)
	} else {
		ctx.Info.SetOutput(io.Discard)
	}
	return *ctx
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func Keys[K comparable, V any](m map[K]V) []K {
	keys := make([]K, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func TryMarshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func GetResourceNameFromArn(s string) (string, error) {
	parsed, err := arn.Parse(s)
	if err != nil {
		return "", fmt.Errorf("parsing arn: %w", err)
	}
	p := strings.Split(parsed.Resource, "/")
	name := p[len(p)-1]
	return name, nil
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func DeleteRole(ctx *Context, client *iam.Client, name string) error {
	resp, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(name),
	})
	if err != nil {
		return fmt.Errorf("listing attached policies %s: %w", name, err)
	}

	for _, policy := range resp.AttachedPolicies {
		if _, err := client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			RoleName:  aws.String(name),
			PolicyArn: policy.PolicyArn,
		}); err != nil {
			return fmt.Errorf("detaching policy %s: %w", *policy.PolicyArn, err)
		}
	}

	if _, err := client.DeleteRole(ctx, &iam.DeleteRoleInput{
		RoleName: aws.String(name),
	}); err != nil {
		return fmt.Errorf("deleting role: %v", err)
	}
	return nil
}

func MustGetenv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		panic(fmt.Sprintf("missing env var: %s", name))
	}
	return v
}
