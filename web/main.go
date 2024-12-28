package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/lambdaurl"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ryanjarv/assume-role-id/web/pkg"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
)

//go:embed html
var htmlFs embed.FS

var (
	accountId      = pkg.MustGetenv("ACCOUNT_ID")
	bucket         = pkg.MustGetenv("BUCKET")
	sandboxRoleArn = pkg.MustGetenv("SANDBOX_ROLE_ARN")
	secretName     = pkg.MustGetenv("SECRET_NAME")

	// Don't go looking around for this, it's a secret.
	superSecretPathPrefix = pkg.MustGetenv("SUPER_SECRET_PATH_PREFIX")
)

func main() {
	err := Run()
	if err != nil {
		log.Fatalln(err)
	}
}

func Run() error {
	ctx := pkg.NewContext(context.Background())

	svcArn, err := arn.Parse(sandboxRoleArn)
	if err != nil {
		return fmt.Errorf("parsing svc role arn: %w", err)
	}

	svcAccountCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading default config: %w", err)
	}

	sandboxAccountCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading default config: %w", err)
	}

	sandboxCreds := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(sandboxAccountCfg), sandboxRoleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = "assume-role-id-sandbox"
	})
	sandboxAccountCfg.Credentials = aws.NewCredentialsCache(sandboxCreds)

	if identity, err := sts.NewFromConfig(sandboxAccountCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return fmt.Errorf("getting caller identity: %w", err)
	} else if *identity.Account != svcArn.AccountID {
		return fmt.Errorf("not in the sandbox account: currently using %s", *identity.Account)
	} else {
		ctx.Debug.Printf("running in account: %s", *identity.Account)
	}

	if os.Getenv("DEBUG") != "" {
		ctx.SetLoggingLevel(pkg.DebugLogLevel)
	}

	scanner, err := pkg.NewScanner(&pkg.NewScannerInput{
		Config:    svcAccountCfg,
		AccountId: accountId,
		Bucket:    bucket,
	})
	if err != nil {
		return fmt.Errorf("creating scanner: %w", err)
	}

	regions, err := GetEnabledRegions(sandboxAccountCfg, ctx)
	if err != nil {
		return fmt.Errorf("getting enabled regions: %w", err)
	}

	h := &handler{
		ctx:        ctx,
		iam:        iam.NewFromConfig(sandboxAccountCfg),
		cloudtrail: GetCloudtrailClients(sandboxAccountCfg, regions),
		scanner:    scanner,
		secret:     pkg.Must(pkg.GetOrGenerateSecret(ctx, ssm.NewFromConfig(svcAccountCfg), secretName)),
	}
	ctx.Debug.Printf("account id: %s, bucket: %s", h.scanner.AccountId, h.scanner.BucketName)

	sub, err := fs.Sub(htmlFs, "html")
	if err != nil {
		return fmt.Errorf("getting sub filesystem: %w", err)
	}
	prefix := "/" + superSecretPathPrefix
	mux := http.NewServeMux()

	mux.Handle(prefix+"/", http.StripPrefix(prefix, http.FileServerFS(sub)))
	mux.HandleFunc(prefix+"/role/", h.provisionRole)
	mux.HandleFunc(prefix+"/role/{name}", h.provisionRole)
	mux.HandleFunc(prefix+"/poll/{token}", h.pollEvents)

	if _, ok := os.LookupEnv("AWS_LAMBDA_FUNCTION_NAME"); ok {
		ctx.Debug.Printf("running in lambda mode")
		lambdaurl.Start(mux)
	} else {
		ctx.Debug.Printf("running in web server mode")
		err := http.ListenAndServe(":8080", mux)
		if err != nil {
			return fmt.Errorf("listening and serving: %w", err)
		}
	}

	return nil
}

func GetCloudtrailClients(cfg aws.Config, regions []string) map[string]*cloudtrail.Client {
	clients := map[string]*cloudtrail.Client{}
	for _, region := range regions {
		clients[region] = cloudtrail.NewFromConfig(cfg, func(opts *cloudtrail.Options) {
			opts.Region = region
		})
	}
	return clients
}

type handler struct {
	ctx        *pkg.Context
	iam        *iam.Client
	cloudtrail map[string]*cloudtrail.Client
	accountId  string
	scanner    *pkg.Scanner
	secret     []byte
}

// NOTE: We're using GET requests here because cloudFront + lambda urls seem to have issues with POST requests.
//
//	See: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-lambda.html#create-oac-overview-lambda
func (h *handler) provisionRole(w http.ResponseWriter, r *http.Request) {
	roleName := r.PathValue("name")
	h.ctx.Debug.Printf("got request to create role %s", roleName)

	requireExternalId := false
	if v := r.URL.Query().Get("requireExternalId"); strings.ToLower(v) != "true" {
		requireExternalId = true
	}

	result, err := pkg.CreateRole(h.ctx, h.iam, roleName, requireExternalId, h.secret)
	if err != nil {
		h.ctx.Error.Printf("creating role: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	resp, err := json.Marshal(result)
	if err != nil {
		h.ctx.Error.Printf("marshalling result: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if _, err := w.Write(resp); err != nil {
		h.ctx.Error.Printf("writing response: %v", err)
	}
}

func (h *handler) pollEvents(w http.ResponseWriter, r *http.Request) {
	h.ctx.Debug.Printf("got request to poll events with token %s", r.PathValue("token"))

	result, err := pkg.PollEvents(h.ctx, &pkg.PollEventsInput{
		Token:      r.PathValue("token"),
		Iam:        h.iam,
		CloudTrail: h.cloudtrail,
		Scanner:    h.scanner,
		Secret:     h.secret,
	})
	if err != nil {
		h.ctx.Error.Printf("polling events: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	resp, err := json.Marshal(result)
	if err != nil {
		h.ctx.Error.Printf("marshalling params: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}

	if _, err := w.Write(resp); err != nil {
		h.ctx.Error.Printf("writing response: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}

	return
}

func GetEnabledRegions(cfg aws.Config, ctx *pkg.Context) ([]string, error) {
	var regions []string
	ec2Client := ec2.NewFromConfig(cfg)
	resp, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, fmt.Errorf("describing regions: %w", err)
	}
	for _, region := range resp.Regions {
		regions = append(regions, *region.RegionName)
	}
	return regions, nil
}
