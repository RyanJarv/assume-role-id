package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/lambdaurl"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/ryanjarv/assume-role-id/web/pkg"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
)

var ErrNoSuchPrincipal = errors.New("no such principal")

//go:embed html
var htmlFs embed.FS

func main() {
	err := Run()
	if err != nil {
		log.Fatalln(err)
	}
}

func Run() error {
	ctx := pkg.NewContext(context.Background())
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("loading default config: %w", err)
	}

	if os.Getenv("DEBUG") != "" {
		ctx.SetLoggingLevel(pkg.DebugLogLevel)
	}

	scanner, err := pkg.NewScanner(&pkg.NewScannerInput{
		Config:    cfg,
		AccountId: os.Getenv("ACCOUNT_ID"),
		Bucket:    os.Getenv("BUCKET"),
	})
	if err != nil {
		return fmt.Errorf("creating scanner: %w", err)
	}

	regions, err := GetEnabledRegions(cfg, ctx)
	if err != nil {
		return fmt.Errorf("getting enabled regions: %w", err)
	}

	h := &handler{
		ctx:        ctx,
		iam:        iam.NewFromConfig(cfg),
		cloudtrail: GetCloudtrailClients(cfg, regions),
		scanner:    scanner,
	}
	ctx.Debug.Printf("account id: %s, bucket: %s", h.scanner.AccountId, h.scanner.BucketName)

	sub, err := fs.Sub(htmlFs, "html")
	if err != nil {
		return fmt.Errorf("getting sub filesystem: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.FileServerFS(sub))
	mux.HandleFunc("/role", h.provisionRole)
	mux.HandleFunc("/poll/{name}", h.pollEvents)

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
	cloudtrails := map[string]*cloudtrail.Client{}
	for _, region := range regions {
		cloudtrails[region] = cloudtrail.NewFromConfig(cfg, func(opts *cloudtrail.Options) {
			opts.Region = region
		})
	}
	return cloudtrails
}

type handler struct {
	ctx        *pkg.Context
	iam        *iam.Client
	cloudtrail map[string]*cloudtrail.Client
	accountId  string
	scanner    *pkg.Scanner
}

func (h *handler) provisionRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	all, err := io.ReadAll(r.Body)
	if err != nil {
		h.ctx.Error.Printf("reading body: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}

	req := &pkg.ProvisionRoleRequest{}
	if err = json.Unmarshal(all, req); err != nil {
		h.ctx.Error.Printf("unmarshalling body: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	result, err := pkg.ProvisionRole(h.ctx, h.iam, req)
	if err != nil {
		h.ctx.Error.Printf("provisioning role: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	j, _ := json.Marshal(result)
	w.Write(j)
}

func (h *handler) pollEvents(w http.ResponseWriter, r *http.Request) {
	h.ctx.Debug.Printf("polling events for %s", r.PathValue("name"))

	name := r.PathValue("name")
	params, err := pkg.PollEvents(h.ctx, h.cloudtrail, h.scanner, name)
	if err != nil {
		h.ctx.Error.Printf("provisioning role: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if params == nil {
		http.Error(w, "assume role event not found", http.StatusNotFound)
		return
	} else {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		j, _ := json.Marshal(params)
		w.Write(j)
	}
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
