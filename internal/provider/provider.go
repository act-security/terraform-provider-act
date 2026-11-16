package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/auth"
	"github.com/act-security/terraform-provider-act/internal/client"
	"github.com/act-security/terraform-provider-act/internal/retry"
)

var tenantIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var _ provider.Provider = (*actProvider)(nil)

type actProvider struct {
	version string
}

type providerModel struct {
	TenantID          types.String `tfsdk:"tenant_id"`
	ClientID          types.String `tfsdk:"client_id"`
	ClientSecret      types.String `tfsdk:"client_secret"`
	UseOIDC           types.Bool   `tfsdk:"use_oidc"`
	OIDCToken         types.String `tfsdk:"oidc_token"`
	OIDCTokenFilePath types.String `tfsdk:"oidc_token_file_path"`
}

type ProviderData struct {
	Client *client.Client
	Whoami *apigen.Whoami
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &actProvider{version: version}
	}
}

func (p *actProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "act"
	resp.Version = p.version
}

func (p *actProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Act provider connects Terraform to [Act Security](https://act.security). It signs in with an Act API key, or with the CI job's OIDC token instead of the key's secret, and finds the tenant and the regional API on its own.",
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{
				MarkdownDescription: "The Act tenant ID, a lowercase UUID, here or in `ACT_TENANT_ID`. Not needed: the provider reads the tenant from the API key. When set, the provider fails if the key belongs to another tenant.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(tenantIDPattern, "must be a lowercase UUID")},
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "The API key's client ID, from Settings → API keys in the Act console. Required, here or in `ACT_CLIENT_ID`.",
				Optional:            true,
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "The API key's client secret, here or in `ACT_CLIENT_SECRET`, which keeps it out of the configuration. Required unless the provider signs in with an OIDC token; never set both.",
				Optional:            true,
				Sensitive:           true,
			},
			"use_oidc": schema.BoolAttribute{
				MarkdownDescription: "Sign in with the OIDC token of the CI job instead of `client_secret`, here or in `ACT_USE_OIDC`. The provider reads `TFC_WORKLOAD_IDENTITY_TOKEN_ACT`, then `TFC_WORKLOAD_IDENTITY_TOKEN` (HCP Terraform), then requests a token from GitHub Actions for the Act STS audience. The API key needs a trust policy for the job.",
				Optional:            true,
			},
			"oidc_token": schema.StringAttribute{
				MarkdownDescription: "An OIDC token issued to the CI job for the Act STS audience, here or in `ACT_OIDC_TOKEN`. Use it with a CI system the provider does not detect with `use_oidc`.",
				Optional:            true,
				Sensitive:           true,
			},
			"oidc_token_file_path": schema.StringAttribute{
				MarkdownDescription: "A file holding the CI job's OIDC token, here or in `ACT_OIDC_TOKEN_FILE_PATH`. The provider reads it again every time it renews its Act token, so a token the CI system refreshes keeps working.",
				Optional:            true,
			},
		},
	}
}

func (p *actProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, v := range []types.String{cfg.TenantID, cfg.ClientID, cfg.ClientSecret, cfg.OIDCToken, cfg.OIDCTokenFilePath} {
		if v.IsUnknown() {
			return
		}
	}
	if cfg.UseOIDC.IsUnknown() {
		return
	}

	tenantID := valueOrEnv(cfg.TenantID, "ACT_TENANT_ID")
	clientID := valueOrEnv(cfg.ClientID, "ACT_CLIENT_ID")
	httpClient := client.NewHTTPClient()
	credential, credentialErr := resolveCredential(credentialInputs{
		clientSecret:  valueOrEnv(cfg.ClientSecret, "ACT_CLIENT_SECRET"),
		oidcToken:     valueOrEnv(cfg.OIDCToken, "ACT_OIDC_TOKEN"),
		oidcTokenFile: valueOrEnv(cfg.OIDCTokenFilePath, "ACT_OIDC_TOKEN_FILE_PATH"),
		useOIDC:       boolOrEnv(cfg.UseOIDC, "ACT_USE_OIDC"),
	}, ciEnvironment{getenv: os.Getenv, httpClient: httpClient, retry: retry.Default()})

	requireValue(resp, "client_id", "ACT_CLIENT_ID", clientID)
	if credentialErr != nil {
		resp.Diagnostics.AddAttributeError(path.Root("client_secret"), "Missing or conflicting Act credentials", credentialErr.Error())
	}
	if tenantID != "" && !tenantIDPattern.MatchString(tenantID) {
		resp.Diagnostics.AddAttributeError(path.Root("tenant_id"), "Invalid tenant_id", "tenant_id must be a lowercase UUID.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint, err := auth.ResolveEndpoint(os.Getenv("ACT_ENDPOINT"))
	if err != nil {
		resp.Diagnostics.AddError("Invalid Act endpoint", err.Error())
		return
	}
	if endpoint.Unsafe {
		resp.Diagnostics.AddWarning("Unsafe Act endpoint", fmt.Sprintf("The provider talks to the loopback STS %s. Use this only for local development.", endpoint.Origin))
	}

	userAgent := fmt.Sprintf("terraform-provider-act/%s terraform/%s", p.version, req.TerraformVersion)
	session, err := auth.NewSession(ctx, auth.Config{
		Endpoint:     endpoint,
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: credential.clientSecret,
		CIToken:      credential.ciToken,
		HTTPClient:   httpClient,
		UserAgent:    userAgent,
		Retry:        retry.Default(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Act authentication failed", err.Error())
		return
	}
	tflog.Debug(ctx, "Act STS resolved the tenant", map[string]any{"region": session.Region, "public_api_url": session.APIOrigin})

	apiClient, err := client.New(session.APIOrigin, session, httpClient, userAgent, retry.Default())
	if err != nil {
		resp.Diagnostics.AddError("Act API client", err.Error())
		return
	}
	whoami, err := apiClient.Whoami(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Act API whoami failed", err.Error())
		return
	}
	if whoami.TenantID != session.TenantID {
		resp.Diagnostics.AddError("Act tenant mismatch", fmt.Sprintf("The Act API answered for tenant %s, not %s.", whoami.TenantID, session.TenantID))
		return
	}

	data := &ProviderData{Client: apiClient, Whoami: whoami}
	resp.DataSourceData = data
	resp.ResourceData = data
}

func (p *actProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSlackIntegrationResource,
		NewJiraIntegrationResource,
		NewWizIntegrationResource,
		NewSplunkIntegrationResource,
		NewAwsAccountDeploymentResource,
		NewAwsOrganizationDeploymentResource,
		NewNotificationRuleResource,
		NewNotificationRecipientResource,
	}
}

func (p *actProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCurrentIdentityDataSource,
		NewIntegrationDataSource,
		NewIntegrationTypesDataSource,
		NewAwsOnboardingParametersDataSource,
		NewDeploymentDataSource,
		NewDeploymentsDataSource,
		NewDeploymentCoverageDataSource,
		NewDeploymentAccountsDataSource,
		NewUserDataSource,
		NewSlackChannelDataSource,
		NewNotificationEventTypesDataSource,
	}
}

func valueOrEnv(v types.String, env string) string {
	if !v.IsNull() && v.ValueString() != "" {
		return v.ValueString()
	}
	return os.Getenv(env)
}

func requireValue(resp *provider.ConfigureResponse, attr, env, value string) {
	if value == "" {
		resp.Diagnostics.AddAttributeError(path.Root(attr), "Missing "+attr, fmt.Sprintf("Set %s in the provider block or the %s environment variable.", attr, env))
	}
}

func boolOrEnv(v types.Bool, env string) string {
	if !v.IsNull() {
		return strconv.FormatBool(v.ValueBool())
	}
	return os.Getenv(env)
}
