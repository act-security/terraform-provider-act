package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"

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

var (
	tenantIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	regionPattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

var _ provider.Provider = (*actProvider)(nil)

type actProvider struct {
	version string
}

type providerModel struct {
	TenantID     types.String `tfsdk:"tenant_id"`
	Region       types.String `tfsdk:"region"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
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
		MarkdownDescription: "The Act provider manages Act Security deployments as code. It authenticates with an Act API key at the Act STS (`auth.act.security`), which also tells it which regional public API serves the key's tenant.",
		Attributes: map[string]schema.Attribute{
			"tenant_id": schema.StringAttribute{
				MarkdownDescription: "The Act tenant ID, a lowercase UUID. Can also be set with `ACT_TENANT_ID`. Optional: the provider reads the tenant from the API key's token. When set, the provider fails if the key belongs to another tenant.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(tenantIDPattern, "must be a lowercase UUID")},
			},
			"region": schema.StringAttribute{
				MarkdownDescription: "The Act region the tenant lives in, such as `us1` or `eu1`. Can also be set with `ACT_REGION`. Optional: when set, the provider fails if the tenant lives elsewhere. The API endpoint always comes from the STS.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(regionPattern, "must be a lowercase region name such as us1")},
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "The API key's client ID, from Settings → API keys in the Act console. Can also be set with `ACT_CLIENT_ID`.",
				Optional:            true,
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "The API key's client secret. Can also be set with `ACT_CLIENT_SECRET`, which keeps it out of the configuration.",
				Optional:            true,
				Sensitive:           true,
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
	for _, v := range []types.String{cfg.TenantID, cfg.Region, cfg.ClientID, cfg.ClientSecret} {
		if v.IsUnknown() {
			return
		}
	}

	tenantID := valueOrEnv(cfg.TenantID, "ACT_TENANT_ID")
	region := valueOrEnv(cfg.Region, "ACT_REGION")
	clientID := valueOrEnv(cfg.ClientID, "ACT_CLIENT_ID")
	clientSecret := valueOrEnv(cfg.ClientSecret, "ACT_CLIENT_SECRET")

	requireValue(resp, "client_id", "ACT_CLIENT_ID", clientID)
	requireValue(resp, "client_secret", "ACT_CLIENT_SECRET", clientSecret)
	if tenantID != "" && !tenantIDPattern.MatchString(tenantID) {
		resp.Diagnostics.AddAttributeError(path.Root("tenant_id"), "Invalid tenant_id", "tenant_id must be a lowercase UUID.")
	}
	if region != "" && !regionPattern.MatchString(region) {
		resp.Diagnostics.AddAttributeError(path.Root("region"), "Invalid region", "region must be a lowercase region name such as us1.")
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

	httpClient := client.NewHTTPClient()
	userAgent := fmt.Sprintf("terraform-provider-act/%s terraform/%s", p.version, req.TerraformVersion)
	session, err := auth.NewSession(ctx, auth.Config{
		Endpoint:     endpoint,
		TenantID:     tenantID,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Region:       region,
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
	if region != "" && whoami.Region != nil && *whoami.Region != region {
		resp.Diagnostics.AddError("Act region mismatch", fmt.Sprintf("The Act API serves region %q, but the provider sets region %q.", *whoami.Region, region))
		return
	}

	data := &ProviderData{Client: apiClient, Whoami: whoami}
	resp.DataSourceData = data
	resp.ResourceData = data
}

func (p *actProvider) Resources(context.Context) []func() resource.Resource {
	return nil
}

func (p *actProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCurrentIdentityDataSource,
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
