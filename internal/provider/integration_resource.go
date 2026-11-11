package provider

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const (
	privateETag            = "etag"
	privateSecretAppliedAt = "secret_applied_at"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type integrationConfigField struct {
	attr         string
	wire         string
	description  string
	validators   []validator.String
	defaultValue string
}

type integrationSecretField struct {
	attr        string
	wire        string
	description string
	validators  []validator.String
}

type integrationKind struct {
	name        string
	apiType     apigen.InstallableIntegrationType
	title       string
	description string
	config      []integrationConfigField
	secret      integrationSecretField
}

type integrationResource struct {
	kind integrationKind
	data *ProviderData
}

var (
	_ resource.ResourceWithConfigure        = (*integrationResource)(nil)
	_ resource.ResourceWithImportState      = (*integrationResource)(nil)
	_ resource.ResourceWithModifyPlan       = (*integrationResource)(nil)
	_ resource.ResourceWithConfigValidators = (*integrationResource)(nil)
)

func (k integrationKind) secretWO() string        { return k.secret.attr + "_wo" }
func (k integrationKind) secretWOVersion() string { return k.secret.attr + "_wo_version" }
func (k integrationKind) secretUpdatedAt() string { return k.secret.attr + "_updated_at" }

func (r *integrationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.kind.name + "_integration"
}

func (r *integrationResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	k := r.kind
	attributes := map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The installation ID. It stays the same when you rotate `" + k.secret.attr + "` or change a setting, so notification rules can reference it.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"display_name": schema.StringAttribute{
			MarkdownDescription: "The name Act shows for the integration.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"status": schema.StringAttribute{
			MarkdownDescription: "The connection status: `connected`, `pending`, `error` or `disconnected`.",
			Computed:            true,
		},
		"health_reason": schema.StringAttribute{
			MarkdownDescription: "Why the connection is unhealthy, when Act reports a reason. Null while connected.",
			Computed:            true,
		},
		"health_note": schema.StringAttribute{
			MarkdownDescription: "What to do about an unhealthy connection. Null while connected.",
			Computed:            true,
		},
		k.secret.attr: schema.StringAttribute{
			MarkdownDescription: k.secret.description + " Stored in the Terraform state. Set exactly one of `" + k.secret.attr + "` and `" + k.secretWO() + "`; prefer `" + k.secretWO() + "` on Terraform 1.11 and later.",
			Optional:            true,
			Sensitive:           true,
			Validators:          append([]validator.String{stringvalidator.PreferWriteOnlyAttribute(path.MatchRoot(k.secretWO()))}, k.secret.validators...),
		},
		k.secretWO(): schema.StringAttribute{
			MarkdownDescription: k.secret.description + " Write-only: never stored in the plan or the state. Needs Terraform 1.11 or later. Change `" + k.secretWOVersion() + "` to send a new value.",
			Optional:            true,
			Sensitive:           true,
			WriteOnly:           true,
			Validators:          append([]validator.String{stringvalidator.AlsoRequires(path.MatchRoot(k.secretWOVersion()))}, k.secret.validators...),
		},
		k.secretWOVersion(): schema.Int64Attribute{
			MarkdownDescription: "Any number you choose. Changing it sends `" + k.secretWO() + "` to Act again, in place.",
			Optional:            true,
			Validators:          []validator.Int64{int64validator.AlsoRequires(path.MatchRoot(k.secretWO()))},
		},
		k.secretUpdatedAt(): schema.StringAttribute{
			MarkdownDescription: "When Act last stored a new `" + k.secret.attr + "`, in RFC 3339. When it moves without Terraform, for example after a rotation in the Act console, the next plan sends the configured value again.",
			Computed:            true,
		},
	}
	for _, field := range k.config {
		attribute := schema.StringAttribute{
			MarkdownDescription: field.description,
			Validators:          field.validators,
		}
		if field.defaultValue == "" {
			attribute.Required = true
		} else {
			attribute.Optional = true
			attribute.Computed = true
			attribute.Default = stringdefault.StaticString(field.defaultValue)
		}
		attributes[field.attr] = attribute
	}
	resp.Schema = schema.Schema{MarkdownDescription: k.description, Attributes: attributes}
}

func (r *integrationResource) ConfigValidators(context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(path.MatchRoot(r.kind.secret.attr), path.MatchRoot(r.kind.secretWO())),
	}
}

func (r *integrationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*ProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", "The provider passed data of an unexpected type.")
		return
	}
	r.data = data
}

type privateGetter interface {
	GetKey(ctx context.Context, key string) ([]byte, diag.Diagnostics)
}

type privateSetter interface {
	SetKey(ctx context.Context, key string, value []byte) diag.Diagnostics
}

func privateString(ctx context.Context, private privateGetter, key string) string {
	raw, _ := private.GetKey(ctx, key)
	var value string
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return ""
	}
	return value
}

func setPrivate(ctx context.Context, private privateSetter, key, value string, diags *diag.Diagnostics) {
	raw, err := json.Marshal(value)
	if err != nil {
		diags.AddError("Private state", err.Error())
		return
	}
	diags.Append(private.SetKey(ctx, key, raw)...)
}

type attributeGetter interface {
	GetAttribute(ctx context.Context, p path.Path, target any) diag.Diagnostics
}

type attributeSetter interface {
	SetAttribute(ctx context.Context, p path.Path, value any) diag.Diagnostics
}

func stringAt(ctx context.Context, source attributeGetter, attribute string, diags *diag.Diagnostics) types.String {
	var value types.String
	diags.Append(source.GetAttribute(ctx, path.Root(attribute), &value)...)
	return value
}

func int64At(ctx context.Context, source attributeGetter, attribute string, diags *diag.Diagnostics) types.Int64 {
	var value types.Int64
	diags.Append(source.GetAttribute(ctx, path.Root(attribute), &value)...)
	return value
}

func (r *integrationResource) configValues(ctx context.Context, source attributeGetter, diags *diag.Diagnostics) map[string]string {
	values := map[string]string{}
	for _, field := range r.kind.config {
		value := stringAt(ctx, source, field.attr, diags)
		if !value.IsNull() && !value.IsUnknown() {
			values[field.wire] = value.ValueString()
		}
	}
	return values
}

func (r *integrationResource) secretValue(ctx context.Context, config, plan attributeGetter, diags *diag.Diagnostics) string {
	if written := stringAt(ctx, config, r.kind.secretWO(), diags); !written.IsNull() && !written.IsUnknown() {
		return written.ValueString()
	}
	return stringAt(ctx, plan, r.kind.secret.attr, diags).ValueString()
}

func apiConfig(values map[string]string) *apigen.IntegrationConfig {
	if len(values) == 0 {
		return nil
	}
	config := &apigen.IntegrationConfig{}
	for wire, value := range values {
		v := value
		switch wire {
		case "baseUrl":
			config.BaseURL = &v
		case "email":
			email := apigenEmail(v)
			config.Email = &email
		case "clientId":
			config.ClientID = &v
		case "apiEndpointUrl":
			config.APIEndpointURL = &v
		case "hecUrl":
			config.HecURL = &v
		case "tlsVerification":
			tls := apigen.SplunkTLSVerification(v)
			config.TLSVerification = &tls
		}
	}
	return config
}

func apiSecrets(wire, value string) apigen.IntegrationSecrets {
	secrets := apigen.IntegrationSecrets{}
	switch wire {
	case "botToken":
		secrets.BotToken = &value
	case "apiToken":
		secrets.APIToken = &value
	case "clientSecret":
		secrets.ClientSecret = &value
	case "hecToken":
		secrets.HecToken = &value
	}
	return secrets
}

func (r *integrationResource) writeComputed(ctx context.Context, target attributeSetter, item apigen.Integration, diags *diag.Diagnostics) {
	set := func(attribute string, value attr.Value) {
		diags.Append(target.SetAttribute(ctx, path.Root(attribute), value)...)
	}
	set("id", types.StringValue(item.ID))
	set("display_name", types.StringValue(item.DisplayName))
	set("status", types.StringValue(string(item.Status)))
	reason, note := types.StringNull(), types.StringNull()
	if item.Health != nil {
		reason, note = types.StringPointerValue(item.Health.Reason), types.StringPointerValue(item.Health.Note)
	}
	set("health_reason", reason)
	set("health_note", note)
	updatedAt := types.StringNull()
	if state, ok := item.Secrets[r.kind.secret.wire]; ok {
		updatedAt = types.StringValue(state.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	set(r.kind.secretUpdatedAt(), updatedAt)
	for _, field := range r.kind.config {
		if value, ok := item.Config[field.wire]; ok {
			set(field.attr, types.StringValue(value))
		}
	}
}

func (r *integrationResource) secretAppliedAt(item apigen.Integration) string {
	if state, ok := item.Secrets[r.kind.secret.wire]; ok {
		return state.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return ""
}

func (r *integrationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	diags := &resp.Diagnostics
	values := r.configValues(ctx, req.Plan, diags)
	secret := r.secretValue(ctx, req.Config, req.Plan, diags)
	if diags.HasError() {
		return
	}
	body := apigen.IntegrationCreate{
		Type:    r.kind.apiType,
		Config:  apiConfig(values),
		Secrets: apiSecrets(r.kind.secret.wire, secret),
	}
	result, err := r.data.Client.CreateIntegration(ctx, body, idempotencyKey())
	if err != nil {
		r.addWriteError(diags, "create", err)
		return
	}
	resp.State.Raw = req.Plan.Raw.Copy()
	r.writeComputed(ctx, &resp.State, result.Integration, diags)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, diags)
	setPrivate(ctx, resp.Private, privateSecretAppliedAt, r.secretAppliedAt(result.Integration), diags)
}

func (r *integrationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	diags := &resp.Diagnostics
	id := stringAt(ctx, req.State, "id", diags)
	if diags.HasError() {
		return
	}
	result, err := r.data.Client.GetIntegration(ctx, id.ValueString())
	if err != nil {
		diags.AddError("Reading the "+r.kind.title+" integration failed", err.Error())
		return
	}
	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	if string(result.Integration.Type) != string(r.kind.apiType) {
		diags.AddError("Wrong integration type", fmt.Sprintf("Integration %s is a %s integration, not %s.", id.ValueString(), result.Integration.Type, r.kind.apiType))
		return
	}
	r.writeComputed(ctx, &resp.State, result.Integration, diags)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, diags)
	if result.Integration.Status == apigen.IntegrationStatusError {
		diags.AddWarning(r.kind.title+" integration is unhealthy", fmt.Sprintf("Act reports the connection as %s: %s", result.Integration.Status, healthNote(result.Integration)))
	}
}

func healthNote(item apigen.Integration) string {
	if item.Health != nil && item.Health.Note != nil {
		return *item.Health.Note
	}
	return "no detail"
}

func (r *integrationResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	diags := &resp.Diagnostics
	remote := stringAt(ctx, req.State, r.kind.secretUpdatedAt(), diags)
	applied := privateString(ctx, req.Private, privateSecretAppliedAt)
	if diags.HasError() || remote.IsNull() || applied == "" || remote.ValueString() == applied {
		return
	}
	diags.Append(resp.Plan.SetAttribute(ctx, path.Root(r.kind.secretUpdatedAt()), types.StringUnknown())...)
	diags.AddWarning(
		"The "+r.kind.secret.attr+" changed outside Terraform",
		"Act stored a new "+r.kind.secret.attr+" at "+remote.ValueString()+" that this configuration did not send. This apply sends the configured value again. To keep a value set in the Act console, remove the resource from Terraform instead.",
	)
}

func (r *integrationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	diags := &resp.Diagnostics
	id := stringAt(ctx, req.State, "id", diags)
	planned := r.configValues(ctx, req.Plan, diags)
	current := r.configValues(ctx, req.State, diags)
	changed := map[string]string{}
	for wire, value := range planned {
		if current[wire] != value {
			changed[wire] = value
		}
	}
	plaintextChanged := !stringAt(ctx, req.Plan, r.kind.secret.attr, diags).Equal(stringAt(ctx, req.State, r.kind.secret.attr, diags))
	versionChanged := !int64At(ctx, req.Plan, r.kind.secretWOVersion(), diags).Equal(int64At(ctx, req.State, r.kind.secretWOVersion(), diags))
	drifted := stringAt(ctx, req.Plan, r.kind.secretUpdatedAt(), diags).IsUnknown()
	if diags.HasError() {
		return
	}
	patch := apigen.IntegrationPatch{Type: r.kind.apiType, Config: apiConfig(changed)}
	if len(changed) > 0 || plaintextChanged || versionChanged || drifted {
		secrets := apiSecrets(r.kind.secret.wire, r.secretValue(ctx, req.Config, req.Plan, diags))
		patch.Secrets = &secrets
	}
	result, err := r.data.Client.UpdateIntegration(ctx, id.ValueString(), privateString(ctx, req.Private, privateETag), patch)
	if err != nil {
		r.addWriteError(diags, "update", err)
		return
	}
	resp.State.Raw = req.Plan.Raw.Copy()
	r.writeComputed(ctx, &resp.State, result.Integration, diags)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, diags)
	setPrivate(ctx, resp.Private, privateSecretAppliedAt, r.secretAppliedAt(result.Integration), diags)
}

func (r *integrationResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := stringAt(ctx, req.State, "id", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.data.Client.DeleteIntegration(ctx, id.ValueString()); err != nil {
		resp.Diagnostics.AddError("Uninstalling the "+r.kind.title+" integration failed", err.Error())
	}
}

func (r *integrationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if id == r.kind.name {
		kind := apigen.IntegrationType(r.kind.apiType)
		items, err := r.data.Client.ListIntegrations(ctx, &kind)
		if err != nil {
			resp.Diagnostics.AddError("Listing integrations failed", err.Error())
			return
		}
		if len(items) == 0 {
			resp.Diagnostics.AddError("No "+r.kind.title+" integration to import", "This tenant has no "+r.kind.title+" integration installed.")
			return
		}
		id = items[0].ID
	}
	if !uuidPattern.MatchString(id) {
		resp.Diagnostics.AddError("Invalid import ID", fmt.Sprintf("Use the integration ID, a lowercase UUID, or %q.", r.kind.name))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func (r *integrationResource) addWriteError(diags *diag.Diagnostics, action string, err error) {
	var apiErr *client.APIError
	summary := fmt.Sprintf("Could not %s the %s integration", action, r.kind.title)
	if !asAPIError(err, &apiErr) {
		diags.AddError(summary, err.Error())
		return
	}
	switch {
	case apiErr.Status == http.StatusConflict && apiErr.Code == "already_exists":
		existing := apiErr.Detail("integrationId")
		diags.AddError(summary, fmt.Sprintf("This tenant already has a %s integration (%s). A tenant has at most one per type. Import it instead:\n\n  terraform import act_%s_integration.<name> %s", r.kind.title, existing, r.kind.name, existing))
	case apiErr.Code == "connection_check_failed":
		diags.AddError(summary, "Act could not connect with these settings, so nothing changed. "+apiErr.Detail("note"))
	case apiErr.Code == "invalid_request":
		if attribute := r.attributeOf(apiErr.Detail("attribute")); attribute != "" {
			diags.AddAttributeError(path.Root(attribute), summary, fmt.Sprintf("Act rejected %s: %s.", attribute, apiErr.Detail("reason")))
			return
		}
		diags.AddError(summary, err.Error())
	case apiErr.Status == http.StatusPreconditionFailed:
		diags.AddError(summary, "The integration changed in Act since Terraform last read it. Run terraform apply again to plan against the current settings.")
	default:
		diags.AddError(summary, err.Error())
	}
}

func (r *integrationResource) attributeOf(wireAttribute string) string {
	name := wireAttribute[strings.LastIndex(wireAttribute, ".")+1:]
	if name == r.kind.secret.wire {
		return r.kind.secret.attr
	}
	for _, field := range r.kind.config {
		if field.wire == name {
			return field.attr
		}
	}
	return ""
}

func idempotencyKey() string {
	return "tf-" + strings.ToLower(rand.Text())
}
