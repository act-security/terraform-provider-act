package provider

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const (
	azureLogSourceTitle   = "Azure log source"
	stoppedCollectingLogs = "Act stopped collecting the logs and removed the Event Hubs it read."
)

type azureLogSourceModel struct {
	ID                   types.String   `tfsdk:"id"`
	DeploymentID         types.String   `tfsdk:"deployment_id"`
	EventsSubscriptionID types.String   `tfsdk:"events_subscription_id"`
	ActivityLogs         types.Bool     `tfsdk:"activity_logs"`
	EntraIDLogs          types.Bool     `tfsdk:"entra_id_logs"`
	EventHubs            types.List     `tfsdk:"event_hubs"`
	Timeouts             timeouts.Value `tfsdk:"timeouts"`
}

var eventHubAttributeTypes = map[string]attr.Type{
	"namespace": types.StringType,
	"event_hub": types.StringType,
	"data_type": types.StringType,
	"enabled":   types.BoolType,
}

var (
	_ resource.ResourceWithConfigure      = (*azureLogSourceResource)(nil)
	_ resource.ResourceWithImportState    = (*azureLogSourceResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*azureLogSourceResource)(nil)
	_ resource.ResourceWithValidateConfig = (*azureLogSourceResource)(nil)
)

type azureLogSourceResource struct {
	data *ProviderData
}

func NewAzureLogSourceResource() resource.Resource {
	return &azureLogSourceResource{}
}

func (r *azureLogSourceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_log_source"
}

func (r *azureLogSourceResource) typeName() string {
	return "act_azure_log_source"
}

func (r *azureLogSourceResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Collects the tenant-wide Azure activity logs and Entra ID logs of an `act_azure_deployment` through Event Hubs. Act verifies that it can read the Event Hubs before it registers them, so the apply fails and nothing changes when Act cannot use them.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The deployment ID, equal to `deployment_id`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"deployment_id": schema.StringAttribute{
				MarkdownDescription: "The ID of the `act_azure_deployment` that collects the logs. It must be `active`. Changing it replaces the log source.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"events_subscription_id": schema.StringAttribute{
				MarkdownDescription: "The subscription that holds the Event Hub namespace the logs stream to, a lowercase UUID. Changing it updates the log source in place and Act verifies the Event Hubs again. Act does not return it when it is read, so Terraform keeps the value from your configuration: after an import, the first apply sends it once.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			},
			"activity_logs": schema.BoolAttribute{
				MarkdownDescription: "Collect the Azure activity logs. Defaults to `false`. Set it or `entra_id_logs`, or both. Changing it updates the log source in place; setting it to `false` stops collecting the stream.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"entra_id_logs": schema.BoolAttribute{
				MarkdownDescription: "Collect the Entra ID sign-in and audit logs. Defaults to `false`. Set it or `activity_logs`, or both. Changing it updates the log source in place; setting it to `false` stops collecting the stream.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"event_hubs": schema.ListNestedAttribute{
				MarkdownDescription: "The Event Hubs Act collects from.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"namespace": schema.StringAttribute{MarkdownDescription: "The fully qualified host of the Event Hub namespace.", Computed: true},
					"event_hub": schema.StringAttribute{MarkdownDescription: "The Event Hub name.", Computed: true},
					"data_type": schema.StringAttribute{MarkdownDescription: "`activity_logs` or `entra_id_logs`.", Computed: true},
					"enabled":   schema.BoolAttribute{MarkdownDescription: "Whether Act collects from it.", Computed: true},
				}},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Update: true}),
		},
	}
}

func (r *azureLogSourceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *azureLogSourceResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config azureLogSourceModel
	if resp.Diagnostics.Append(req.Config.Get(ctx, &config)...); resp.Diagnostics.HasError() {
		return
	}
	if config.ActivityLogs.IsUnknown() || config.EntraIDLogs.IsUnknown() || config.collectsAnyStream() {
		return
	}
	resp.Diagnostics.AddAttributeError(path.Root("activity_logs"), "No log stream to collect", "Set activity_logs, entra_id_logs or both to true. To stop collecting every stream, remove the resource.")
}

func (r *azureLogSourceResource) ModifyPlan(_ context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	r.writeAccess().warnAtPlan(r.data, req, resp)
}

func (r *azureLogSourceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.writeAccess().refuseAtApply(r.data, "creates", &resp.Diagnostics) {
		return
	}
	var plan azureLogSourceModel
	if resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...); resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, logSourceWrite{model: &plan, action: createAction, timeout: plan.Timeouts.Create, state: &resp.State, diags: &resp.Diagnostics})
}

func (r *azureLogSourceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state azureLogSourceModel
	if resp.Diagnostics.Append(req.State.Get(ctx, &state)...); resp.Diagnostics.HasError() {
		return
	}
	source, err := r.data.Client.GetAzureLogSource(ctx, state.ID.ValueString())
	switch {
	case err != nil:
		resp.Diagnostics.AddError("Reading the "+azureLogSourceTitle+" failed", err.Error())
	case source == nil || (!source.ActivityLogs && !source.EntraIDLogs):
		resp.State.RemoveResource(ctx)
	default:
		state.writeFrom(*source, &resp.Diagnostics)
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	}
}

func (r *azureLogSourceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.writeAccess().refuseAtApply(r.data, "changes", &resp.Diagnostics) {
		return
	}
	var plan azureLogSourceModel
	if resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...); resp.Diagnostics.HasError() {
		return
	}
	r.put(ctx, logSourceWrite{model: &plan, action: "update", timeout: plan.Timeouts.Update, state: &resp.State, diags: &resp.Diagnostics})
}

func (r *azureLogSourceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.writeAccess().refuseAtApply(r.data, "destroys", &resp.Diagnostics) {
		return
	}
	var state azureLogSourceModel
	if resp.Diagnostics.Append(req.State.Get(ctx, &state)...); resp.Diagnostics.HasError() {
		return
	}
	cleanup, err := r.data.Client.DeleteAzureLogSource(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Removing the "+azureLogSourceTitle+" failed", err.Error())
		return
	}
	reportCleanup(cleanupReport{summary: "Act stopped collecting " + state.label(), done: stoppedCollectingLogs, side: azureLogsWording.side, items: cleanup}, &resp.Diagnostics)
}

func (r *azureLogSourceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if !uuidPattern.MatchString(id) {
		resp.Diagnostics.AddError("Invalid import ID", "Use the ID of the Azure deployment, a lowercase UUID.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("deployment_id"), id)...)
}

type logSourceWrite struct {
	model   *azureLogSourceModel
	action  string
	timeout func(context.Context, time.Duration) (time.Duration, diag.Diagnostics)
	state   *tfsdk.State
	diags   *diag.Diagnostics
}

func (r *azureLogSourceResource) put(ctx context.Context, w logSourceWrite) {
	ctx, cancel, ok := withAzureTimeout(ctx, w.timeout, w.diags)
	if !ok {
		return
	}
	defer cancel()
	request := client.AzureLogSourcePutRequest{DeploymentID: w.model.DeploymentID.ValueString(), Body: w.model.putBody()}
	var source *apigen.AzureLogSource
	outcome, err := azureVerification.run(ctx, func(ctx context.Context) error {
		var callErr error
		source, callErr = r.data.Client.PutAzureLogSource(ctx, request)
		return callErr
	})
	if err != nil {
		r.addWriteError(w, writeFailure{action: w.action, target: w.model.label(), outcome: outcome, err: err})
		return
	}
	w.model.ID = w.model.DeploymentID
	w.model.writeFrom(*source, w.diags)
	w.diags.Append(w.state.Set(ctx, w.model)...)
}

func (r *azureLogSourceResource) addWriteError(w logSourceWrite, failure writeFailure) {
	var apiErr *client.APIError
	if asAPIError(failure.err, &apiErr) && apiErr.Code == string(apigen.ErrorEnvelopeErrorCodeConflict) {
		w.diags.AddAttributeError(
			path.Root("deployment_id"),
			fmt.Sprintf("Could not %s the %s", failure.action, azureLogSourceTitle),
			fmt.Sprintf("Act collects logs only through an active deployment, and deployment %s is not active: %s Approve Act or fix the deployment first, then apply again.", w.model.DeploymentID.ValueString(), asSentence(apiErr.Message)),
		)
		return
	}
	r.errors().addWriteError(w.diags, failure)
}

func (r *azureLogSourceResource) errors() deploymentErrors {
	return deploymentErrors{
		title:      azureLogSourceTitle,
		typeName:   r.typeName(),
		wording:    azureLogsWording,
		credential: wireAttribute{wire: "eventsSubscriptionId", name: "events_subscription_id"},
		attributes: map[string]string{
			"eventsSubscriptionId": "events_subscription_id",
			"activityLogs":         "activity_logs",
			"entraIdLogs":          "entra_id_logs",
		},
	}
}

func (r *azureLogSourceResource) writeAccess() writeAccess {
	return writeAccess{scope: deploymentsWriteScope, typeName: r.typeName()}
}

func (m *azureLogSourceModel) collectsAnyStream() bool {
	return m.ActivityLogs.ValueBool() || m.EntraIDLogs.ValueBool()
}

func (m *azureLogSourceModel) label() string {
	return "the log source of Azure deployment " + m.DeploymentID.ValueString()
}

func (m *azureLogSourceModel) putBody() apigen.AzureLogSourcePut {
	return apigen.AzureLogSourcePut{
		EventsSubscriptionID: m.EventsSubscriptionID.ValueString(),
		ActivityLogs:         m.ActivityLogs.ValueBool(),
		EntraIDLogs:          m.EntraIDLogs.ValueBool(),
	}
}

func (m *azureLogSourceModel) writeFrom(source apigen.AzureLogSource, diags *diag.Diagnostics) {
	m.ID = types.StringValue(source.DeploymentID)
	m.DeploymentID = types.StringValue(source.DeploymentID)
	m.ActivityLogs = types.BoolValue(source.ActivityLogs)
	m.EntraIDLogs = types.BoolValue(source.EntraIDLogs)
	hubs := make([]attr.Value, 0, len(source.EventHubs))
	for _, hub := range source.EventHubs {
		value, hubDiags := types.ObjectValue(eventHubAttributeTypes, map[string]attr.Value{
			"namespace": types.StringValue(hub.Namespace),
			"event_hub": types.StringValue(hub.EventHub),
			"data_type": types.StringValue(string(hub.DataType)),
			"enabled":   types.BoolValue(hub.Enabled),
		})
		diags.Append(hubDiags...)
		hubs = append(hubs, value)
	}
	list, listDiags := types.ListValue(types.ObjectType{AttrTypes: eventHubAttributeTypes}, hubs)
	diags.Append(listDiags...)
	m.EventHubs = list
}
