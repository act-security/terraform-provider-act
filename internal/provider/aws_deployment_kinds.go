package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const stackSetTargetLimit = 850

type awsAccountDeploymentModel struct {
	awsDeploymentCommon
	AccountID types.String `tfsdk:"account_id"`
}

type awsOrganizationDeploymentModel struct {
	awsDeploymentCommon
	OrganizationID        types.String `tfsdk:"organization_id"`
	RootID                types.String `tfsdk:"root_id"`
	OrganizationalUnitIDs types.Set    `tfsdk:"organizational_unit_ids"`
	ExcludedAccountIDs    types.Set    `tfsdk:"excluded_account_ids"`
	MemberRoleName        types.String `tfsdk:"member_role_name"`
	MemberRolePath        types.String `tfsdk:"member_role_path"`
	ManagementAccountID   types.String `tfsdk:"management_account_id"`
}

var (
	_ resource.ResourceWithConfigure      = (*awsDeploymentResource[awsAccountDeploymentModel, *awsAccountDeploymentModel])(nil)
	_ resource.ResourceWithImportState    = (*awsDeploymentResource[awsAccountDeploymentModel, *awsAccountDeploymentModel])(nil)
	_ resource.ResourceWithModifyPlan     = (*awsDeploymentResource[awsAccountDeploymentModel, *awsAccountDeploymentModel])(nil)
	_ resource.ResourceWithValidateConfig = (*awsDeploymentResource[awsAccountDeploymentModel, *awsAccountDeploymentModel])(nil)
)

func NewAwsAccountDeploymentResource() resource.Resource {
	return &awsDeploymentResource[awsAccountDeploymentModel, *awsAccountDeploymentModel]{kind: awsDeploymentKind{
		suffix:            "aws_account_deployment",
		title:             "AWS account",
		description:       "Connects one AWS account to Act through an IAM role in that account. Act verifies the role before it stores anything, so the apply fails and nothing is created when Act cannot use it.",
		protectByDefault:  false,
		scope:             apigen.DeploymentScopeAccount,
		importFormats:     "the deployment ID, a lowercase UUID, or the 12-digit account ID",
		importKey:         awsAccountIDPattern.MatchString,
		wrongScopeMessage: "is an AWS organization deployment. Manage it with act_aws_organization_deployment.",
		targetAttributes: func() map[string]schema.Attribute {
			return map[string]schema.Attribute{
				"account_id": schema.StringAttribute{
					MarkdownDescription: "The 12-digit AWS account ID. It must be the account of `role_arn`. Changing it replaces the deployment.",
					Required:            true,
					Validators:          []validator.String{stringvalidator.RegexMatches(awsAccountIDPattern, "must be a 12-digit AWS account ID")},
					PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				},
			}
		},
	}}
}

func NewAwsOrganizationDeploymentResource() resource.Resource {
	return &awsDeploymentResource[awsOrganizationDeploymentModel, *awsOrganizationDeploymentModel]{kind: awsDeploymentKind{
		suffix:            "aws_organization_deployment",
		title:             "AWS organization",
		description:       "Connects an AWS organization to Act, either the whole root or a set of organizational units, through an IAM role in the management account or a StackSets delegated administrator account. Act verifies the role and the organization before it stores anything.",
		protectByDefault:  true,
		scope:             apigen.DeploymentScopeOrganization,
		importFormats:     "the deployment ID, a lowercase UUID, the organization ID (`o-...`) or the root ID (`r-...`)",
		importKey:         func(id string) bool { return awsOrgIDPattern.MatchString(id) || awsRootIDPattern.MatchString(id) },
		wrongScopeMessage: "is an AWS account deployment. Manage it with act_aws_account_deployment.",
		targetAttributes:  organizationAttributes,
	}}
}

func organizationAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"organization_id": schema.StringAttribute{
			MarkdownDescription: "The AWS organization ID, `o-` followed by 10 to 32 characters. Act checks that the role's account belongs to it. Changing it replaces the deployment.",
			Required:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(awsOrgIDPattern, "must be an AWS organization ID")},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"root_id": schema.StringAttribute{
			MarkdownDescription: "The organization root ID, `r-...`, to cover every account. Set this or `organizational_unit_ids`. Changing the scope updates the deployment in place and Act verifies it again.",
			Optional:            true,
			Validators: []validator.String{
				stringvalidator.RegexMatches(awsRootIDPattern, "must be an AWS organization root ID"),
				stringvalidator.ExactlyOneOf(path.MatchRoot("organizational_unit_ids")),
			},
		},
		"organizational_unit_ids": schema.SetAttribute{
			MarkdownDescription: "The organizational units to cover, `ou-...`. Set this or `root_id`. To leave a sandbox OU out, list the other OUs.",
			ElementType:         types.StringType,
			Optional:            true,
			Validators: []validator.Set{
				setvalidator.SizeAtLeast(1),
				setvalidator.ValueStringsAre(stringvalidator.RegexMatches(awsOUIDPattern, "must be an organizational unit ID")),
				stackSetTargetValidator{},
			},
		},
		"excluded_account_ids": schema.SetAttribute{
			MarkdownDescription: "Member accounts Act leaves out, as 12-digit IDs.",
			ElementType:         types.StringType,
			Optional:            true,
			Validators: []validator.Set{
				setvalidator.SizeAtLeast(1),
				setvalidator.ValueStringsAre(stringvalidator.RegexMatches(awsAccountIDPattern, "must be a 12-digit AWS account ID")),
			},
		},
		"member_role_name": schema.StringAttribute{
			MarkdownDescription: "The name of the role in each member account. Defaults to `ActSecurityRole-<deployment_id>`. Set it when another system, such as Account Factory for Terraform or Control Tower, creates the member roles.",
			Optional:            true,
			Computed:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(awsRoleNamePattern, "must be an IAM role name")},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"member_role_path": schema.StringAttribute{
			MarkdownDescription: "The IAM path of the member roles. Defaults to `/`.",
			Optional:            true,
			Computed:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(awsRolePathPattern, "must be an IAM path that starts and ends with /")},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"management_account_id": schema.StringAttribute{
			MarkdownDescription: "The organization's management account, as AWS reports it.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
	}
}

func (m *awsAccountDeploymentModel) common() *awsDeploymentCommon { return &m.awsDeploymentCommon }

func (m *awsAccountDeploymentModel) targetLabel() string {
	return "AWS account " + m.AccountID.ValueString()
}

func (m *awsAccountDeploymentModel) targetKey() types.String { return m.AccountID }

func (m *awsAccountDeploymentModel) setTarget(_ context.Context, body *apigen.AwsDeploymentCreate, _ *diag.Diagnostics) {
	account := m.AccountID.ValueString()
	body.AccountID = &account
}

func (m *awsAccountDeploymentModel) patchTarget(context.Context, awsDeploymentModel, client.AwsDeploymentPatch, *diag.Diagnostics) {
}

func (m *awsAccountDeploymentModel) readTarget(_ context.Context, item apigen.AwsDeployment, _ *diag.Diagnostics) {
	m.AccountID = types.StringPointerValue(item.AccountID)
}

func (m *awsAccountDeploymentModel) sameTarget(other awsDeploymentModel) bool {
	o, ok := other.(*awsAccountDeploymentModel)
	return ok && m.AccountID.Equal(o.AccountID)
}

func (m *awsAccountDeploymentModel) validate(diags *diag.Diagnostics) {
	if m.AccountID.IsUnknown() || m.AccountID.IsNull() || m.RoleArn.IsUnknown() || m.RoleArn.IsNull() {
		return
	}
	match := awsRoleArnPattern.FindStringSubmatch(m.RoleArn.ValueString())
	if match != nil && match[1] != m.AccountID.ValueString() {
		diags.AddAttributeError(path.Root("role_arn"), "The role is in another account", fmt.Sprintf("role_arn is in account %s, but account_id is %s. Act assumes a role in the account it connects.", match[1], m.AccountID.ValueString()))
	}
}

func (m *awsOrganizationDeploymentModel) common() *awsDeploymentCommon { return &m.awsDeploymentCommon }

func (m *awsOrganizationDeploymentModel) targetLabel() string {
	return "AWS organization " + m.OrganizationID.ValueString()
}

func (m *awsOrganizationDeploymentModel) targetKey() types.String { return m.OrganizationID }

func (m *awsOrganizationDeploymentModel) setTarget(ctx context.Context, body *apigen.AwsDeploymentCreate, diags *diag.Diagnostics) {
	org := &apigen.AwsOrganizationInput{
		OrganizationID:        m.OrganizationID.ValueString(),
		RootID:                knownString(m.RootID),
		OrganizationalUnitIds: stringSlice(ctx, m.OrganizationalUnitIDs, diags),
		ExcludedAccountIds:    stringSlice(ctx, m.ExcludedAccountIDs, diags),
		MemberRoleName:        knownString(m.MemberRoleName),
		MemberRolePath:        knownString(m.MemberRolePath),
	}
	body.Organization = org
}

func (m *awsOrganizationDeploymentModel) patchTarget(ctx context.Context, prior awsDeploymentModel, patch client.AwsDeploymentPatch, diags *diag.Diagnostics) {
	current, ok := prior.(*awsOrganizationDeploymentModel)
	if !ok {
		return
	}
	org := map[string]any{}
	if !m.RootID.IsNull() && !m.RootID.Equal(current.RootID) {
		org["rootId"] = m.RootID.ValueString()
	}
	if !m.OrganizationalUnitIDs.IsNull() && !m.OrganizationalUnitIDs.Equal(current.OrganizationalUnitIDs) {
		org["organizationalUnitIds"] = sliceOrNil(stringSlice(ctx, m.OrganizationalUnitIDs, diags))
	}
	if !m.ExcludedAccountIDs.Equal(current.ExcludedAccountIDs) {
		org["excludedAccountIds"] = sliceOrNil(stringSlice(ctx, m.ExcludedAccountIDs, diags))
	}
	if !m.MemberRoleName.IsUnknown() && !m.MemberRoleName.Equal(current.MemberRoleName) {
		org["memberRoleName"] = m.MemberRoleName.ValueString()
	}
	if !m.MemberRolePath.IsUnknown() && !m.MemberRolePath.Equal(current.MemberRolePath) {
		org["memberRolePath"] = m.MemberRolePath.ValueString()
	}
	if len(org) > 0 {
		patch["organization"] = org
	}
}

func (m *awsOrganizationDeploymentModel) readTarget(ctx context.Context, item apigen.AwsDeployment, diags *diag.Diagnostics) {
	org := item.Organization
	if org == nil {
		return
	}
	m.OrganizationID = types.StringValue(org.OrganizationID)
	m.RootID = types.StringPointerValue(org.RootID)
	m.OrganizationalUnitIDs = nullableStringSet(ctx, org.OrganizationalUnitIds, diags)
	m.ExcludedAccountIDs = nullableStringSet(ctx, org.ExcludedAccountIds, diags)
	m.MemberRoleName = types.StringValue(org.MemberRoleName)
	m.MemberRolePath = types.StringValue(org.MemberRolePath)
	m.ManagementAccountID = types.StringValue(org.ManagementAccountID)
}

func (m *awsOrganizationDeploymentModel) sameTarget(other awsDeploymentModel) bool {
	o, ok := other.(*awsOrganizationDeploymentModel)
	return ok &&
		m.OrganizationID.Equal(o.OrganizationID) &&
		m.RootID.Equal(o.RootID) &&
		m.OrganizationalUnitIDs.Equal(o.OrganizationalUnitIDs) &&
		m.ExcludedAccountIDs.Equal(o.ExcludedAccountIDs) &&
		m.MemberRoleName.Equal(o.MemberRoleName) &&
		m.MemberRolePath.Equal(o.MemberRolePath)
}

func (m *awsOrganizationDeploymentModel) validate(*diag.Diagnostics) {}

type stackSetTargetValidator struct{}

func (stackSetTargetValidator) Description(context.Context) string {
	return fmt.Sprintf("the organizational unit IDs, joined by commas, fit in %d characters", stackSetTargetLimit)
}

func (v stackSetTargetValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (stackSetTargetValidator) ValidateSet(_ context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	ids := []string{}
	for _, element := range req.ConfigValue.Elements() {
		value, ok := element.(types.String)
		if !ok || value.IsUnknown() {
			return
		}
		ids = append(ids, value.ValueString())
	}
	if joined := strings.Join(ids, ","); len(joined) > stackSetTargetLimit {
		resp.Diagnostics.AddAttributeError(req.Path, "Too many organizational units", fmt.Sprintf("The %d organizational unit IDs take %d characters, more than the %d a CloudFormation StackSet accepts as targets. Set root_id to cover the whole organization, and list the accounts to leave out in excluded_account_ids.", len(ids), len(joined), stackSetTargetLimit))
	}
}

func knownString(value types.String) *string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	v := value.ValueString()
	return &v
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func stringSlice(ctx context.Context, value types.Set, diags *diag.Diagnostics) *[]string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	values := []string{}
	diags.Append(value.ElementsAs(ctx, &values, false)...)
	return &values
}

func stringMap(ctx context.Context, value types.Map, diags *diag.Diagnostics) *map[string]string {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	values := map[string]string{}
	diags.Append(value.ElementsAs(ctx, &values, false)...)
	return &values
}

func sliceOrNil(values *[]string) any {
	if values == nil {
		return nil
	}
	return *values
}

func capabilityList(values []string) []apigen.AwsCapability {
	capabilities := make([]apigen.AwsCapability, 0, len(values))
	for _, value := range values {
		capabilities = append(capabilities, apigen.AwsCapability(value))
	}
	return capabilities
}

func stringSet(ctx context.Context, values []string, diags *diag.Diagnostics) types.Set {
	set, setDiags := types.SetValueFrom(ctx, types.StringType, values)
	diags.Append(setDiags...)
	return set
}

func nullableStringSet(ctx context.Context, values *[]string, diags *diag.Diagnostics) types.Set {
	if values == nil {
		return types.SetNull(types.StringType)
	}
	return stringSet(ctx, *values, diags)
}

func nullableStringMap(ctx context.Context, values map[string]string, prior types.Map, diags *diag.Diagnostics) types.Map {
	if len(values) == 0 && (prior.IsNull() || prior.IsUnknown()) {
		return types.MapNull(types.StringType)
	}
	elements := map[string]attr.Value{}
	for key, value := range values {
		elements[key] = types.StringValue(value)
	}
	result, mapDiags := types.MapValue(types.StringType, elements)
	diags.Append(mapDiags...)
	return result
}
