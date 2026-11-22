package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const memberRoleDeploymentID = "00000000-0000-4000-8000-0000000000b1"

func organizationWithMemberRole(name, rolePath string) *awsOrganizationDeploymentModel {
	model := &awsOrganizationDeploymentModel{
		OrganizationID:        types.StringValue("o-abcdefghij"),
		RootID:                types.StringValue("r-ab12"),
		OrganizationalUnitIDs: types.SetNull(types.StringType),
		ExcludedAccountIDs:    types.SetNull(types.StringType),
		MemberRoleName:        types.StringValue(name),
		MemberRolePath:        types.StringValue(rolePath),
	}
	model.DeploymentID = types.StringValue(memberRoleDeploymentID)
	return model
}

func TestOrganizationCreateBodyLeavesTheMemberRoleToAct(t *testing.T) {
	var diags diag.Diagnostics
	body := apigen.AwsDeploymentCreate{}
	organizationWithMemberRole(actMemberRolePrefix+memberRoleDeploymentID, actMemberRolePath).setTarget(context.Background(), &body, &diags)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if body.Organization.MemberRoleName != nil || body.Organization.MemberRolePath != nil {
		t.Fatalf("create body sends memberRoleName=%v memberRolePath=%v, want neither", body.Organization.MemberRoleName, body.Organization.MemberRolePath)
	}
}

func TestOrganizationPatchLeavesTheMemberRoleToAct(t *testing.T) {
	var diags diag.Diagnostics
	patch := client.DeploymentPatch{}
	prior := organizationWithMemberRole("ActSecurityRole-old", "/old/")
	organizationWithMemberRole(actMemberRolePrefix+memberRoleDeploymentID, actMemberRolePath).patchTarget(context.Background(), prior, patch, &diags)
	if diags.HasError() {
		t.Fatal(diags)
	}
	if organization, ok := patch["organization"]; ok {
		t.Fatalf("patch sends organization=%v, want no organization change", organization)
	}
}

func TestActMemberRoleFollowsTheDeployment(t *testing.T) {
	next := organizationWithMemberRole("ignored", "/ignored/")
	sameDeployment := organizationWithMemberRole("AWSAFTExecution", "/aft/")
	otherDeployment := organizationWithMemberRole("AWSAFTExecution", "/aft/")
	otherDeployment.DeploymentID = types.StringValue("00000000-0000-4000-8000-0000000000b2")
	unknownID := organizationWithMemberRole("ignored", "/ignored/")
	unknownID.DeploymentID = types.StringUnknown()

	tests := []struct {
		name     string
		next     *awsOrganizationDeploymentModel
		prior    awsDeploymentModel
		wantName types.String
		wantPath types.String
	}{
		{name: "create", next: next, prior: nil, wantName: types.StringValue(actMemberRolePrefix + memberRoleDeploymentID), wantPath: types.StringValue(actMemberRolePath)},
		{name: "update keeps the role Act reports", next: next, prior: sameDeployment, wantName: types.StringValue("AWSAFTExecution"), wantPath: types.StringValue("/aft/")},
		{name: "replacement uses the new deployment's role", next: next, prior: otherDeployment, wantName: types.StringValue(actMemberRolePrefix + memberRoleDeploymentID), wantPath: types.StringValue(actMemberRolePath)},
		{name: "unknown deployment ID", next: unknownID, prior: nil, wantName: types.StringUnknown(), wantPath: types.StringValue(actMemberRolePath)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.next.actMemberRole(tt.prior)
			if !got.name.Equal(tt.wantName) || !got.path.Equal(tt.wantPath) {
				t.Fatalf("actMemberRole = %v %v, want %v %v", got.name, got.path, tt.wantName, tt.wantPath)
			}
		})
	}
}
