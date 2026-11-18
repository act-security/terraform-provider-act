package provider

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

func TestPendingConsentWarningNamesTheLinkAndTheApprover(t *testing.T) {
	const consentURL = "https://login.example.test/adminconsent"
	tests := []struct {
		includeEntraID bool
		approver       string
	}{
		{includeEntraID: false, approver: "an Application Administrator or a Cloud Application Administrator"},
		{includeEntraID: true, approver: "a Global Administrator or a Privileged Role Administrator"},
	}
	for _, tt := range tests {
		model := &azureDeploymentModel{
			SubscriptionID:    types.StringValue("11111111-1111-4111-8111-111111111111"),
			ManagementGroupID: types.StringNull(),
			AzureTenantID:     types.StringValue("00000000-0000-4000-8000-0000000000d1"),
			IncludeEntraID:    types.BoolValue(tt.includeEntraID),
			Status:            types.StringValue("pending_consent"),
			ConsentURL:        types.StringValue(consentURL),
		}
		var diags diag.Diagnostics
		(&azureDeploymentResource{}).reportStatus(model, &diags)
		if diags.WarningsCount() != 1 || diags.HasError() {
			t.Fatalf("include_entra_id %t: got %v, want one warning", tt.includeEntraID, diags)
		}
		detail := diags.Warnings()[0].Detail()
		for _, want := range []string{consentURL, tt.approver, "Azure subscription 11111111-1111-4111-8111-111111111111", "Act verifies the deployment on its own"} {
			if !strings.Contains(detail, want) {
				t.Errorf("include_entra_id %t: warning %q does not mention %q", tt.includeEntraID, detail, want)
			}
		}
	}
}

func TestAzureImportIDs(t *testing.T) {
	tests := []struct {
		id    string
		ok    bool
		scope string
	}{
		{id: "subscription/11111111-1111-4111-8111-111111111111", ok: true, scope: "subscription"},
		{id: "management-group/mg-platform", ok: true, scope: "management_group"},
		{id: "subscription/not-a-uuid"},
		{id: "management-group/has spaces"},
		{id: "resource-group/rg"},
		{id: "11111111-1111-4111-8111-111111111111"},
	}
	for _, tt := range tests {
		lookup, ok := azureImportLookup(tt.id)
		if ok != tt.ok || (ok && string(lookup.scope) != tt.scope) {
			t.Errorf("%q: got %+v %t, want scope %q %t", tt.id, lookup, ok, tt.scope, tt.ok)
		}
	}
}

func TestLogSourceDeletionWarnsAboutWhatStillStreams(t *testing.T) {
	source := azureLogSourceModel{DeploymentID: types.StringValue("11111111-1111-4111-8111-111111111111")}
	var diags diag.Diagnostics
	reportCleanup(cleanupReport{
		summary: "Act stopped collecting " + source.label(),
		done:    stoppedCollectingLogs,
		side:    azureLogsWording.side,
		items:   []apigen.CleanupItem{{Resource: "act-logs.servicebus.windows.net/act-activity-logs", Description: "A diagnostic setting still streams activity_logs to this Event Hub."}},
	}, &diags)
	if diags.WarningsCount() != 1 {
		t.Fatalf("got %v, want one warning", diags)
	}
	warning := diags.Warnings()[0]
	want := "Act stopped collecting the logs and removed the Event Hubs it read. These still exist in Azure:\n\n- act-logs.servicebus.windows.net/act-activity-logs: A diagnostic setting still streams activity_logs to this Event Hub."
	if warning.Summary() != "Act stopped collecting the log source of Azure deployment 11111111-1111-4111-8111-111111111111" || warning.Detail() != want {
		t.Errorf("got %q / %q", warning.Summary(), warning.Detail())
	}
}
