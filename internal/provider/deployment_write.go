package provider

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const createAction = "create"

type cloudWording struct {
	side            string
	credential      string
	propagation     string
	slowPropagation string
}

var (
	awsWording = cloudWording{
		side:            "AWS",
		credential:      "the role",
		propagation:     "AWS propagated the role",
		slowPropagation: "the role takes longer to propagate",
	}
	azureWording = cloudWording{
		side:            "Azure",
		credential:      "the service principal",
		propagation:     "Azure propagated the role assignments",
		slowPropagation: "the role assignments take longer to propagate",
	}
)

type wireAttribute struct {
	wire string
	name string
}

type deploymentErrors struct {
	title      string
	typeName   string
	wording    cloudWording
	credential wireAttribute
	attributes map[string]string
}

type deploymentCloud[T any] struct {
	errors     deploymentErrors
	policy     *verificationPolicy
	get        func(ctx context.Context, id string) (*client.DeploymentResult[T], error)
	consoleURL func(item T) *string
	active     func(item T) bool
}

type deploymentStep[T any] struct {
	action   string
	needed   func(last *client.DeploymentResult[T]) bool
	send     func(ctx context.Context, ref client.DeploymentRef) (*client.DeploymentResult[T], error)
	announce bool
}

type deploymentWriter[T any] struct {
	cloud     deploymentCloud[T]
	target    string
	unchanged func(ctx context.Context, fresh T) bool
	ref       client.DeploymentRef
	result    *client.DeploymentResult[T]
	diags     *diag.Diagnostics
}

func (w *deploymentWriter[T]) runAll(ctx context.Context, steps []deploymentStep[T]) bool {
	if w.diags.HasError() {
		return false
	}
	for _, step := range steps {
		if step.needed(w.result) && !w.run(ctx, step) {
			return false
		}
	}
	return true
}

func (w *deploymentWriter[T]) run(ctx context.Context, step deploymentStep[T]) bool {
	outcome, err := w.cloud.policy.run(ctx, func(ctx context.Context) error { return w.sendOnce(ctx, step) })
	if err != nil {
		if !w.diags.HasError() {
			w.cloud.errors.addWriteError(w.diags, writeFailure{action: step.action, target: w.target, outcome: outcome, err: err})
		}
		return false
	}
	w.ref.ETag = w.result.ETag
	if step.announce && w.cloud.active(w.result.Deployment) {
		w.diags.AddWarning(
			"Act verified "+w.cloud.errors.wording.credential+" again",
			proofOfLife(connectionReport{target: w.target, consoleURL: w.cloud.consoleURL(w.result.Deployment), outcome: outcome, reconnected: true, wording: w.cloud.errors.wording}),
		)
	}
	return true
}

func (w *deploymentWriter[T]) sendOnce(ctx context.Context, step deploymentStep[T]) error {
	result, err := step.send(ctx, w.ref)
	if client.IsStatus(err, http.StatusPreconditionFailed) && w.refreshETag(ctx) {
		result, err = step.send(ctx, w.ref)
	}
	if err == nil {
		w.result = result
	}
	return err
}

func (w *deploymentWriter[T]) refreshETag(ctx context.Context) bool {
	title := w.cloud.errors.title
	fresh, ok := w.readAgain(ctx, fmt.Sprintf("Act answered 412 for deployment %s, and reading it again failed", w.ref.ID))
	if !ok {
		return false
	}
	if !w.unchanged(ctx, fresh.Deployment) {
		w.diags.AddError(
			"The "+title+" deployment changed in Act",
			fmt.Sprintf("Someone changed deployment %s since Terraform last read it, so nothing was sent. Run terraform apply again to plan against the current settings.", w.ref.ID),
		)
		return false
	}
	w.ref.ETag = fresh.ETag
	return true
}

func (w *deploymentWriter[T]) latest(ctx context.Context) (*client.DeploymentResult[T], bool) {
	if w.result != nil {
		return w.result, true
	}
	return w.readAgain(ctx, "")
}

func (w *deploymentWriter[T]) readAgain(ctx context.Context, failurePrefix string) (*client.DeploymentResult[T], bool) {
	title := w.cloud.errors.title
	fresh, err := w.cloud.get(ctx, w.ref.ID)
	switch {
	case err != nil:
		detail := err.Error()
		if failurePrefix != "" {
			detail = failurePrefix + ": " + detail
		}
		w.diags.AddError("Reading the "+title+" deployment failed", detail)
		return nil, false
	case fresh == nil:
		w.diags.AddError("The "+title+" deployment is gone", fmt.Sprintf("Deployment %s was deleted in Act during this apply. Run terraform apply again to create it.", w.ref.ID))
		return nil, false
	}
	return fresh, true
}

type writeFailure struct {
	action  string
	target  string
	outcome verificationOutcome
	err     error
}

type alreadyExistsDetails struct {
	DeploymentID string `json:"deploymentId"`
}

type invalidRequestDetails struct {
	Attribute string `json:"attribute"`
	Reason    string `json:"reason"`
}

func (e deploymentErrors) addWriteError(diags *diag.Diagnostics, failure writeFailure) {
	summary := fmt.Sprintf("Could not %s the %s deployment", failure.action, e.title)
	var apiErr *client.APIError
	if !asAPIError(failure.err, &apiErr) {
		diags.AddError(summary, failure.err.Error())
		return
	}
	switch apigen.ErrorEnvelopeErrorCode(apiErr.Code) {
	case apigen.ErrorEnvelopeErrorCodeAlreadyExists:
		diags.AddError(summary, e.importInstead(apiErr, failure.target))
	case apigen.ErrorEnvelopeErrorCodeVerificationFailed:
		e.addVerificationError(diags, summary, failure)
	case apigen.ErrorEnvelopeErrorCodePreconditionFailed:
		diags.AddError(summary, "The deployment changed in Act since Terraform last read it. Run terraform apply again to plan against the current settings.")
	case apigen.ErrorEnvelopeErrorCodeInvalidRequest:
		e.addInvalidRequestError(diags, summary, apiErr)
	default:
		diags.AddError(summary, apiErr.Error())
	}
}

func (e deploymentErrors) importInstead(apiErr *client.APIError, target string) string {
	var details alreadyExistsDetails
	existing := target
	if apiErr.DecodeDetails(&details) == nil && details.DeploymentID != "" {
		existing = details.DeploymentID
	}
	return fmt.Sprintf("Act already has a deployment for %s. Terraform does not take it over silently. Import it instead:\n\nimport {\n  to = %s.<name>\n  id = %q\n}", target, e.typeName, existing)
}

func (e deploymentErrors) addVerificationError(diags *diag.Diagnostics, summary string, failure writeFailure) {
	verification, _ := asVerificationFailure(failure.err)
	detail := verification.describe(failure, e.wording)
	if verification.Attribute == e.credential.wire || verification.Attribute == "" {
		diags.AddAttributeError(path.Root(e.credential.name), summary, detail)
		return
	}
	diags.AddError(summary, detail)
}

func (e deploymentErrors) addInvalidRequestError(diags *diag.Diagnostics, summary string, apiErr *client.APIError) {
	var details invalidRequestDetails
	if apiErr.DecodeDetails(&details) != nil || e.attributes[details.Attribute] == "" {
		diags.AddError(summary, apiErr.Error())
		return
	}
	attribute := e.attributes[details.Attribute]
	diags.AddAttributeError(path.Root(attribute), summary, fmt.Sprintf("Act rejected %s: %s.", attribute, details.Reason))
}

func (e deploymentErrors) addDeleteError(id string, err error, diags *diag.Diagnostics) {
	var apiErr *client.APIError
	if asAPIError(err, &apiErr) && apiErr.Code == string(apigen.ErrorEnvelopeErrorCodeDeletionProtected) {
		diags.AddError("The "+e.title+" deployment has deletion protection", fmt.Sprintf("Act refused to delete %s. Set deletion_protection = false and apply before you destroy it.", id))
		return
	}
	if asAPIError(err, &apiErr) && apiErr.Code == string(apigen.ErrorEnvelopeErrorCodePreconditionFailed) {
		diags.AddError("The "+e.title+" deployment changed in Act", fmt.Sprintf("Someone changed deployment %s since Terraform last read it, so Act kept it. Run terraform destroy again to plan against the current settings.", id))
		return
	}
	diags.AddError("Disconnecting the "+e.title+" deployment failed", err.Error())
}

func (e deploymentErrors) refuseProtectedDestroy(id string, diags *diag.Diagnostics) {
	diags.AddError(
		"The "+e.title+" deployment has deletion protection",
		fmt.Sprintf("Act refuses to delete %s while deletion_protection is true, so this plan stops here instead of failing halfway through the apply. Set deletion_protection = false and apply first. To stop managing it without disconnecting it, use a removed block with lifecycle { destroy = false } or terraform state rm.", id),
	)
}

func (e deploymentErrors) refuseProtectedReplacement(id string, diags *diag.Diagnostics) {
	diags.AddError(
		"The "+e.title+" deployment has deletion protection",
		fmt.Sprintf("This change replaces %s, which deletes it first, and Act refuses to delete it while deletion_protection is true. Set deletion_protection = false and apply first.", id),
	)
}

func (f *verificationFailure) describe(failure writeFailure, wording cloudWording) string {
	return f.whatActSaw(wording) + f.whyItStopped(failure.outcome, wording) + whatWasKept(failure.action)
}

func (f *verificationFailure) whatActSaw(wording cloudWording) string {
	detail := "Act could not use " + wording.credential + ": " + f.CloudErrorCode + "."
	if f.Hint == "" {
		return detail
	}
	return detail + " " + asSentence(f.Hint)
}

func (f *verificationFailure) whyItStopped(outcome verificationOutcome, wording cloudWording) string {
	switch {
	case f.RetryClass == retryClassPropagation && outcome.timedOut:
		return fmt.Sprintf(" Act kept trying for %s (%d attempts) while %s, then gave up. Apply again, or raise timeouts if %s.", outcome.elapsed.Round(time.Second), outcome.attempts, wording.propagation, wording.slowPropagation)
	case outcome.attempts > 1:
		return fmt.Sprintf(" Act got the same answer %d times, so this needs a fix on the %s side.", outcome.attempts, wording.side)
	default:
		return ""
	}
}

func whatWasKept(action string) string {
	if action != createAction {
		return ""
	}
	return " Nothing was stored."
}

func asSentence(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || strings.ContainsAny(trimmed[len(trimmed)-1:], ".!?") {
		return trimmed
	}
	return trimmed + "."
}

type connectionReport struct {
	target      string
	consoleURL  *string
	outcome     verificationOutcome
	reconnected bool
	wording     cloudWording
}

func proofOfLife(report connectionReport) string {
	message := "Connected. Act started the first scan of " + report.target + "."
	if report.reconnected {
		message = "Connected again. Act can use " + report.wording.credential + " of " + report.target + "."
	}
	if report.consoleURL != nil {
		message += " Open " + *report.consoleURL
	}
	if report.outcome.attempts > 1 {
		message += fmt.Sprintf("\n\nVerified after %s and %d attempts while %s.", report.outcome.elapsed.Round(time.Second), report.outcome.attempts, report.wording.propagation)
	}
	return message
}

func addDeploymentWarnings(diags *diag.Diagnostics, warnings []apigen.DeploymentWarning) {
	for _, warning := range warnings {
		diags.AddWarning("Act: "+warning.Code, warning.Message)
	}
}

type cleanupReport struct {
	target string
	side   string
	items  []apigen.CleanupItem
}

func reportCleanup(report cleanupReport, diags *diag.Diagnostics) {
	if len(report.items) == 0 {
		return
	}
	lines := make([]string, 0, len(report.items))
	for _, item := range report.items {
		lines = append(lines, "- "+item.Resource+": "+item.Description)
	}
	diags.AddWarning("Act disconnected "+report.target, "Act stopped scanning and deleted the credentials it held. These still exist in "+report.side+":\n\n"+strings.Join(lines, "\n"))
}

type importLookup struct {
	cloud  apigen.Cloud
	scope  apigen.DeploymentScope
	target string
	label  string
}

func resolveImportByTarget(ctx context.Context, c *client.Client, lookup importLookup, diags *diag.Diagnostics) (string, bool) {
	cloud := lookup.cloud
	items, err := c.ListDeployments(ctx, client.DeploymentFilter{Cloud: &cloud, Target: &lookup.target})
	if err != nil {
		diags.AddError("Listing deployments failed", err.Error())
		return "", false
	}
	matches := []string{}
	for _, item := range items {
		if item.Scope == lookup.scope {
			matches = append(matches, item.ID)
		}
	}
	switch len(matches) {
	case 0:
		diags.AddError("No deployment to import", fmt.Sprintf("This tenant has no %s deployment for %s.", lookup.label, lookup.target))
		return "", false
	case 1:
		return matches[0], true
	default:
		diags.AddError("More than one deployment matches", fmt.Sprintf("Deployments %s all cover %s. Import one by its ID.", strings.Join(matches, ", "), lookup.target))
		return "", false
	}
}
