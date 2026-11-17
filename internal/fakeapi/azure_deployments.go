package fakeapi

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
)

const (
	ActAzureAppClientID      = "00000000-0000-4000-8000-0000000000a1"
	AzureModuleSource        = "act-security/act/azurerm"
	AzureReaderRoleID        = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
	AzureDirectoryReadRoleID = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
	azureDeploymentVersion   = "2026.11"
	adminConsentOrigin       = "https://login.microsoftonline.com/"
)

var (
	azurePrincipalCheck = credentialCheck{attribute: "servicePrincipalId", message: "Act could not use the service principal"}
	azureRoleActions    = []string{
		"Microsoft.Web/sites/config/list/action",
		"Microsoft.Storage/storageAccounts/blobServices/containers/read",
	}
)

type storedAzureDeployment struct {
	item    gen.AzureDeployment
	version int
}

type idempotentAzureDeployment struct {
	body     string
	response gen.AzureDeployment
	etag     string
}

type azureDeployments struct {
	byID        map[string]*storedAzureDeployment
	idempotency map[string]idempotentAzureDeployment
	pending     map[string]func(*gen.AzureDeployment)
	consented   map[string]bool
}

func newAzureDeployments() azureDeployments {
	return azureDeployments{
		byID:        map[string]*storedAzureDeployment{},
		idempotency: map[string]idempotentAzureDeployment{},
		pending:     map[string]func(*gen.AzureDeployment){},
		consented:   map[string]bool{},
	}
}

func (f *Fake) AzureSubscriptionDeploymentID(subscriptionID string) string {
	return f.deploymentID(azureSubscriptionTarget(subscriptionID))
}

func (f *Fake) AzureManagementGroupDeploymentID(managementGroupID string) string {
	return f.deploymentID(azureManagementGroupTarget(managementGroupID))
}

func (f *Fake) AzureServicePrincipalID(directoryID string) string {
	return derivedUUID("azure-service-principal|" + directoryID)
}

func AzureAdminConsentURL(directoryID string) string {
	return adminConsentOrigin + directoryID + "/adminconsent?" + url.Values{"client_id": {ActAzureAppClientID}}.Encode()
}

func (f *Fake) GrantAzureConsent(directoryID string) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	azure := &f.deployments.azure
	azure.consented[directoryID] = true
	for _, stored := range azure.byID {
		if stored.item.AzureTenantID == directoryID && stored.item.Status == gen.DeploymentStatusPendingConsent {
			azure.settle(stored)
			stored.version++
		}
	}
}

func (f *Fake) ChangeAzureDeploymentBeforeNextPatch(id string, change func(*gen.AzureDeployment)) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	f.deployments.azure.pending[id] = change
}

func (f *Fake) AzureDeployment(id string) (gen.AzureDeployment, bool) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	stored, ok := f.deployments.azure.byID[id]
	if !ok {
		return gen.AzureDeployment{}, false
	}
	return stored.item, true
}

func (s *apiServer) GetAzureOnboarding(_ context.Context, req gen.GetAzureOnboardingRequestObject) (gen.GetAzureOnboardingResponseObject, error) {
	params := req.Params
	target, ok := azureTargetOf(params.SubscriptionID, params.ManagementGroupID)
	if !ok {
		return gen.GetAzureOnboarding400JSONResponse(invalid("subscriptionId", "exactly_one_target")), nil
	}
	key := target.naturalKey
	target.variant = deref(params.Variant)
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	id := s.fake.deploymentID(target)
	var existing *gen.ExistingDeployment
	if stored := store.azure.byNaturalKey(key); stored != nil && params.Variant == nil {
		id = stored.item.ID
		existing = &gen.ExistingDeployment{ID: id, Status: stored.item.Status, CreatedVia: stored.item.CreatedVia}
	}
	values := gen.GetAzureOnboarding200JSONResponse{
		DeploymentID:            id,
		ExistingDeployment:      existing,
		AzureTenantID:           params.DirectoryID,
		TenantConsented:         store.azure.consented[params.DirectoryID],
		AdminConsentURL:         AzureAdminConsentURL(params.DirectoryID),
		ActAppClientID:          ActAzureAppClientID,
		CustomRoleName:          "ActSecurityReader-" + id,
		CustomRoleActions:       azureRoleActions,
		BindingMarker:           "act-deployment:" + id,
		RequiredBuiltinRoleIds:  []string{AzureReaderRoleID},
		RequiredGraphAppRoleIds: []string{AzureDirectoryReadRoleID},
	}
	if values.TenantConsented {
		principal := s.fake.AzureServicePrincipalID(params.DirectoryID)
		values.ActServicePrincipalID = &principal
	}
	if !store.unpublished {
		addPublishedAzureModule(&values)
	}
	return values, nil
}

func addPublishedAzureModule(values *gen.GetAzureOnboarding200JSONResponse) {
	source, version, deployed := AzureModuleSource, ModuleVersion, azureDeploymentVersion
	moduleDigest, permissions := fakeDigest("d"), fakeDigest("e")
	versions := []gen.ModuleVersion{{Version: ModuleVersion, Sha256: moduleDigest, PermissionsHash: permissions, DeploymentVersion: deployed}}
	values.ModuleSource, values.ModuleVersion, values.DeploymentVersion = &source, &version, &deployed
	values.ModuleSha256, values.PermissionsHash = &moduleDigest, &permissions
	values.ModuleVersions = &versions
}

func (s *apiServer) CreateAzureDeployment(_ context.Context, req gen.CreateAzureDeploymentRequestObject) (gen.CreateAzureDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	body := *req.Body
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	key := req.Params.IdempotencyKey
	if previous, ok := store.azure.idempotency[key]; ok {
		if previous.body != string(raw) {
			return gen.CreateAzureDeployment422JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeIdempotencyMismatch, "Idempotency key reused")), nil
		}
		return gen.CreateAzureDeployment201JSONResponse{Body: previous.response, Headers: gen.CreateAzureDeployment201ResponseHeaders{ETag: previous.etag}}, nil
	}
	target, ok := azureTargetOf(body.SubscriptionID, body.ManagementGroupID)
	if !ok {
		return gen.CreateAzureDeployment400JSONResponse(invalid("subscriptionId", "exactly_one_target")), nil
	}
	if existing := store.azure.byNaturalKey(target.naturalKey); existing != nil {
		e := envelope(gen.ErrorEnvelopeErrorCodeAlreadyExists, "A deployment for this target already exists")
		details := map[string]any{"deploymentId": existing.item.ID}
		e.Error.Details = &details
		return gen.CreateAzureDeployment409JSONResponse(e), nil
	}
	if body.DeploymentID != s.fake.deploymentID(target) {
		return gen.CreateAzureDeployment400JSONResponse(invalid("deploymentId", "not_issued_by_act")), nil
	}
	if failure, ok := store.nextFailure(body.ServicePrincipalID); ok {
		return gen.CreateAzureDeployment422JSONResponse(verificationFailed(azurePrincipalCheck, failure)), nil
	}
	stored := &storedAzureDeployment{item: s.fake.newAzureDeployment(body)}
	store.azure.settle(stored)
	store.azure.byID[stored.item.ID] = stored
	store.azure.idempotency[key] = idempotentAzureDeployment{body: string(raw), response: stored.item, etag: stored.etag()}
	return gen.CreateAzureDeployment201JSONResponse{Body: stored.item, Headers: gen.CreateAzureDeployment201ResponseHeaders{ETag: stored.etag()}}, nil
}

func (f *Fake) newAzureDeployment(body gen.AzureDeploymentCreate) gen.AzureDeployment {
	method := gen.AzureDeploymentMethodTerraform
	if body.DeploymentMethod != nil {
		method = *body.DeploymentMethod
	}
	item := gen.AzureDeployment{
		ID:                 body.DeploymentID,
		Name:               "azure-" + deref(body.SubscriptionID) + deref(body.ManagementGroupID),
		Tags:               map[string]string{},
		SubscriptionID:     body.SubscriptionID,
		ManagementGroupID:  body.ManagementGroupID,
		AzureTenantID:      body.AzureTenantID,
		ServicePrincipalID: &body.ServicePrincipalID,
		IncludeEntraID:     body.IncludeEntraID != nil && *body.IncludeEntraID,
		DeploymentMethod:   &method,
		Warnings:           []gen.DeploymentWarning{},
		DeletionProtection: body.ManagementGroupID != nil,
		ConsoleURL:         consoleURL(body.DeploymentID),
		CreatedVia:         deploymentSource(gen.DeploymentChangeSourceAPI),
		CreatedAt:          f.now().UTC(),
	}
	if body.Name != nil {
		item.Name = *body.Name
	}
	if body.Tags != nil {
		item.Tags = *body.Tags
	}
	if body.DeletionProtection != nil {
		item.DeletionProtection = *body.DeletionProtection
	}
	return item
}

func (s *apiServer) GetAzureDeployment(_ context.Context, req gen.GetAzureDeploymentRequestObject) (gen.GetAzureDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.azure.byID[req.ID]
	if !ok {
		return gen.GetAzureDeployment404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	return gen.GetAzureDeployment200JSONResponse{Body: stored.item, Headers: gen.GetAzureDeployment200ResponseHeaders{ETag: stored.etag()}}, nil
}

func (s *apiServer) UpdateAzureDeployment(_ context.Context, req gen.UpdateAzureDeploymentRequestObject) (gen.UpdateAzureDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.azure.byID[req.ID]
	if !ok {
		return gen.UpdateAzureDeployment404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	store.azure.applyPendingChange(stored)
	if req.Params.IfMatch != stored.etag() {
		return gen.UpdateAzureDeployment412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	patch := *req.Body
	if patch.DeploymentMethod != nil && (stored.item.DeploymentMethod == nil || *patch.DeploymentMethod != *stored.item.DeploymentMethod) {
		return gen.UpdateAzureDeployment400JSONResponse(invalid("deploymentMethod", "immutable")), nil
	}
	patched, reverify := applyAzurePatch(stored.item, patch)
	if reverify {
		if failure, ok := store.nextFailure(deref(patched.ServicePrincipalID)); ok {
			return gen.UpdateAzureDeployment422JSONResponse(verificationFailed(azurePrincipalCheck, failure)), nil
		}
	}
	stored.item = patched
	if reverify {
		store.azure.settle(stored)
	}
	stored.version++
	return gen.UpdateAzureDeployment200JSONResponse{Body: stored.item, Headers: gen.UpdateAzureDeployment200ResponseHeaders{ETag: stored.etag()}}, nil
}

func applyAzurePatch(item gen.AzureDeployment, patch gen.AzureDeploymentPatch) (gen.AzureDeployment, bool) {
	reverify := false
	if patch.ServicePrincipalID != nil && *patch.ServicePrincipalID != deref(item.ServicePrincipalID) {
		item.ServicePrincipalID, reverify = patch.ServicePrincipalID, true
	}
	if patch.IncludeEntraID != nil && *patch.IncludeEntraID != item.IncludeEntraID {
		item.IncludeEntraID, reverify = *patch.IncludeEntraID, true
	}
	if patch.Name != nil {
		item.Name = *patch.Name
	}
	if patch.Tags != nil {
		item.Tags = *patch.Tags
	}
	if patch.DeletionProtection != nil {
		item.DeletionProtection = *patch.DeletionProtection
	}
	return item, reverify
}

func (s *apiServer) VerifyAzureDeployment(_ context.Context, req gen.VerifyAzureDeploymentRequestObject) (gen.VerifyAzureDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.azure.byID[req.ID]
	if !ok {
		return gen.VerifyAzureDeployment404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != stored.etag() {
		return gen.VerifyAzureDeployment412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	if failure, ok := store.nextFailure(deref(stored.item.ServicePrincipalID)); ok {
		return gen.VerifyAzureDeployment422JSONResponse(verificationFailed(azurePrincipalCheck, failure)), nil
	}
	store.azure.settle(stored)
	stored.version++
	return gen.VerifyAzureDeployment200JSONResponse{Body: stored.item, Headers: gen.VerifyAzureDeployment200ResponseHeaders{ETag: stored.etag()}}, nil
}

func (s *apiServer) DeleteAzureDeployment(_ context.Context, req gen.DeleteAzureDeploymentRequestObject) (gen.DeleteAzureDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.azure.byID[req.ID]
	if !ok {
		return gen.DeleteAzureDeployment404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != nil && *req.Params.IfMatch != stored.etag() {
		return gen.DeleteAzureDeployment412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	if stored.item.DeletionProtection {
		return gen.DeleteAzureDeployment409JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeDeletionProtected, "Deletion protection is on")), nil
	}
	delete(store.azure.byID, req.ID)
	cleanup := []gen.CleanupItem{{
		Resource:    "service principal " + deref(stored.item.ServicePrincipalID),
		Description: "Its role assignments still grant Act read access. Remove them, or keep them to connect again later.",
	}}
	return gen.DeleteAzureDeployment200JSONResponse{ID: req.ID, CleanupRequired: cleanup}, nil
}

func (a *azureDeployments) settle(stored *storedAzureDeployment) {
	stored.item.ErrorCode, stored.item.ErrorMessage = nil, nil
	if a.consented[stored.item.AzureTenantID] {
		stored.item.Status, stored.item.ConsentURL = gen.DeploymentStatusActive, nil
		return
	}
	consent := AzureAdminConsentURL(stored.item.AzureTenantID)
	stored.item.Status, stored.item.ConsentURL = gen.DeploymentStatusPendingConsent, &consent
}

func (a *azureDeployments) applyPendingChange(stored *storedAzureDeployment) {
	change, ok := a.pending[stored.item.ID]
	if !ok {
		return
	}
	delete(a.pending, stored.item.ID)
	change(&stored.item)
	stored.version++
}

func (a *azureDeployments) byNaturalKey(key string) *storedAzureDeployment {
	for _, stored := range a.byID {
		if stored.naturalKey() == key {
			return stored
		}
	}
	return nil
}

func azureSubscriptionTarget(subscriptionID string) deploymentTarget {
	return deploymentTarget{naturalKey: "azure:subscription:" + subscriptionID}
}

func azureManagementGroupTarget(managementGroupID string) deploymentTarget {
	return deploymentTarget{naturalKey: "azure:management_group:" + managementGroupID}
}

func azureTargetOf(subscriptionID, managementGroupID *string) (deploymentTarget, bool) {
	switch {
	case subscriptionID != nil && managementGroupID == nil:
		return azureSubscriptionTarget(*subscriptionID), true
	case managementGroupID != nil && subscriptionID == nil:
		return azureManagementGroupTarget(*managementGroupID), true
	default:
		return deploymentTarget{}, false
	}
}

func (s *storedAzureDeployment) etag() string {
	return versionedETag(s.item.ID, s.version)
}

func (s *storedAzureDeployment) naturalKey() string {
	target, _ := azureTargetOf(s.item.SubscriptionID, s.item.ManagementGroupID)
	return target.naturalKey
}

func (s *storedAzureDeployment) summary() gen.DeploymentSummary {
	scope, target := gen.DeploymentScopeSubscription, deref(s.item.SubscriptionID)
	if s.item.ManagementGroupID != nil {
		scope, target = gen.DeploymentScopeManagementGroup, *s.item.ManagementGroupID
	}
	return gen.DeploymentSummary{
		ID:                 s.item.ID,
		Cloud:              gen.CloudAzure,
		Name:               s.item.Name,
		Scope:              scope,
		Targets:            []string{target},
		Status:             s.item.Status,
		UpdateAvailable:    s.item.UpdateAvailable,
		DeletionProtection: s.item.DeletionProtection,
		Tags:               s.item.Tags,
		CreatedAt:          s.item.CreatedAt,
	}
}
