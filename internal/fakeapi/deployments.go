package fakeapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
)

const (
	ActPrincipalArn      = "arn:aws:iam::123456789012:role/act-fake-principal"
	DeprecatedPrincipal  = "arn:aws:iam::123456789012:role/act-fake-principal-previous"
	ExternalIDKeyVersion = 2
	ConsoleOrigin        = "https://app.act.security"
	ModuleSource         = "act-security/act/aws"
	ModuleVersion        = "1.0.0"
	RetryClassPropagate  = "propagation"
	RetryClassDetermined = "deterministic"
	listPageSize         = 2
	externalIDLength     = 40
	maxPatchBodyBytes    = 1 << 20
	sha256HexLength      = 64
)

var (
	roleArnAccount = regexp.MustCompile(`^arn:aws:iam::(\d{12}):role/`)
	cellKey        = []byte("fake-cell-key-not-a-real-secret")
)

type VerificationFailure struct {
	RetryClass     string
	CloudErrorCode string
	Hint           string
}

type storedDeployment struct {
	item    gen.AwsDeployment
	version int
}

type deploymentStore struct {
	mu          sync.Mutex
	byID        map[string]*storedDeployment
	idempotency map[string]idempotentDeployment
	failures    map[string][]VerificationFailure
	members     map[string][]gen.MemberAccount
	pending     map[string]func(*gen.AwsDeployment)
	unpublished bool
}

type idempotentDeployment struct {
	body     string
	response gen.AwsDeployment
	etag     string
}

func newDeploymentStore() *deploymentStore {
	return &deploymentStore{
		byID:        map[string]*storedDeployment{},
		idempotency: map[string]idempotentDeployment{},
		failures:    map[string][]VerificationFailure{},
		members:     map[string][]gen.MemberAccount{},
		pending:     map[string]func(*gen.AwsDeployment){},
	}
}

func (s *storedDeployment) etag() string {
	return fmt.Sprintf(`"%s-%d"`, s.item.ID, s.version)
}

func (s *storedDeployment) naturalKey() string {
	if s.item.Organization != nil {
		return organizationTarget(deref(s.item.Organization.OrganizationID)).naturalKey
	}
	return accountTarget(deref(s.item.AccountID)).naturalKey
}

func (s *storedDeployment) targets() []string {
	if s.item.Organization == nil {
		return []string{deref(s.item.AccountID)}
	}
	org := s.item.Organization
	targets := []string{}
	if org.OrganizationID != nil {
		targets = append(targets, *org.OrganizationID)
	}
	if org.RootID != nil {
		targets = append(targets, *org.RootID)
	}
	if org.OrganizationalUnitIds != nil {
		targets = append(targets, *org.OrganizationalUnitIds...)
	}
	return targets
}

type deploymentTarget struct {
	naturalKey string
	variant    string
}

func accountTarget(accountID string) deploymentTarget {
	return deploymentTarget{naturalKey: "aws:account:" + accountID}
}

func organizationTarget(organizationID string) deploymentTarget {
	return deploymentTarget{naturalKey: "aws:organization:" + organizationID}
}

func (f *Fake) AwsAccountDeploymentID(accountID string) string {
	return f.deploymentID(accountTarget(accountID))
}

func (f *Fake) AwsOrganizationDeploymentID(organizationID string) string {
	return f.deploymentID(organizationTarget(organizationID))
}

func (f *Fake) deploymentID(target deploymentTarget) string {
	mac := hmac.New(sha256.New, cellKey)
	mac.Write([]byte(f.cfg.TenantID + "|" + target.naturalKey + "|" + target.variant))
	b := mac.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x80
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func derivedExternalID(id string) string {
	mac := hmac.New(sha256.New, cellKey)
	mac.Write([]byte("external-id|" + id))
	return hex.EncodeToString(mac.Sum(nil))[:externalIDLength]
}

func (f *Fake) QueueVerificationFailures(roleArn string, failures ...VerificationFailure) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	f.deployments.failures[roleArn] = append(f.deployments.failures[roleArn], failures...)
}

type DeploymentFailure struct {
	DeploymentID string
	Code         string
	Message      string
}

func (f *Fake) FailDeploymentOutOfBand(failure DeploymentFailure) bool {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	stored, ok := f.deployments.byID[failure.DeploymentID]
	if !ok {
		return false
	}
	stored.item.Status = gen.DeploymentStatusFailed
	stored.item.ErrorCode = &failure.Code
	stored.item.ErrorMessage = &failure.Message
	return true
}

func (f *Fake) ChangeDeploymentBeforeNextPatch(id string, change func(*gen.AwsDeployment)) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	f.deployments.pending[id] = change
}

func (s *deploymentStore) applyPendingChange(stored *storedDeployment) {
	change, ok := s.pending[stored.item.ID]
	if !ok {
		return
	}
	delete(s.pending, stored.item.ID)
	change(&stored.item)
	stored.version++
}

func (f *Fake) UnpublishModules() {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	f.deployments.unpublished = true
}

func (f *Fake) DeleteDeploymentOutOfBand(id string) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	delete(f.deployments.byID, id)
}

func (f *Fake) SetMemberAccounts(id string, accounts []gen.MemberAccount) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	f.deployments.members[id] = accounts
}

func (f *Fake) AwsDeployment(id string) (gen.AwsDeployment, bool) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	stored, ok := f.deployments.byID[id]
	if !ok {
		return gen.AwsDeployment{}, false
	}
	return stored.item, true
}

type LegacyAwsAccount struct {
	AccountID  string
	RoleArn    string
	ExternalID string
}

func (f *Fake) SeedLegacyAwsAccountDeployment(legacy LegacyAwsAccount) string {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	id := randomUUID()
	accountID := legacy.AccountID
	now := f.now().UTC()
	method := gen.AwsDeploymentMethodCloudformation
	stored := &storedDeployment{item: gen.AwsDeployment{
		ID:                   id,
		Name:                 "aws-" + accountID,
		Tags:                 map[string]string{},
		AccountID:            &accountID,
		RoleArn:              &legacy.RoleArn,
		DisabledCapabilities: []gen.AwsCapability{},
		DeploymentMethod:     &method,
		ExternalID:           legacy.ExternalID,
		ExternalIDSource:     gen.ExternalIDSourceLegacy,
		Status:               gen.DeploymentStatusActive,
		Warnings:             []gen.DeploymentWarning{},
		ConsoleURL:           consoleURL(id),
		CreatedVia:           deploymentSource(gen.DeploymentChangeSourceUI),
		CreatedAt:            now,
	}}
	f.deployments.byID[id] = stored
	return id
}

type LegacyAwsOrganization struct {
	RoleArn string
	RootID  string
}

func (f *Fake) SeedLegacyAwsOrganizationDeployment(legacy LegacyAwsOrganization) string {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	id := randomUUID()
	method := gen.AwsDeploymentMethodCloudformation
	version := ExternalIDKeyVersion
	f.deployments.byID[id] = &storedDeployment{item: gen.AwsDeployment{
		ID:                   id,
		Name:                 "aws-organization",
		Tags:                 map[string]string{},
		RoleArn:              &legacy.RoleArn,
		DisabledCapabilities: []gen.AwsCapability{},
		DeploymentMethod:     &method,
		ExternalID:           derivedExternalID(id),
		ExternalIDSource:     gen.ExternalIDSourceDerived,
		ExternalIDKeyVersion: &version,
		Status:               gen.DeploymentStatusActive,
		Warnings:             []gen.DeploymentWarning{},
		ConsoleURL:           consoleURL(id),
		CreatedVia:           deploymentSource(gen.DeploymentChangeSourceUI),
		CreatedAt:            f.now().UTC(),
		DeletionProtection:   true,
		Organization:         &gen.AwsOrganization{RootID: &legacy.RootID},
	}}
	return id
}

func (s *deploymentStore) byNaturalKey(key string) *storedDeployment {
	for _, stored := range s.byID {
		if stored.naturalKey() == key {
			return stored
		}
	}
	return nil
}

func (s *apiServer) GetAwsOnboarding(_ context.Context, req gen.GetAwsOnboardingRequestObject) (gen.GetAwsOnboardingResponseObject, error) {
	params := req.Params
	if (params.AccountID == nil) == (params.OrganizationID == nil) {
		return gen.GetAwsOnboarding400JSONResponse(invalid("accountId", "exactly_one_target")), nil
	}
	target := accountTarget(deref(params.AccountID))
	if params.OrganizationID != nil {
		target = organizationTarget(*params.OrganizationID)
	}
	key := target.naturalKey
	target.variant = deref(params.Variant)
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	id := s.fake.deploymentID(target)
	externalID, source := derivedExternalID(id), gen.ExternalIDSourceDerived
	var existing *gen.ExistingDeployment
	if stored := store.byNaturalKey(key); stored != nil && params.Variant == nil {
		id = stored.item.ID
		externalID, source = stored.item.ExternalID, stored.item.ExternalIDSource
		existing = &gen.ExistingDeployment{ID: id, Status: stored.item.Status, CreatedVia: stored.item.CreatedVia}
	}
	return onboardingValues(onboardingInput{
		id:           id,
		existing:     existing,
		externalID:   externalID,
		source:       source,
		accountID:    params.AccountID,
		unpublished:  store.unpublished,
		legacyStored: source == gen.ExternalIDSourceLegacy,
	}), nil
}

type onboardingInput struct {
	id           string
	existing     *gen.ExistingDeployment
	externalID   string
	source       gen.ExternalIDSource
	accountID    *string
	unpublished  bool
	legacyStored bool
}

func onboardingValues(in onboardingInput) gen.GetAwsOnboarding200JSONResponse {
	roleName := "ActSecurityRole-" + in.id
	values := gen.GetAwsOnboarding200JSONResponse{
		DeploymentID:              in.id,
		ExistingDeployment:        in.existing,
		ActPrincipalArn:           ActPrincipalArn,
		DeprecatedPrincipals:      []gen.DeprecatedPrincipal{{Arn: DeprecatedPrincipal, ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}},
		ExternalID:                in.externalID,
		ExternalIDSource:          in.source,
		TargetExternalID:          derivedExternalID(in.id),
		RoleName:                  roleName,
		AssumeRolePolicyJSON:      assumeRolePolicy(in.externalID),
		CloudformationTemplateURL: ConsoleOrigin + "/templates/aws/" + ModuleVersion + "/role.yaml",
		DeploymentVersion:         "2026.11",
	}
	if !in.legacyStored {
		version := ExternalIDKeyVersion
		values.ExternalIDKeyVersion = &version
	}
	if in.accountID != nil {
		arn := "arn:aws:iam::" + *in.accountID + ":role/" + roleName
		values.RoleArn = &arn
	} else {
		path := "/"
		values.MemberRoleName, values.MemberRolePath = &roleName, &path
	}
	if !in.unpublished {
		addPublishedModule(&values)
	}
	return values
}

func addPublishedModule(values *gen.GetAwsOnboarding200JSONResponse) {
	documents := map[string]string{"ActSecurityReadOnly": `{"Version":"2012-10-17","Statement":[]}`}
	managed := []string{"arn:aws:iam::aws:policy/SecurityAudit"}
	source, version := ModuleSource, ModuleVersion
	templateDigest, moduleDigest, permissions := fakeDigest("a"), fakeDigest("b"), fakeDigest("c")
	versions := []gen.ModuleVersion{{Version: ModuleVersion, Sha256: moduleDigest, PermissionsHash: permissions, DeploymentVersion: values.DeploymentVersion}}
	values.CustomPolicyDocuments = &documents
	values.ManagedPolicyArns = &managed
	values.CloudformationTemplateSha256 = &templateDigest
	values.ModuleSource, values.ModuleVersion = &source, &version
	values.ModuleSha256, values.PermissionsHash = &moduleDigest, &permissions
	values.ModuleVersions = &versions
}

func assumeRolePolicy(externalID string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":%q}}}]}`, ActPrincipalArn, externalID)
}

func (s *apiServer) CreateAwsDeployment(_ context.Context, req gen.CreateAwsDeploymentRequestObject) (gen.CreateAwsDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	body := *req.Body
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	key := req.Params.IdempotencyKey
	if previous, ok := store.idempotency[key]; ok {
		if previous.body != string(raw) {
			return gen.CreateAwsDeployment422JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeIdempotencyMismatch, "Idempotency key reused")), nil
		}
		return gen.CreateAwsDeployment201JSONResponse{Body: previous.response, Headers: gen.CreateAwsDeployment201ResponseHeaders{ETag: previous.etag}}, nil
	}
	if (body.AccountID == nil) == (body.Organization == nil) {
		return gen.CreateAwsDeployment400JSONResponse(invalid("accountId", "exactly_one_target")), nil
	}
	target := accountTarget(deref(body.AccountID))
	if body.Organization != nil {
		target = organizationTarget(body.Organization.OrganizationID)
		if (body.Organization.RootID == nil) == (body.Organization.OrganizationalUnitIds == nil) {
			return gen.CreateAwsDeployment400JSONResponse(invalid("organization.rootId", "exactly_one_scope")), nil
		}
	}
	if existing := store.byNaturalKey(target.naturalKey); existing != nil {
		e := envelope(gen.ErrorEnvelopeErrorCodeAlreadyExists, "A deployment for this target already exists")
		details := map[string]any{"deploymentId": existing.item.ID}
		e.Error.Details = &details
		return gen.CreateAwsDeployment409JSONResponse(e), nil
	}
	if body.DeploymentID != s.fake.deploymentID(target) {
		return gen.CreateAwsDeployment400JSONResponse(invalid("deploymentId", "not_issued_by_act")), nil
	}
	roleAccount := roleArnAccount.FindStringSubmatch(body.RoleArn)
	if roleAccount == nil {
		return gen.CreateAwsDeployment400JSONResponse(invalid("roleArn", "invalid_arn")), nil
	}
	if !roleInAccount(body.RoleArn, body.AccountID) {
		return gen.CreateAwsDeployment422JSONResponse(verificationFailed(accountMismatch)), nil
	}
	if failure, ok := store.nextFailure(body.RoleArn); ok {
		return gen.CreateAwsDeployment422JSONResponse(verificationFailed(failure)), nil
	}
	item := s.fake.newAwsDeployment(body, roleAccount[1])
	stored := &storedDeployment{item: item}
	store.byID[item.ID] = stored
	store.idempotency[key] = idempotentDeployment{body: string(raw), response: item, etag: stored.etag()}
	return gen.CreateAwsDeployment201JSONResponse{Body: item, Headers: gen.CreateAwsDeployment201ResponseHeaders{ETag: stored.etag()}}, nil
}

func (f *Fake) newAwsDeployment(body gen.AwsDeploymentCreate, roleAccount string) gen.AwsDeployment {
	item := gen.AwsDeployment{
		ID:                   body.DeploymentID,
		Tags:                 map[string]string{},
		RoleArn:              &body.RoleArn,
		AllowedRegions:       body.AllowedRegions,
		DisabledCapabilities: []gen.AwsCapability{},
		ExternalID:           derivedExternalID(body.DeploymentID),
		ExternalIDSource:     gen.ExternalIDSourceDerived,
		ExternalIDKeyVersion: intPointer(ExternalIDKeyVersion),
		Status:               gen.DeploymentStatusActive,
		Warnings:             []gen.DeploymentWarning{},
		ConsoleURL:           consoleURL(body.DeploymentID),
		CreatedVia:           deploymentSource(gen.DeploymentChangeSourceAPI),
		CreatedAt:            f.now().UTC(),
		DeletionProtection:   body.Organization != nil,
	}
	method := gen.AwsDeploymentMethodTerraform
	if body.DeploymentMethod != nil {
		method = *body.DeploymentMethod
	}
	item.DeploymentMethod = &method
	if body.ExternalIDKeyVersion != nil {
		item.ExternalIDKeyVersion = body.ExternalIDKeyVersion
	}
	if body.DisabledCapabilities != nil {
		item.DisabledCapabilities = *body.DisabledCapabilities
	}
	if body.Tags != nil {
		item.Tags = *body.Tags
	}
	if body.DeletionProtection != nil {
		item.DeletionProtection = *body.DeletionProtection
	}
	if body.AccountID != nil {
		item.AccountID = body.AccountID
		item.Name = "aws-" + *body.AccountID
	} else {
		org := body.Organization
		item.Name = "aws-" + org.OrganizationID
		roleName, rolePath := "ActSecurityRole-"+body.DeploymentID, "/"
		item.Organization = &gen.AwsOrganization{
			OrganizationID:        &org.OrganizationID,
			RootID:                org.RootID,
			OrganizationalUnitIds: org.OrganizationalUnitIds,
			ExcludedAccountIds:    org.ExcludedAccountIds,
			ManagementAccountID:   &roleAccount,
			MemberRoleName:        &roleName,
			MemberRolePath:        &rolePath,
		}
		if org.MemberRoleName != nil {
			item.Organization.MemberRoleName = org.MemberRoleName
		}
		if org.MemberRolePath != nil {
			item.Organization.MemberRolePath = org.MemberRolePath
		}
	}
	if body.Name != nil {
		item.Name = *body.Name
	}
	return item
}

func (s *deploymentStore) nextFailure(roleArn string) (VerificationFailure, bool) {
	queue := s.failures[roleArn]
	if len(queue) == 0 {
		return VerificationFailure{}, false
	}
	s.failures[roleArn] = queue[1:]
	return queue[0], true
}

func verificationFailed(failure VerificationFailure) gen.ErrorEnvelope {
	e := envelope(gen.ErrorEnvelopeErrorCodeVerificationFailed, "Act could not assume the role")
	details := map[string]any{
		"retryClass":     failure.RetryClass,
		"cloudErrorCode": failure.CloudErrorCode,
		"attribute":      "roleArn",
		"hint":           failure.Hint,
	}
	e.Error.Details = &details
	e.Error.Retryable = false
	return e
}

func (s *apiServer) GetAwsDeployment(_ context.Context, req gen.GetAwsDeploymentRequestObject) (gen.GetAwsDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.GetAwsDeployment404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	return gen.GetAwsDeployment200JSONResponse{Body: stored.item, Headers: gen.GetAwsDeployment200ResponseHeaders{ETag: stored.etag()}}, nil
}

type rawBodyKey struct{}

func captureBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.Body == nil {
			next.ServeHTTP(w, r)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxPatchBodyBytes))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, envelope(gen.ErrorEnvelopeErrorCodeInvalidRequest, err.Error()))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), rawBodyKey{}, raw)))
	})
}

func presentFields(ctx context.Context, path ...string) map[string]json.RawMessage {
	raw, ok := ctx.Value(rawBodyKey{}).([]byte)
	fields := map[string]json.RawMessage{}
	if !ok || json.Unmarshal(raw, &fields) != nil {
		return map[string]json.RawMessage{}
	}
	for _, name := range path {
		nested := map[string]json.RawMessage{}
		if json.Unmarshal(fields[name], &nested) != nil {
			return map[string]json.RawMessage{}
		}
		fields = nested
	}
	return fields
}

func (s *apiServer) UpdateAwsDeployment(ctx context.Context, req gen.UpdateAwsDeploymentRequestObject) (gen.UpdateAwsDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.UpdateAwsDeployment404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	store.applyPendingChange(stored)
	if req.Params.IfMatch != stored.etag() {
		return gen.UpdateAwsDeployment412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	patched, rejection := applyDeploymentPatch(ctx, stored.item, *req.Body)
	if rejection != nil {
		return rejection, nil
	}
	if patched.reverify {
		if failure, ok := store.nextFailure(deref(patched.item.RoleArn)); ok {
			return gen.UpdateAwsDeployment422JSONResponse(verificationFailed(failure)), nil
		}
		patched.item.Status, patched.item.ErrorCode, patched.item.ErrorMessage = gen.DeploymentStatusActive, nil, nil
	}
	stored.item = patched.item
	stored.version++
	return gen.UpdateAwsDeployment200JSONResponse{Body: stored.item, Headers: gen.UpdateAwsDeployment200ResponseHeaders{ETag: stored.etag()}}, nil
}

type patchedDeployment struct {
	item     gen.AwsDeployment
	reverify bool
}

func applyDeploymentPatch(ctx context.Context, current gen.AwsDeployment, body gen.AwsDeploymentPatch) (patchedDeployment, gen.UpdateAwsDeploymentResponseObject) {
	patched := patchedDeployment{item: current}
	if body.RoleArn != nil && *body.RoleArn != deref(current.RoleArn) {
		if !roleInAccount(*body.RoleArn, current.AccountID) {
			return patched, gen.UpdateAwsDeployment422JSONResponse(verificationFailed(accountMismatch))
		}
		patched.item.RoleArn, patched.reverify = body.RoleArn, true
	}
	applySettingsPatch(ctx, &patched.item, body)
	if body.Organization == nil {
		return patched, nil
	}
	if current.Organization == nil {
		return patched, gen.UpdateAwsDeployment400JSONResponse(invalid("organization", "not_an_organization"))
	}
	org, retargeted := applyOrganizationPatch(ctx, *current.Organization, *body.Organization)
	patched.item.Organization, patched.reverify = &org, patched.reverify || retargeted
	return patched, nil
}

var accountMismatch = VerificationFailure{RetryClass: RetryClassDetermined, CloudErrorCode: "ACCOUNT_ID_MISMATCH", Hint: "The role is in another account."}

func roleInAccount(roleArn string, accountID *string) bool {
	if accountID == nil {
		return true
	}
	match := roleArnAccount.FindStringSubmatch(roleArn)
	return match != nil && match[1] == *accountID
}

func applySettingsPatch(ctx context.Context, item *gen.AwsDeployment, body gen.AwsDeploymentPatch) {
	if body.Name != nil {
		item.Name = *body.Name
	}
	if body.Tags != nil {
		item.Tags = *body.Tags
	}
	if _, ok := presentFields(ctx)["allowedRegions"]; ok {
		item.AllowedRegions = body.AllowedRegions
	}
	if body.DisabledCapabilities != nil {
		item.DisabledCapabilities = *body.DisabledCapabilities
	}
	if body.DeploymentMethod != nil {
		item.DeploymentMethod = body.DeploymentMethod
	}
	if body.DeletionProtection != nil {
		item.DeletionProtection = *body.DeletionProtection
	}
}

func applyOrganizationPatch(ctx context.Context, org gen.AwsOrganization, patch gen.AwsOrganizationPatch) (gen.AwsOrganization, bool) {
	retargeted := patch.RootID != nil || patch.OrganizationalUnitIds != nil
	if patch.RootID != nil {
		org.RootID, org.OrganizationalUnitIds = patch.RootID, nil
	}
	if patch.OrganizationalUnitIds != nil {
		org.OrganizationalUnitIds, org.RootID = patch.OrganizationalUnitIds, nil
	}
	if _, ok := presentFields(ctx, "organization")["excludedAccountIds"]; ok {
		org.ExcludedAccountIds = patch.ExcludedAccountIds
	}
	if patch.MemberRoleName != nil {
		org.MemberRoleName = patch.MemberRoleName
	}
	if patch.MemberRolePath != nil {
		org.MemberRolePath = patch.MemberRolePath
	}
	return org, retargeted
}

func (s *apiServer) VerifyAwsDeployment(_ context.Context, req gen.VerifyAwsDeploymentRequestObject) (gen.VerifyAwsDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.VerifyAwsDeployment404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != stored.etag() {
		return gen.VerifyAwsDeployment412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	if failure, ok := store.nextFailure(deref(stored.item.RoleArn)); ok {
		return gen.VerifyAwsDeployment422JSONResponse(verificationFailed(failure)), nil
	}
	stored.item.Status, stored.item.ErrorCode, stored.item.ErrorMessage = gen.DeploymentStatusActive, nil, nil
	stored.version++
	return gen.VerifyAwsDeployment200JSONResponse{Body: stored.item, Headers: gen.VerifyAwsDeployment200ResponseHeaders{ETag: stored.etag()}}, nil
}

func (s *apiServer) RotateAwsExternalID(_ context.Context, req gen.RotateAwsExternalIDRequestObject) (gen.RotateAwsExternalIDResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.RotateAwsExternalID404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != stored.etag() {
		return gen.RotateAwsExternalID412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	if failure, ok := store.nextFailure(deref(stored.item.RoleArn)); ok {
		return gen.RotateAwsExternalID422JSONResponse(verificationFailed(failure)), nil
	}
	stored.item.ExternalID = derivedExternalID(stored.item.ID)
	stored.item.ExternalIDSource = gen.ExternalIDSourceDerived
	stored.item.ExternalIDKeyVersion = intPointer(ExternalIDKeyVersion)
	stored.version++
	return gen.RotateAwsExternalID200JSONResponse{Body: stored.item, Headers: gen.RotateAwsExternalID200ResponseHeaders{ETag: stored.etag()}}, nil
}

func (s *apiServer) DeleteAwsDeployment(_ context.Context, req gen.DeleteAwsDeploymentRequestObject) (gen.DeleteAwsDeploymentResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.DeleteAwsDeployment404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != nil && *req.Params.IfMatch != stored.etag() {
		return gen.DeleteAwsDeployment412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	if stored.item.DeletionProtection {
		return gen.DeleteAwsDeployment409JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeDeletionProtected, "Deletion protection is on")), nil
	}
	delete(store.byID, req.ID)
	delete(store.members, req.ID)
	cleanup := []gen.CleanupItem{{Resource: deref(stored.item.RoleArn), Description: "The IAM role still trusts Act. Delete it, or keep it to connect again later."}}
	return gen.DeleteAwsDeployment200JSONResponse{ID: req.ID, CleanupRequired: cleanup}, nil
}

func (s *apiServer) ListDeployments(_ context.Context, req gen.ListDeploymentsRequestObject) (gen.ListDeploymentsResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	params := req.Params
	items := []gen.DeploymentSummary{}
	for _, stored := range store.byID {
		summary := stored.summary()
		if params.Cloud != nil && *params.Cloud != summary.Cloud {
			continue
		}
		if params.Status != nil && *params.Status != summary.Status {
			continue
		}
		if params.Target != nil && !slices.Contains(summary.Targets, *params.Target) {
			continue
		}
		if params.Tag != nil && !hasTags(summary.Tags, *params.Tag) {
			continue
		}
		items = append(items, summary)
	}
	slices.SortFunc(items, func(a, b gen.DeploymentSummary) int { return strings.Compare(a.ID, b.ID) })
	size := listPageSize
	if params.PageSize != nil {
		size = *params.PageSize
	}
	start := 0
	if params.PageToken != nil {
		parsed, err := strconv.Atoi(*params.PageToken)
		if err != nil || parsed < 0 || parsed > len(items) {
			return gen.ListDeployments400JSONResponse(invalid("pageToken", "invalid")), nil
		}
		start = parsed
	}
	end := min(start+size, len(items))
	page := gen.ListDeployments200JSONResponse{Items: items[start:end]}
	if end < len(items) {
		token := strconv.Itoa(end)
		page.NextPageToken = &token
	}
	return page, nil
}

func (s *storedDeployment) summary() gen.DeploymentSummary {
	scope := gen.DeploymentScopeAccount
	if s.item.Organization != nil {
		scope = gen.DeploymentScopeOrganization
	}
	return gen.DeploymentSummary{
		ID:                 s.item.ID,
		Cloud:              gen.CloudAws,
		Name:               s.item.Name,
		Scope:              scope,
		Targets:            s.targets(),
		Status:             s.item.Status,
		UpdateAvailable:    s.item.UpdateAvailable,
		DeletionProtection: s.item.DeletionProtection,
		Tags:               s.item.Tags,
		CreatedAt:          s.item.CreatedAt,
	}
}

func (s *apiServer) GetDeploymentCoverage(_ context.Context, req gen.GetDeploymentCoverageRequestObject) (gen.GetDeploymentCoverageResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.GetDeploymentCoverage404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	coverage := gen.GetDeploymentCoverage200JSONResponse{
		DeploymentID:   req.ID,
		DiscoveryState: gen.DiscoveryStateComplete,
		FailedAccounts: []gen.FailedMemberAccount{},
	}
	discovered := stored.item.CreatedAt
	coverage.LastDiscoveryAt = &discovered
	for _, member := range store.memberAccounts(stored) {
		switch member.Status {
		case gen.MemberAccountStatusConnected:
			coverage.AccountsExpected++
			coverage.AccountsConnected++
		case gen.MemberAccountStatusPending:
			coverage.AccountsExpected++
			coverage.AccountsPending++
		case gen.MemberAccountStatusFailed:
			coverage.AccountsExpected++
			coverage.AccountsFailed++
			coverage.FailedAccounts = append(coverage.FailedAccounts, gen.FailedMemberAccount{
				AccountID: member.AccountID, ErrorCode: deref(member.ErrorCode), FailingSince: stored.item.CreatedAt,
			})
		case gen.MemberAccountStatusExcluded:
		}
	}
	return coverage, nil
}

func (s *deploymentStore) memberAccounts(stored *storedDeployment) []gen.MemberAccount {
	if members, ok := s.members[stored.item.ID]; ok {
		return members
	}
	if stored.item.AccountID == nil {
		return []gen.MemberAccount{}
	}
	status := gen.MemberAccountStatusConnected
	if stored.item.Status == gen.DeploymentStatusFailed {
		status = gen.MemberAccountStatusFailed
	}
	return []gen.MemberAccount{{AccountID: *stored.item.AccountID, Status: status, ErrorCode: stored.item.ErrorCode}}
}

func (s *apiServer) ListDeploymentAccounts(_ context.Context, req gen.ListDeploymentAccountsRequestObject) (gen.ListDeploymentAccountsResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.ListDeploymentAccounts404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	items := []gen.MemberAccount{}
	for _, member := range store.memberAccounts(stored) {
		if req.Params.Status == nil || *req.Params.Status == member.Status {
			items = append(items, member)
		}
	}
	return gen.ListDeploymentAccounts200JSONResponse{Items: items}, nil
}

func fakeDigest(fill string) string {
	return strings.Repeat(fill, sha256HexLength)
}

func consoleURL(id string) *string {
	url := ConsoleOrigin + "/settings/deployments/" + id
	return &url
}

func intPointer(value int) *int {
	return &value
}

func deploymentSource(source gen.DeploymentChangeSource) *gen.DeploymentChangeSource {
	return &source
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func hasTags(tags, want map[string]string) bool {
	for key, value := range want {
		if tags[key] != value {
			return false
		}
	}
	return true
}
