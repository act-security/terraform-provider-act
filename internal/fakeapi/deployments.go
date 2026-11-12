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
	"sort"
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
)

var (
	roleArnAccount = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:iam::(\d{12}):role/`)
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
	}
}

func (s *storedDeployment) etag() string {
	return fmt.Sprintf(`"%s-%d"`, s.item.ID, s.version)
}

func (s *storedDeployment) naturalKey() string {
	if s.item.Organization != nil {
		return "aws:organization:" + s.item.Organization.OrganizationID
	}
	return "aws:account:" + deref(s.item.AccountID)
}

func (s *storedDeployment) targets() []string {
	if s.item.Organization == nil {
		return []string{deref(s.item.AccountID)}
	}
	org := s.item.Organization
	targets := []string{org.OrganizationID}
	if org.RootID != nil {
		targets = append(targets, *org.RootID)
	}
	if org.OrganizationalUnitIds != nil {
		targets = append(targets, *org.OrganizationalUnitIds...)
	}
	return targets
}

func (f *Fake) DeploymentID(naturalKey, variant string) string {
	mac := hmac.New(sha256.New, cellKey)
	mac.Write([]byte(f.cfg.TenantID + "|" + naturalKey + "|" + variant))
	b := mac.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x80
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func derivedExternalID(id string) string {
	mac := hmac.New(sha256.New, cellKey)
	mac.Write([]byte("external-id|" + id))
	return hex.EncodeToString(mac.Sum(nil))[:40]
}

func (f *Fake) QueueVerificationFailures(roleArn string, failures ...VerificationFailure) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	f.deployments.failures[roleArn] = append(f.deployments.failures[roleArn], failures...)
}

func (f *Fake) FailDeploymentOutOfBand(id, code, message string) bool {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	stored, ok := f.deployments.byID[id]
	if !ok {
		return false
	}
	stored.item.Status = gen.DeploymentStatusFailed
	stored.item.ErrorCode = &code
	stored.item.ErrorMessage = &message
	return true
}

func (f *Fake) RenameDeploymentOutOfBand(id, name string) bool {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	stored, ok := f.deployments.byID[id]
	if !ok {
		return false
	}
	stored.item.Name = name
	stored.version++
	return true
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

func (f *Fake) SeedLegacyAwsAccountDeployment(accountID, roleArn, externalID string) string {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	id := randomUUID()
	now := f.now().UTC()
	method := gen.AwsDeploymentMethodCloudformation
	stored := &storedDeployment{item: gen.AwsDeployment{
		ID:                   id,
		Name:                 "aws-" + accountID,
		Tags:                 map[string]string{},
		AccountID:            &accountID,
		RoleArn:              roleArn,
		DisabledCapabilities: []gen.AwsCapability{},
		DeploymentMethod:     &method,
		ExternalID:           externalID,
		ExternalIDSource:     gen.ExternalIDSourceLegacy,
		ExternalIDKeyVersion: ExternalIDKeyVersion,
		Status:               gen.DeploymentStatusActive,
		Warnings:             []gen.DeploymentWarning{},
		ConsoleURL:           consoleURL(id),
		CreatedVia:           deploymentSource(gen.DeploymentChangeSourceUI),
		CreatedAt:            now,
	}}
	f.deployments.byID[id] = stored
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
	key := "aws:account:" + deref(params.AccountID)
	if params.OrganizationID != nil {
		key = "aws:organization:" + *params.OrganizationID
	}
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	id := s.fake.DeploymentID(key, deref(params.Variant))
	externalID, source := derivedExternalID(id), gen.ExternalIDSourceDerived
	var existing *gen.ExistingDeployment
	if stored := store.byNaturalKey(key); stored != nil && params.Variant == nil {
		id = stored.item.ID
		externalID, source = stored.item.ExternalID, stored.item.ExternalIDSource
		existing = &gen.ExistingDeployment{ID: id, Status: stored.item.Status, CreatedVia: stored.item.CreatedVia}
	}
	roleName := "ActSecurityRole-" + id
	var roleArn *string
	if params.AccountID != nil {
		arn := "arn:aws:iam::" + *params.AccountID + ":role/" + roleName
		roleArn = &arn
	}
	return gen.GetAwsOnboarding200JSONResponse{
		DeploymentID:                 id,
		ExistingDeployment:           existing,
		ActPrincipalArn:              ActPrincipalArn,
		DeprecatedPrincipals:         []gen.DeprecatedPrincipal{{Arn: DeprecatedPrincipal, ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}},
		ExternalID:                   externalID,
		ExternalIDSource:             source,
		TargetExternalID:             derivedExternalID(id),
		ExternalIDKeyVersion:         ExternalIDKeyVersion,
		RoleName:                     roleName,
		RoleArn:                      roleArn,
		AssumeRolePolicyJSON:         assumeRolePolicy(externalID),
		CustomPolicyDocuments:        map[string]string{"ActSecurityReadOnly": `{"Version":"2012-10-17","Statement":[]}`},
		ManagedPolicyArns:            []string{"arn:aws:iam::aws:policy/SecurityAudit"},
		MemberRoleName:               roleName,
		MemberRolePath:               "/",
		CloudformationTemplateURL:    ConsoleOrigin + "/templates/aws/" + ModuleVersion + "/role.yaml",
		CloudformationTemplateSha256: strings.Repeat("a", 64),
		ModuleSource:                 ModuleSource,
		ModuleVersion:                ModuleVersion,
		ModuleSha256:                 strings.Repeat("b", 64),
		PermissionsHash:              strings.Repeat("c", 64),
		DeploymentVersion:            "2026.11",
		ModuleVersions: []gen.ModuleVersion{{
			Version: ModuleVersion, Sha256: strings.Repeat("b", 64), PermissionsHash: strings.Repeat("c", 64), DeploymentVersion: "2026.11",
		}},
	}, nil
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
	natural := "aws:account:" + deref(body.AccountID)
	if body.Organization != nil {
		natural = "aws:organization:" + body.Organization.OrganizationID
		if (body.Organization.RootID == nil) == (body.Organization.OrganizationalUnitIds == nil) {
			return gen.CreateAwsDeployment400JSONResponse(invalid("organization.rootId", "exactly_one_scope")), nil
		}
	}
	if existing := store.byNaturalKey(natural); existing != nil {
		e := envelope(gen.ErrorEnvelopeErrorCodeAlreadyExists, "A deployment for this target already exists")
		details := map[string]any{"deploymentId": existing.item.ID}
		e.Error.Details = &details
		return gen.CreateAwsDeployment409JSONResponse(e), nil
	}
	if body.DeploymentID != s.fake.DeploymentID(natural, "") {
		return gen.CreateAwsDeployment400JSONResponse(invalid("deploymentId", "not_issued_by_act")), nil
	}
	roleAccount := roleArnAccount.FindStringSubmatch(body.RoleArn)
	if roleAccount == nil {
		return gen.CreateAwsDeployment400JSONResponse(invalid("roleArn", "invalid_arn")), nil
	}
	if body.AccountID != nil && roleAccount[1] != *body.AccountID {
		return gen.CreateAwsDeployment422JSONResponse(verificationFailed(VerificationFailure{RetryClass: RetryClassDetermined, CloudErrorCode: "ACCOUNT_ID_MISMATCH", Hint: "The role is in another account."})), nil
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
		RoleArn:              body.RoleArn,
		AllowedRegions:       body.AllowedRegions,
		DisabledCapabilities: []gen.AwsCapability{},
		ExternalID:           derivedExternalID(body.DeploymentID),
		ExternalIDSource:     gen.ExternalIDSourceDerived,
		ExternalIDKeyVersion: ExternalIDKeyVersion,
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
		item.ExternalIDKeyVersion = *body.ExternalIDKeyVersion
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
		item.Organization = &gen.AwsOrganization{
			OrganizationID:        org.OrganizationID,
			RootID:                org.RootID,
			OrganizationalUnitIds: org.OrganizationalUnitIds,
			ExcludedAccountIds:    org.ExcludedAccountIds,
			ManagementAccountID:   roleAccount,
			MemberRoleName:        "ActSecurityRole-" + body.DeploymentID,
			MemberRolePath:        "/",
		}
		if org.MemberRoleName != nil {
			item.Organization.MemberRoleName = *org.MemberRoleName
		}
		if org.MemberRolePath != nil {
			item.Organization.MemberRolePath = *org.MemberRolePath
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
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
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
	if req.Params.IfMatch != stored.etag() {
		return gen.UpdateAwsDeployment412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	body := *req.Body
	present := presentFields(ctx)
	next := stored.item
	reverify := false
	if body.RoleArn != nil && *body.RoleArn != next.RoleArn {
		roleAccount := roleArnAccount.FindStringSubmatch(*body.RoleArn)
		if next.AccountID != nil && (roleAccount == nil || roleAccount[1] != *next.AccountID) {
			return gen.UpdateAwsDeployment422JSONResponse(verificationFailed(VerificationFailure{RetryClass: RetryClassDetermined, CloudErrorCode: "ACCOUNT_ID_MISMATCH", Hint: "The role is in another account."})), nil
		}
		next.RoleArn = *body.RoleArn
		reverify = true
	}
	if body.Name != nil {
		next.Name = *body.Name
	}
	if body.Tags != nil {
		next.Tags = *body.Tags
	}
	if _, ok := present["allowedRegions"]; ok {
		next.AllowedRegions = body.AllowedRegions
	}
	if body.DisabledCapabilities != nil {
		next.DisabledCapabilities = *body.DisabledCapabilities
	}
	if body.DeploymentMethod != nil {
		next.DeploymentMethod = body.DeploymentMethod
	}
	if body.DeletionProtection != nil {
		next.DeletionProtection = *body.DeletionProtection
	}
	if body.Organization != nil {
		if next.Organization == nil {
			return gen.UpdateAwsDeployment400JSONResponse(invalid("organization", "not_an_organization")), nil
		}
		org := *next.Organization
		patch := body.Organization
		if patch.RootID != nil {
			org.RootID, org.OrganizationalUnitIds = patch.RootID, nil
			reverify = true
		}
		if patch.OrganizationalUnitIds != nil {
			org.OrganizationalUnitIds, org.RootID = patch.OrganizationalUnitIds, nil
			reverify = true
		}
		if _, ok := presentFields(ctx, "organization")["excludedAccountIds"]; ok {
			org.ExcludedAccountIds = patch.ExcludedAccountIds
		}
		if patch.MemberRoleName != nil {
			org.MemberRoleName = *patch.MemberRoleName
		}
		if patch.MemberRolePath != nil {
			org.MemberRolePath = *patch.MemberRolePath
		}
		next.Organization = &org
	}
	if reverify {
		if failure, ok := store.nextFailure(next.RoleArn); ok {
			return gen.UpdateAwsDeployment422JSONResponse(verificationFailed(failure)), nil
		}
		next.Status, next.ErrorCode, next.ErrorMessage = gen.DeploymentStatusActive, nil, nil
	}
	stored.item = next
	stored.version++
	return gen.UpdateAwsDeployment200JSONResponse{Body: stored.item, Headers: gen.UpdateAwsDeployment200ResponseHeaders{ETag: stored.etag()}}, nil
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
	if failure, ok := store.nextFailure(stored.item.RoleArn); ok {
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
	if failure, ok := store.nextFailure(stored.item.RoleArn); ok {
		return gen.RotateAwsExternalID422JSONResponse(verificationFailed(failure)), nil
	}
	stored.item.ExternalID = derivedExternalID(stored.item.ID)
	stored.item.ExternalIDSource = gen.ExternalIDSourceDerived
	stored.item.ExternalIDKeyVersion = ExternalIDKeyVersion
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
	cleanup := []gen.CleanupItem{{Resource: stored.item.RoleArn, Description: "The IAM role still trusts Act. Delete it, or keep it to connect again later."}}
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
		if params.Target != nil && !contains(summary.Targets, *params.Target) {
			continue
		}
		if params.Tag != nil && !hasTags(summary.Tags, *params.Tag) {
			continue
		}
		items = append(items, summary)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	size := 2
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

func consoleURL(id string) string {
	return ConsoleOrigin + "/settings/deployments/" + id
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

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasTags(tags, want map[string]string) bool {
	for key, value := range want {
		if tags[key] != value {
			return false
		}
	}
	return true
}
