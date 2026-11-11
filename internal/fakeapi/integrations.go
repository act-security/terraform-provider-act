package fakeapi

import (
	"context"
	"crypto/rand"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
)

const (
	ConnectionCheckFailureTrigger = "xoxb-fail-connection-check"
	EmailIntegrationID            = "00000000-0000-4000-8000-0000000000e1"
)

type integrationFields struct {
	config []string
	secret string
}

var integrationTypeFields = map[gen.InstallableIntegrationType]integrationFields{
	gen.InstallableIntegrationTypeSlack:  {secret: "botToken"},
	gen.InstallableIntegrationTypeJira:   {config: []string{"baseUrl", "email"}, secret: "apiToken"},
	gen.InstallableIntegrationTypeWiz:    {config: []string{"clientId", "apiEndpointUrl"}, secret: "clientSecret"},
	gen.InstallableIntegrationTypeSplunk: {config: []string{"hecUrl", "tlsVerification"}, secret: "hecToken"},
}

var integrationDisplayNames = map[gen.IntegrationType]string{
	gen.IntegrationTypeSlack:  "Slack",
	gen.IntegrationTypeJira:   "Jira",
	gen.IntegrationTypeWiz:    "Wiz",
	gen.IntegrationTypeSplunk: "Splunk",
	gen.IntegrationTypeEmail:  "Email",
}

type storedIntegration struct {
	item    gen.Integration
	secret  string
	version int
}

type integrationStore struct {
	mu          sync.Mutex
	byID        map[string]*storedIntegration
	idempotency map[string]idempotentCreate
}

type idempotentCreate struct {
	body     gen.IntegrationCreate
	response gen.Integration
	etag     string
}

func newIntegrationStore(now time.Time) *integrationStore {
	return &integrationStore{
		byID: map[string]*storedIntegration{
			EmailIntegrationID: {item: gen.Integration{
				ID:          EmailIntegrationID,
				Type:        gen.IntegrationTypeEmail,
				DisplayName: "Email",
				Status:      gen.IntegrationStatusConnected,
				Config:      map[string]string{},
				Secrets:     map[string]gen.IntegrationSecretState{},
				ConnectedAt: now,
				UpdatedAt:   now,
			}},
		},
		idempotency: map[string]idempotentCreate{},
	}
}

func (s *storedIntegration) etag() string {
	return fmt.Sprintf(`"%s-%d"`, s.item.ID, s.version)
}

func (f *Fake) IntegrationSecret(id string) (string, bool) {
	f.integrations.mu.Lock()
	defer f.integrations.mu.Unlock()
	stored, ok := f.integrations.byID[id]
	if !ok {
		return "", false
	}
	return stored.secret, true
}

func (f *Fake) RotateIntegrationSecretOutOfBand(id, secret string) bool {
	f.integrations.mu.Lock()
	defer f.integrations.mu.Unlock()
	stored, ok := f.integrations.byID[id]
	if !ok {
		return false
	}
	now := f.now().UTC().Add(time.Second)
	stored.secret = secret
	stored.version++
	stored.item.UpdatedAt = now
	stored.item.LastModifiedVia = changeSource(gen.IntegrationChangeSourceUI)
	for field := range stored.item.Secrets {
		stored.item.Secrets[field] = gen.IntegrationSecretState{Configured: true, UpdatedAt: now}
	}
	return true
}

func (f *Fake) DeleteIntegrationOutOfBand(id string) {
	f.integrations.mu.Lock()
	defer f.integrations.mu.Unlock()
	delete(f.integrations.byID, id)
}

func (s *apiServer) ListIntegrationTypes(context.Context, gen.ListIntegrationTypesRequestObject) (gen.ListIntegrationTypesResponseObject, error) {
	store := s.fake.integrations
	store.mu.Lock()
	defer store.mu.Unlock()
	installed := map[gen.IntegrationType]bool{}
	for _, stored := range store.byID {
		installed[stored.item.Type] = true
	}
	items := []gen.IntegrationTypeInfo{}
	for _, kind := range []gen.InstallableIntegrationType{
		gen.InstallableIntegrationTypeSlack,
		gen.InstallableIntegrationTypeJira,
		gen.InstallableIntegrationTypeWiz,
		gen.InstallableIntegrationTypeSplunk,
	} {
		fields := integrationTypeFields[kind]
		described := []gen.IntegrationTypeField{}
		for _, name := range fields.config {
			described = append(described, gen.IntegrationTypeField{Name: name})
		}
		described = append(described, gen.IntegrationTypeField{Name: fields.secret, Sensitive: true})
		items = append(items, gen.IntegrationTypeInfo{
			Type:        gen.IntegrationType(kind),
			DisplayName: integrationDisplayNames[gen.IntegrationType(kind)],
			Category:    "notifications",
			Installable: true,
			Installed:   installed[gen.IntegrationType(kind)],
			Fields:      described,
		})
	}
	items = append(items, gen.IntegrationTypeInfo{
		Type:        gen.IntegrationTypeEmail,
		DisplayName: "Email",
		Category:    "notifications",
		Installed:   true,
		Fields:      []gen.IntegrationTypeField{},
	})
	return gen.ListIntegrationTypes200JSONResponse{Items: items}, nil
}

func (s *apiServer) ListIntegrations(_ context.Context, req gen.ListIntegrationsRequestObject) (gen.ListIntegrationsResponseObject, error) {
	store := s.fake.integrations
	store.mu.Lock()
	defer store.mu.Unlock()
	items := []gen.Integration{}
	for _, stored := range store.byID {
		if req.Params.Type != nil && stored.item.Type != *req.Params.Type {
			continue
		}
		if req.Params.Status != nil && stored.item.Status != *req.Params.Status {
			continue
		}
		items = append(items, stored.item)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ConnectedAt.Before(items[j].ConnectedAt) })
	return gen.ListIntegrations200JSONResponse{Items: items}, nil
}

func (s *apiServer) GetIntegration(_ context.Context, req gen.GetIntegrationRequestObject) (gen.GetIntegrationResponseObject, error) {
	store := s.fake.integrations
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.GetIntegration404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	return gen.GetIntegration200JSONResponse{Body: stored.item, Headers: gen.GetIntegration200ResponseHeaders{ETag: stored.etag()}}, nil
}

func (s *apiServer) CreateIntegration(_ context.Context, req gen.CreateIntegrationRequestObject) (gen.CreateIntegrationResponseObject, error) {
	store := s.fake.integrations
	store.mu.Lock()
	defer store.mu.Unlock()
	body := *req.Body
	if key := req.Params.IdempotencyKey; key != nil {
		if previous, ok := store.idempotency[*key]; ok {
			if fmt.Sprint(previous.body) != fmt.Sprint(body) {
				return gen.CreateIntegration422JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeIdempotencyMismatch, "Idempotency key reused")), nil
			}
			return gen.CreateIntegration201JSONResponse{Body: previous.response, Headers: gen.CreateIntegration201ResponseHeaders{ETag: previous.etag}}, nil
		}
	}
	fields, ok := integrationTypeFields[body.Type]
	if !ok {
		return gen.CreateIntegration400JSONResponse(invalid("type", "unknown_type")), nil
	}
	config := configMap(body.Config)
	for _, name := range fields.config {
		if config[name] == "" {
			return gen.CreateIntegration400JSONResponse(invalid("config."+name, "required")), nil
		}
	}
	secret := secretOf(&body.Secrets, fields.secret)
	if secret == "" {
		return gen.CreateIntegration400JSONResponse(invalid("secrets."+fields.secret, "required")), nil
	}
	if secret == ConnectionCheckFailureTrigger {
		return gen.CreateIntegration422JSONResponse(connectionCheckFailed()), nil
	}
	for _, stored := range store.byID {
		if stored.item.Type == gen.IntegrationType(body.Type) {
			e := envelope(gen.ErrorEnvelopeErrorCodeAlreadyExists, "The resource already exists")
			details := map[string]any{"integrationId": stored.item.ID}
			e.Error.Details = &details
			return gen.CreateIntegration409JSONResponse(e), nil
		}
	}
	now := s.fake.now().UTC()
	stored := &storedIntegration{
		item: gen.Integration{
			ID:              randomUUID(),
			Type:            gen.IntegrationType(body.Type),
			DisplayName:     integrationDisplayNames[gen.IntegrationType(body.Type)],
			Status:          gen.IntegrationStatusConnected,
			Config:          config,
			Secrets:         map[string]gen.IntegrationSecretState{fields.secret: {Configured: true, UpdatedAt: now}},
			CreatedVia:      changeSource(gen.IntegrationChangeSourceAPI),
			LastModifiedVia: changeSource(gen.IntegrationChangeSourceAPI),
			ConnectedAt:     now,
			UpdatedAt:       now,
		},
		secret: secret,
	}
	store.byID[stored.item.ID] = stored
	if key := req.Params.IdempotencyKey; key != nil {
		store.idempotency[*key] = idempotentCreate{body: body, response: stored.item, etag: stored.etag()}
	}
	return gen.CreateIntegration201JSONResponse{Body: stored.item, Headers: gen.CreateIntegration201ResponseHeaders{ETag: stored.etag()}}, nil
}

func (s *apiServer) UpdateIntegration(_ context.Context, req gen.UpdateIntegrationRequestObject) (gen.UpdateIntegrationResponseObject, error) {
	store := s.fake.integrations
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok {
		return gen.UpdateIntegration404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != stored.etag() {
		return gen.UpdateIntegration412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	body := *req.Body
	if gen.IntegrationType(body.Type) != stored.item.Type {
		return gen.UpdateIntegration400JSONResponse(invalid("type", "type_mismatch")), nil
	}
	fields := integrationTypeFields[body.Type]
	changed := configMap(body.Config)
	configChanged := false
	for name, value := range changed {
		if stored.item.Config[name] != value {
			configChanged = true
		}
	}
	secret := secretOf(body.Secrets, fields.secret)
	if configChanged && secret == "" {
		return gen.UpdateIntegration400JSONResponse(invalid("secrets."+fields.secret, "secret_required")), nil
	}
	if secret == ConnectionCheckFailureTrigger {
		return gen.UpdateIntegration422JSONResponse(connectionCheckFailed()), nil
	}
	now := s.fake.now().UTC().Add(time.Duration(stored.version+1) * time.Millisecond)
	for name, value := range changed {
		stored.item.Config[name] = value
	}
	if secret != "" && secret != stored.secret {
		stored.secret = secret
		stored.item.Secrets[fields.secret] = gen.IntegrationSecretState{Configured: true, UpdatedAt: now}
	}
	stored.version++
	stored.item.UpdatedAt = now
	stored.item.LastModifiedVia = changeSource(gen.IntegrationChangeSourceAPI)
	return gen.UpdateIntegration200JSONResponse{Body: stored.item, Headers: gen.UpdateIntegration200ResponseHeaders{ETag: stored.etag()}}, nil
}

func (s *apiServer) DeleteIntegration(_ context.Context, req gen.DeleteIntegrationRequestObject) (gen.DeleteIntegrationResponseObject, error) {
	store := s.fake.integrations
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[req.ID]
	if !ok || stored.item.Type == gen.IntegrationTypeEmail {
		return gen.DeleteIntegration404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != nil && *req.Params.IfMatch != stored.etag() {
		return gen.DeleteIntegration412JSONResponse(envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")), nil
	}
	delete(store.byID, req.ID)
	return gen.DeleteIntegration204Response{}, nil
}

func configMap(config *gen.IntegrationConfig) map[string]string {
	out := map[string]string{}
	if config == nil {
		return out
	}
	set := func(name string, value *string) {
		if value != nil {
			out[name] = *value
		}
	}
	set("baseUrl", config.BaseURL)
	set("clientId", config.ClientID)
	set("apiEndpointUrl", config.APIEndpointURL)
	set("hecUrl", config.HecURL)
	if config.Email != nil {
		out["email"] = string(*config.Email)
	}
	if config.TLSVerification != nil {
		out["tlsVerification"] = string(*config.TLSVerification)
	}
	return out
}

func secretOf(secrets *gen.IntegrationSecrets, name string) string {
	if secrets == nil {
		return ""
	}
	values := map[string]*string{
		"botToken":     secrets.BotToken,
		"apiToken":     secrets.APIToken,
		"clientSecret": secrets.ClientSecret,
		"hecToken":     secrets.HecToken,
	}
	if value := values[name]; value != nil {
		return *value
	}
	return ""
}

func changeSource(source gen.IntegrationChangeSource) *gen.IntegrationChangeSource {
	return &source
}

func invalid(attribute, reason string) gen.ErrorEnvelope {
	e := envelope(gen.ErrorEnvelopeErrorCodeInvalidRequest, "The request is not valid")
	details := map[string]any{"attribute": attribute, "reason": reason}
	e.Error.Details = &details
	return e
}

func connectionCheckFailed() gen.ErrorEnvelope {
	e := envelope(gen.ErrorEnvelopeErrorCodeConnectionCheckFailed, "Connection check failed")
	details := map[string]any{"note": "The provider rejected the credentials"}
	e.Error.Details = &details
	return e
}

func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (f *Fake) SeedIntegration(kind, secret string) string {
	f.integrations.mu.Lock()
	defer f.integrations.mu.Unlock()
	fields := integrationTypeFields[gen.InstallableIntegrationType(kind)]
	now := f.now().UTC()
	stored := &storedIntegration{
		item: gen.Integration{
			ID:          randomUUID(),
			Type:        gen.IntegrationType(kind),
			DisplayName: integrationDisplayNames[gen.IntegrationType(kind)],
			Status:      gen.IntegrationStatusConnected,
			Config:      map[string]string{},
			Secrets:     map[string]gen.IntegrationSecretState{fields.secret: {Configured: true, UpdatedAt: now}},
			CreatedVia:  changeSource(gen.IntegrationChangeSourceUI),
			ConnectedAt: now,
			UpdatedAt:   now,
		},
		secret: secret,
	}
	f.integrations.byID[stored.item.ID] = stored
	return stored.item.ID
}
