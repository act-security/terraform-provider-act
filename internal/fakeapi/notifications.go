package fakeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
)

const (
	SlackChannelSecurityID   = "C0SECURITY1"
	SlackChannelSecurityName = "security-alerts"
	SlackChannelPlatformID   = "C0PLATFORM1"
	SlackChannelPlatformName = "platform"
	currentClientRevision    = 1
)

var slackChannels = []gen.SlackChannel{
	{ID: SlackChannelSecurityID, Name: SlackChannelSecurityName},
	{ID: SlackChannelPlatformID, Name: SlackChannelPlatformName},
}

var notificationEventTypes = []gen.NotificationEventTypeInfo{
	{EventType: "policy.drift_detected", Category: "policies", Title: "Policy drift detected", Description: "A deployed policy no longer matches its definition."},
	{EventType: "policy_audit.finished", Category: "policies", Title: "Policy audit finished", Description: "A policy audit run completed."},
	{
		EventType:   "simulation.finished",
		Category:    "simulations",
		Title:       "Simulation finished",
		Description: "A policy simulation completed.",
		ConditionFields: []gen.NotificationConditionFieldInfo{{
			Field:    gen.NotificationConditionFieldSource,
			Operator: gen.NotificationConditionOperatorIn,
			Values:   []string{"campaigns", "policy_mgmt"},
		}},
	},
	{EventType: "connector.unhealthy", Category: "connectors", Title: "Connector unhealthy", Description: "A cloud connector stopped reporting."},
}

var notificationLimits = gen.NotificationRuleLimits{
	MaxNameLength:               100,
	MaxEventTypesPerRule:        10,
	MaxActionsPerRule:           2,
	MaxRecipientsPerRule:        20,
	MaxEmailRecipients:          100,
	MaxSlackChannels:            50,
	MaxEnabledRulesPerEventType: 50,
	MaxRecipientNameLength:      100,
	ActivityRetentionMonths:     6,
}

type notificationStore struct {
	mu                    sync.Mutex
	rules                 map[string]*gen.NotificationRule
	recipients            map[string]*gen.NotificationRecipient
	ruleKeys              map[string]idempotentNotification
	recipientKeys         map[string]idempotentNotification
	loseNextCreateReply   bool
	editBeforeReplace     string
	ruleCreateRequests    int
	replacedWithoutFields []string
}

type idempotentNotification struct {
	body string
	id   string
}

func newNotificationStore() *notificationStore {
	return &notificationStore{
		rules:         map[string]*gen.NotificationRule{},
		recipients:    map[string]*gen.NotificationRecipient{},
		ruleKeys:      map[string]idempotentNotification{},
		recipientKeys: map[string]idempotentNotification{},
	}
}

func revisionTag(revision int) string {
	return fmt.Sprintf(`"%d"`, revision)
}

func matchesRevision(ifMatch string, revision int) bool {
	for _, tag := range strings.Split(ifMatch, ",") {
		tag = strings.TrimPrefix(strings.TrimSpace(tag), "W/")
		if tag == "*" || tag == revisionTag(revision) {
			return true
		}
	}
	return false
}

func preconditionFailed(revision int) gen.ErrorEnvelope {
	e := envelope(gen.ErrorEnvelopeErrorCodePreconditionFailed, "The resource changed since it was read")
	details := map[string]any{"etag": revisionTag(revision)}
	e.Error.Details = &details
	return e
}

func notificationsDisabled() gen.ErrorEnvelope {
	e := featureDisabled()
	details := map[string]any{"feature": "notification_rules"}
	e.Error.Details = &details
	return e
}

func domainInvalid(reason, pointer string) gen.ErrorEnvelope {
	e := envelope(gen.ErrorEnvelopeErrorCodeInvalidRequest, "The request is not valid")
	details := map[string]any{"reason": reason, "pointer": pointer}
	e.Error.Details = &details
	return e
}

func notConnected(pointer string) gen.ErrorEnvelope {
	e := envelope(gen.ErrorEnvelopeErrorCodeIntegrationNotConnected, "The integration is not connected")
	details := map[string]any{"pointer": pointer}
	e.Error.Details = &details
	return e
}

type writeError struct {
	status int
	body   gen.ErrorEnvelope
}

func (f *Fake) integrationTypeOf(id string) (gen.IntegrationType, bool) {
	f.integrations.mu.Lock()
	defer f.integrations.mu.Unlock()
	stored, ok := f.integrations.byID[id]
	if !ok {
		return "", false
	}
	return stored.item.Type, true
}

func (f *Fake) slackIntegrationID() (string, bool) {
	f.integrations.mu.Lock()
	defer f.integrations.mu.Unlock()
	for id, stored := range f.integrations.byID {
		if stored.item.Type == gen.IntegrationTypeSlack {
			return id, true
		}
	}
	return "", false
}

func (f *Fake) normalizeActions(actions []gen.NotificationAction, member string) ([]gen.NotificationAction, *writeError) {
	out := make([]gen.NotificationAction, 0, len(actions))
	seen := map[gen.NotificationActionType]bool{}
	for i, action := range actions {
		at := fmt.Sprintf("/%s/%d/%s", member, i, action.Type)
		if seen[action.Type] {
			return nil, &writeError{http.StatusBadRequest, domainInvalid("duplicate_integration", at)}
		}
		seen[action.Type] = true
		switch action.Type {
		case gen.NotificationActionTypeEmail:
			if action.Email == nil || len(action.Email.Recipients) == 0 {
				return nil, &writeError{http.StatusBadRequest, invalid(fmt.Sprintf("%s.%d.email.recipients", member, i), "too_small")}
			}
			if err := f.checkIntegration(action.Email.IntegrationID, gen.IntegrationTypeEmail, at+"/integrationId"); err != nil {
				return nil, err
			}
			out = append(out, gen.NotificationAction{Type: action.Type, Email: &gen.NotificationEmailAction{
				IntegrationID: action.Email.IntegrationID,
				Recipients:    normalizeEmails(action.Email.Recipients),
			}})
		case gen.NotificationActionTypeSlack:
			if action.Slack == nil || len(action.Slack.ChannelIds) == 0 {
				return nil, &writeError{http.StatusBadRequest, invalid(fmt.Sprintf("%s.%d.slack.channelIds", member, i), "too_small")}
			}
			if err := f.checkIntegration(action.Slack.IntegrationID, gen.IntegrationTypeSlack, at+"/integrationId"); err != nil {
				return nil, err
			}
			for _, channel := range action.Slack.ChannelIds {
				if strings.HasPrefix(channel, "#") {
					return nil, &writeError{http.StatusBadRequest, domainInvalid("channel_name_not_allowed", at+"/channelIds")}
				}
			}
			out = append(out, gen.NotificationAction{Type: action.Type, Slack: &gen.NotificationSlackAction{
				IntegrationID: action.Slack.IntegrationID,
				ChannelIds:    sortedUnique(action.Slack.ChannelIds),
			}})
		default:
			return nil, &writeError{http.StatusBadRequest, invalid(fmt.Sprintf("%s.%d.type", member, i), "invalid_enum_value")}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out, nil
}

func (f *Fake) checkIntegration(id string, want gen.IntegrationType, pointer string) *writeError {
	kind, ok := f.integrationTypeOf(id)
	if !ok {
		return &writeError{http.StatusUnprocessableEntity, notConnected(pointer)}
	}
	if kind != want {
		return &writeError{http.StatusBadRequest, domainInvalid("integration_type_mismatch", pointer)}
	}
	return nil
}

func normalizeEmails(values []openapi_types.Email) []openapi_types.Email {
	lowered := make([]string, 0, len(values))
	for _, value := range values {
		lowered = append(lowered, strings.ToLower(strings.TrimSpace(string(value))))
	}
	out := []openapi_types.Email{}
	for _, value := range sortedUnique(lowered) {
		out = append(out, openapi_types.Email(value))
	}
	return out
}

func sortedUnique(values []string) []string {
	out := slices.Clone(values)
	sort.Strings(out)
	return slices.Compact(out)
}

func eventTypeKnown(eventType string) (gen.NotificationEventTypeInfo, bool) {
	for _, info := range notificationEventTypes {
		if info.EventType == eventType {
			return info, true
		}
	}
	return gen.NotificationEventTypeInfo{}, false
}

func (f *Fake) normalizeRule(body gen.NotificationRuleWrite, previous *gen.NotificationRule) (gen.NotificationRule, *writeError) {
	if strings.TrimSpace(body.Name) == "" {
		return gen.NotificationRule{}, &writeError{http.StatusBadRequest, invalid("name", "too_small")}
	}
	if len(body.EventTypes) == 0 {
		return gen.NotificationRule{}, &writeError{http.StatusBadRequest, invalid("eventTypes", "too_small")}
	}
	rule := gen.NotificationRule{Name: body.Name, Enabled: true, Conditions: []gen.NotificationCondition{}, Actions: []gen.NotificationAction{}, RecipientIds: []string{}}
	if previous != nil {
		rule.Enabled, rule.Conditions, rule.Actions, rule.RecipientIds = previous.Enabled, previous.Conditions, previous.Actions, previous.RecipientIds
	}
	if body.Enabled != nil {
		rule.Enabled = *body.Enabled
	}
	for _, eventType := range body.EventTypes {
		if _, ok := eventTypeKnown(eventType); !ok {
			e := domainInvalid("event_type_not_available", "")
			(*e.Error.Details)["pointer"] = nil
			(*e.Error.Details)["eventType"] = eventType
			return gen.NotificationRule{}, &writeError{http.StatusBadRequest, e}
		}
	}
	rule.EventTypes = sortedUnique(body.EventTypes)
	if body.Conditions != nil {
		rule.Conditions = []gen.NotificationCondition{}
		for i, condition := range *body.Conditions {
			if !slices.Contains(rule.EventTypes, condition.EventType) {
				return gen.NotificationRule{}, &writeError{http.StatusBadRequest, domainInvalid("condition_event_type_not_in_rule", fmt.Sprintf("/conditions/%d/eventType", i))}
			}
			info, _ := eventTypeKnown(condition.EventType)
			fieldOK := false
			for _, field := range info.ConditionFields {
				if field.Field == condition.Field && field.Operator == condition.Operator {
					fieldOK = true
					for _, value := range condition.Values {
						if !slices.Contains(field.Values, value) {
							return gen.NotificationRule{}, &writeError{http.StatusBadRequest, domainInvalid("condition_value_unknown", fmt.Sprintf("/conditions/%d/values", i))}
						}
					}
				}
			}
			if !fieldOK {
				return gen.NotificationRule{}, &writeError{http.StatusBadRequest, domainInvalid("condition_field_unknown", fmt.Sprintf("/conditions/%d/field", i))}
			}
			rule.Conditions = append(rule.Conditions, gen.NotificationCondition{
				EventType: condition.EventType,
				Field:     condition.Field,
				Operator:  condition.Operator,
				Values:    sortedUnique(condition.Values),
			})
		}
	}
	if body.Actions != nil {
		actions, err := f.normalizeActions(*body.Actions, "actions")
		if err != nil {
			return gen.NotificationRule{}, err
		}
		rule.Actions = actions
	}
	if body.RecipientIds != nil {
		for i, id := range *body.RecipientIds {
			if _, ok := f.notifications.recipients[id]; !ok {
				return gen.NotificationRule{}, &writeError{http.StatusBadRequest, domainInvalid("unknown_recipient", fmt.Sprintf("/recipientIds/%d", i))}
			}
		}
		rule.RecipientIds = sortedUnique(*body.RecipientIds)
	}
	return rule, nil
}

func (f *Fake) commitRule(rule gen.NotificationRule, previous *gen.NotificationRule) *gen.NotificationRule {
	now := f.now().UTC()
	rule.LastModifiedVia = gen.NotificationChangeSourceAPI
	rule.UpdatedAt = now
	rule.MinClientRevision = currentClientRevision
	if previous == nil {
		rule.ID = randomUUID()
		rule.Revision = 1
		rule.CreatedVia = gen.NotificationChangeSourceAPI
		rule.CreatedAt = now
	} else {
		rule.ID = previous.ID
		rule.Revision = previous.Revision + 1
		rule.CreatedVia = previous.CreatedVia
		rule.CreatedAt = previous.CreatedAt
		if previous.MinClientRevision > rule.MinClientRevision {
			rule.MinClientRevision = previous.MinClientRevision
		}
	}
	webURL := "https://app.act.security/settings/notifications/rules/" + rule.ID
	rule.WebURL = &webURL
	stored := rule
	f.notifications.rules[rule.ID] = &stored
	return &stored
}

func (f *Fake) ruleIDsFor(recipientID string) []string {
	ids := []string{}
	for _, rule := range f.notifications.rules {
		if slices.Contains(rule.RecipientIds, recipientID) {
			ids = append(ids, rule.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func (f *Fake) recipientView(recipient *gen.NotificationRecipient) gen.NotificationRecipient {
	view := *recipient
	view.RuleIds = f.ruleIDsFor(recipient.ID)
	return view
}

func (s *apiServer) notificationsEnabled() bool {
	return !s.fake.cfg.NotificationRulesDisabled
}

func (s *apiServer) GetEmailIntegration(context.Context, gen.GetEmailIntegrationRequestObject) (gen.GetEmailIntegrationResponseObject, error) {
	store := s.fake.integrations
	store.mu.Lock()
	defer store.mu.Unlock()
	stored, ok := store.byID[EmailIntegrationID]
	if !ok {
		return gen.GetEmailIntegration404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	return gen.GetEmailIntegration200JSONResponse{Body: stored.item, Headers: gen.GetEmailIntegration200ResponseHeaders{ETag: stored.etag()}}, nil
}

func (s *apiServer) ListSlackChannels(_ context.Context, req gen.ListSlackChannelsRequestObject) (gen.ListSlackChannelsResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.ListSlackChannels403JSONResponse{Body: notificationsDisabled()}, nil
	}
	id, ok := s.fake.slackIntegrationID()
	if !ok || (req.Params.IntegrationID != nil && *req.Params.IntegrationID != id) {
		e := envelope(gen.ErrorEnvelopeErrorCodeIntegrationNotConnected, "Slack is not connected")
		details := map[string]any{"type": "slack"}
		e.Error.Details = &details
		return gen.ListSlackChannels422JSONResponse(e), nil
	}
	needle := strings.ToLower(strings.TrimPrefix(req.Params.Name, "#"))
	items := []gen.SlackChannel{}
	for _, channel := range slackChannels {
		if channel.ID == req.Params.Name || strings.ToLower(channel.Name) == needle {
			items = append(items, channel)
		}
	}
	return gen.ListSlackChannels200JSONResponse{Items: items}, nil
}

func (s *apiServer) ListNotificationEventTypes(context.Context, gen.ListNotificationEventTypesRequestObject) (gen.ListNotificationEventTypesResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.ListNotificationEventTypes403JSONResponse{Body: notificationsDisabled()}, nil
	}
	items := make([]gen.NotificationEventTypeInfo, 0, len(notificationEventTypes))
	for _, info := range notificationEventTypes {
		info.ActionTypes = []gen.NotificationActionType{gen.NotificationActionTypeEmail, gen.NotificationActionTypeSlack}
		if info.ConditionFields == nil {
			info.ConditionFields = []gen.NotificationConditionFieldInfo{}
		}
		items = append(items, info)
	}
	return gen.ListNotificationEventTypes200JSONResponse{Items: items, Limits: notificationLimits}, nil
}

func (s *apiServer) ListNotificationRules(context.Context, gen.ListNotificationRulesRequestObject) (gen.ListNotificationRulesResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.ListNotificationRules403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	items := []gen.NotificationRule{}
	for _, rule := range store.rules {
		items = append(items, *rule)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return gen.ListNotificationRules200JSONResponse{Items: items}, nil
}

func (s *apiServer) CreateNotificationRule(_ context.Context, req gen.CreateNotificationRuleRequestObject) (gen.CreateNotificationRuleResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.CreateNotificationRule403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	store.ruleCreateRequests++
	body := *req.Body
	fingerprint := fingerprintOf(body)
	if key := req.Params.IdempotencyKey; key != nil {
		if previous, ok := store.ruleKeys[*key]; ok {
			if previous.body != fingerprint {
				return gen.CreateNotificationRule422JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeIdempotencyMismatch, "Idempotency key reused")), nil
			}
			rule := store.rules[previous.id]
			return gen.CreateNotificationRule201JSONResponse{Body: *rule, Headers: gen.CreateNotificationRule201ResponseHeaders{ETag: revisionTag(rule.Revision)}}, nil
		}
	}
	rule, failure := s.fake.normalizeRule(body, nil)
	if failure != nil {
		if failure.status == http.StatusUnprocessableEntity {
			return gen.CreateNotificationRule422JSONResponse(failure.body), nil
		}
		return gen.CreateNotificationRule400JSONResponse(failure.body), nil
	}
	stored := s.fake.commitRule(rule, nil)
	if key := req.Params.IdempotencyKey; key != nil {
		store.ruleKeys[*key] = idempotentNotification{body: fingerprint, id: stored.ID}
	}
	if store.loseNextCreateReply {
		store.loseNextCreateReply = false
		return gen.CreateNotificationRule503JSONResponse{Body: envelope(gen.ErrorEnvelopeErrorCodeUnavailable, "The reply was lost")}, nil
	}
	return gen.CreateNotificationRule201JSONResponse{Body: *stored, Headers: gen.CreateNotificationRule201ResponseHeaders{ETag: revisionTag(stored.Revision)}}, nil
}

func (s *apiServer) ValidateNotificationRule(_ context.Context, req gen.ValidateNotificationRuleRequestObject) (gen.ValidateNotificationRuleResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.ValidateNotificationRule403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	body := *req.Body
	var previous *gen.NotificationRule
	if body.ID != nil {
		found, ok := store.rules[*body.ID]
		if !ok {
			return gen.ValidateNotificationRule404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
		}
		previous = found
	}
	_, failure := s.fake.normalizeRule(gen.NotificationRuleWrite{
		Name: body.Name, Enabled: body.Enabled, EventTypes: body.EventTypes,
		Conditions: body.Conditions, Actions: body.Actions, RecipientIds: body.RecipientIds,
	}, previous)
	if failure == nil {
		return gen.ValidateNotificationRule200JSONResponse{Valid: true}, nil
	}
	result := &gen.NotificationRuleValidationError{Code: string(failure.body.Error.Code)}
	if failure.body.Error.Details != nil {
		if reason, ok := (*failure.body.Error.Details)["reason"].(string); ok {
			result.Reason = &reason
		}
		if pointer, ok := (*failure.body.Error.Details)["pointer"].(string); ok {
			result.Pointer = &pointer
		}
	}
	return gen.ValidateNotificationRule200JSONResponse{Valid: false, Error: result}, nil
}

func (s *apiServer) GetNotificationRule(_ context.Context, req gen.GetNotificationRuleRequestObject) (gen.GetNotificationRuleResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.GetNotificationRule403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	rule, ok := store.rules[req.ID]
	if !ok {
		return gen.GetNotificationRule404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	return gen.GetNotificationRule200JSONResponse{Body: *rule, Headers: gen.GetNotificationRule200ResponseHeaders{ETag: revisionTag(rule.Revision)}}, nil
}

func (s *apiServer) ReplaceNotificationRule(_ context.Context, req gen.ReplaceNotificationRuleRequestObject) (gen.ReplaceNotificationRuleResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.ReplaceNotificationRule403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	previous, ok := store.rules[req.ID]
	if !ok {
		return gen.ReplaceNotificationRule404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if store.editBeforeReplace != "" {
		previous.Name = store.editBeforeReplace
		previous.Revision++
		previous.LastModifiedVia = gen.NotificationChangeSourceUI
		store.editBeforeReplace = ""
	}
	if !matchesRevision(req.Params.IfMatch, previous.Revision) {
		return gen.ReplaceNotificationRule412JSONResponse(preconditionFailed(previous.Revision)), nil
	}
	body := *req.Body
	store.replacedWithoutFields = omittedRuleFields(body)
	rule, failure := s.fake.normalizeRule(body, previous)
	if failure != nil {
		if failure.status == http.StatusUnprocessableEntity {
			return gen.ReplaceNotificationRule422JSONResponse(failure.body), nil
		}
		return gen.ReplaceNotificationRule400JSONResponse(failure.body), nil
	}
	stored := s.fake.commitRule(rule, previous)
	return gen.ReplaceNotificationRule200JSONResponse{Body: *stored, Headers: gen.ReplaceNotificationRule200ResponseHeaders{ETag: revisionTag(stored.Revision)}}, nil
}

func omittedRuleFields(body gen.NotificationRuleWrite) []string {
	omitted := []string{}
	if body.Enabled == nil {
		omitted = append(omitted, "enabled")
	}
	if body.Conditions == nil {
		omitted = append(omitted, "conditions")
	}
	if body.Actions == nil {
		omitted = append(omitted, "actions")
	}
	if body.RecipientIds == nil {
		omitted = append(omitted, "recipientIds")
	}
	return omitted
}

func (s *apiServer) DeleteNotificationRule(_ context.Context, req gen.DeleteNotificationRuleRequestObject) (gen.DeleteNotificationRuleResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.DeleteNotificationRule403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	rule, ok := store.rules[req.ID]
	if !ok {
		return gen.DeleteNotificationRule404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != nil && !matchesRevision(*req.Params.IfMatch, rule.Revision) {
		return gen.DeleteNotificationRule412JSONResponse(preconditionFailed(rule.Revision)), nil
	}
	delete(store.rules, req.ID)
	return gen.DeleteNotificationRule204Response{}, nil
}

func (s *apiServer) ListNotificationRuleActivity(_ context.Context, req gen.ListNotificationRuleActivityRequestObject) (gen.ListNotificationRuleActivityResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.ListNotificationRuleActivity403JSONResponse{Body: notificationsDisabled()}, nil
	}
	return gen.ListNotificationRuleActivity200JSONResponse{Items: []gen.NotificationRuleActivity{}}, nil
}

func (f *Fake) normalizeRecipient(body gen.NotificationRecipientWrite, selfID string) (gen.NotificationRecipient, *writeError) {
	if strings.TrimSpace(body.Name) == "" {
		return gen.NotificationRecipient{}, &writeError{http.StatusBadRequest, invalid("name", "too_small")}
	}
	if len(body.Methods) == 0 {
		return gen.NotificationRecipient{}, &writeError{http.StatusBadRequest, invalid("methods", "too_small")}
	}
	for id, other := range f.notifications.recipients {
		if id != selfID && strings.EqualFold(other.Name, body.Name) {
			e := envelope(gen.ErrorEnvelopeErrorCodeAlreadyExists, "The resource already exists")
			details := map[string]any{"attribute": "name"}
			e.Error.Details = &details
			return gen.NotificationRecipient{}, &writeError{http.StatusConflict, e}
		}
	}
	methods, failure := f.normalizeActions(body.Methods, "methods")
	if failure != nil {
		return gen.NotificationRecipient{}, failure
	}
	return gen.NotificationRecipient{Name: body.Name, Methods: methods}, nil
}

func (f *Fake) commitRecipient(recipient gen.NotificationRecipient, previous *gen.NotificationRecipient) *gen.NotificationRecipient {
	now := f.now().UTC()
	recipient.LastModifiedVia = gen.NotificationChangeSourceAPI
	recipient.UpdatedAt = now
	if previous == nil {
		recipient.ID = randomUUID()
		recipient.Revision = 1
		recipient.CreatedVia = gen.NotificationChangeSourceAPI
		recipient.CreatedAt = now
	} else {
		recipient.ID = previous.ID
		recipient.Revision = previous.Revision + 1
		recipient.CreatedVia = previous.CreatedVia
		recipient.CreatedAt = previous.CreatedAt
	}
	stored := recipient
	f.notifications.recipients[recipient.ID] = &stored
	return &stored
}

func (s *apiServer) ListNotificationRecipients(context.Context, gen.ListNotificationRecipientsRequestObject) (gen.ListNotificationRecipientsResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.ListNotificationRecipients403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	items := []gen.NotificationRecipient{}
	for _, recipient := range store.recipients {
		items = append(items, s.fake.recipientView(recipient))
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	return gen.ListNotificationRecipients200JSONResponse{Items: items}, nil
}

func (s *apiServer) CreateNotificationRecipient(_ context.Context, req gen.CreateNotificationRecipientRequestObject) (gen.CreateNotificationRecipientResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.CreateNotificationRecipient403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	body := *req.Body
	fingerprint := fingerprintOf(body)
	if key := req.Params.IdempotencyKey; key != nil {
		if previous, ok := store.recipientKeys[*key]; ok {
			if previous.body != fingerprint {
				return gen.CreateNotificationRecipient422JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeIdempotencyMismatch, "Idempotency key reused")), nil
			}
			view := s.fake.recipientView(store.recipients[previous.id])
			return gen.CreateNotificationRecipient201JSONResponse{Body: view, Headers: gen.CreateNotificationRecipient201ResponseHeaders{ETag: revisionTag(view.Revision)}}, nil
		}
	}
	recipient, failure := s.fake.normalizeRecipient(body, "")
	if failure != nil {
		switch failure.status {
		case http.StatusConflict:
			return gen.CreateNotificationRecipient409JSONResponse(failure.body), nil
		case http.StatusUnprocessableEntity:
			return gen.CreateNotificationRecipient422JSONResponse(failure.body), nil
		default:
			return gen.CreateNotificationRecipient400JSONResponse(failure.body), nil
		}
	}
	stored := s.fake.commitRecipient(recipient, nil)
	if key := req.Params.IdempotencyKey; key != nil {
		store.recipientKeys[*key] = idempotentNotification{body: fingerprint, id: stored.ID}
	}
	view := s.fake.recipientView(stored)
	return gen.CreateNotificationRecipient201JSONResponse{Body: view, Headers: gen.CreateNotificationRecipient201ResponseHeaders{ETag: revisionTag(view.Revision)}}, nil
}

func (s *apiServer) GetNotificationRecipient(_ context.Context, req gen.GetNotificationRecipientRequestObject) (gen.GetNotificationRecipientResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.GetNotificationRecipient403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	recipient, ok := store.recipients[req.ID]
	if !ok {
		return gen.GetNotificationRecipient404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	view := s.fake.recipientView(recipient)
	return gen.GetNotificationRecipient200JSONResponse{Body: view, Headers: gen.GetNotificationRecipient200ResponseHeaders{ETag: revisionTag(view.Revision)}}, nil
}

func (s *apiServer) ReplaceNotificationRecipient(_ context.Context, req gen.ReplaceNotificationRecipientRequestObject) (gen.ReplaceNotificationRecipientResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.ReplaceNotificationRecipient403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	previous, ok := store.recipients[req.ID]
	if !ok {
		return gen.ReplaceNotificationRecipient404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if !matchesRevision(req.Params.IfMatch, previous.Revision) {
		return gen.ReplaceNotificationRecipient412JSONResponse(preconditionFailed(previous.Revision)), nil
	}
	recipient, failure := s.fake.normalizeRecipient(*req.Body, req.ID)
	if failure != nil {
		switch failure.status {
		case http.StatusConflict:
			return gen.ReplaceNotificationRecipient409JSONResponse(failure.body), nil
		case http.StatusUnprocessableEntity:
			return gen.ReplaceNotificationRecipient422JSONResponse(failure.body), nil
		default:
			return gen.ReplaceNotificationRecipient400JSONResponse(failure.body), nil
		}
	}
	view := s.fake.recipientView(s.fake.commitRecipient(recipient, previous))
	return gen.ReplaceNotificationRecipient200JSONResponse{Body: view, Headers: gen.ReplaceNotificationRecipient200ResponseHeaders{ETag: revisionTag(view.Revision)}}, nil
}

func (s *apiServer) DeleteNotificationRecipient(_ context.Context, req gen.DeleteNotificationRecipientRequestObject) (gen.DeleteNotificationRecipientResponseObject, error) {
	if !s.notificationsEnabled() {
		return gen.DeleteNotificationRecipient403JSONResponse{Body: notificationsDisabled()}, nil
	}
	store := s.fake.notifications
	store.mu.Lock()
	defer store.mu.Unlock()
	recipient, ok := store.recipients[req.ID]
	if !ok {
		return gen.DeleteNotificationRecipient404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	if req.Params.IfMatch != nil && !matchesRevision(*req.Params.IfMatch, recipient.Revision) {
		return gen.DeleteNotificationRecipient412JSONResponse(preconditionFailed(recipient.Revision)), nil
	}
	if ruleIDs := s.fake.ruleIDsFor(req.ID); len(ruleIDs) > 0 {
		e := envelope(gen.ErrorEnvelopeErrorCodeConflict, "The recipient is used by notification rules")
		details := map[string]any{"reason": "notification_recipient_in_use", "ruleIds": ruleIDs}
		e.Error.Details = &details
		return gen.DeleteNotificationRecipient409JSONResponse(e), nil
	}
	delete(store.recipients, req.ID)
	return gen.DeleteNotificationRecipient204Response{}, nil
}

func (f *Fake) NotificationRule(id string) (gen.NotificationRule, bool) {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	rule, ok := f.notifications.rules[id]
	if !ok {
		return gen.NotificationRule{}, false
	}
	return *rule, true
}

func (f *Fake) NotificationRuleCount() int {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	return len(f.notifications.rules)
}

func (f *Fake) NotificationRuleCreateRequests() int {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	return f.notifications.ruleCreateRequests
}

func (f *Fake) LastRuleReplaceOmitted() []string {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	return slices.Clone(f.notifications.replacedWithoutFields)
}

func (f *Fake) LoseNextNotificationRuleCreateReply() {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	f.notifications.loseNextCreateReply = true
}

func (f *Fake) RenameNotificationRuleOutOfBand(id, name string) bool {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	rule, ok := f.notifications.rules[id]
	if !ok {
		return false
	}
	rule.Name = name
	rule.Revision++
	rule.LastModifiedVia = gen.NotificationChangeSourceUI
	return true
}

func (f *Fake) SetNotificationRuleMinClientRevision(id string, revision int) bool {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	rule, ok := f.notifications.rules[id]
	if !ok {
		return false
	}
	rule.MinClientRevision = revision
	return true
}

func (f *Fake) DeleteNotificationRuleOutOfBand(id string) {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	delete(f.notifications.rules, id)
}

func (f *Fake) EditNotificationRuleBeforeNextReplace(name string) {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	f.notifications.editBeforeReplace = name
}

func (f *Fake) SeedNotificationRule(name string, recipientIDs ...string) string {
	f.notifications.mu.Lock()
	defer f.notifications.mu.Unlock()
	rule := gen.NotificationRule{
		Name:         name,
		Enabled:      true,
		EventTypes:   []string{"connector.unhealthy"},
		Conditions:   []gen.NotificationCondition{},
		Actions:      []gen.NotificationAction{},
		RecipientIds: sortedUnique(recipientIDs),
	}
	stored := f.commitRule(rule, nil)
	stored.CreatedVia = gen.NotificationChangeSourceUI
	stored.LastModifiedVia = gen.NotificationChangeSourceUI
	return stored.ID
}

func fingerprintOf(body any) string {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Sprintf("%v", body)
	}
	return string(raw)
}
