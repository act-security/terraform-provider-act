package fakeapi

import (
	"context"

	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
)

func (s *apiServer) ListNotificationEventTypes(context.Context, gen.ListNotificationEventTypesRequestObject) (gen.ListNotificationEventTypesResponseObject, error) {
	return gen.ListNotificationEventTypes403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) ListNotificationRecipients(context.Context, gen.ListNotificationRecipientsRequestObject) (gen.ListNotificationRecipientsResponseObject, error) {
	return gen.ListNotificationRecipients403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) CreateNotificationRecipient(context.Context, gen.CreateNotificationRecipientRequestObject) (gen.CreateNotificationRecipientResponseObject, error) {
	return gen.CreateNotificationRecipient403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) DeleteNotificationRecipient(context.Context, gen.DeleteNotificationRecipientRequestObject) (gen.DeleteNotificationRecipientResponseObject, error) {
	return gen.DeleteNotificationRecipient403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) GetNotificationRecipient(context.Context, gen.GetNotificationRecipientRequestObject) (gen.GetNotificationRecipientResponseObject, error) {
	return gen.GetNotificationRecipient403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) ReplaceNotificationRecipient(context.Context, gen.ReplaceNotificationRecipientRequestObject) (gen.ReplaceNotificationRecipientResponseObject, error) {
	return gen.ReplaceNotificationRecipient403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) ListNotificationRules(context.Context, gen.ListNotificationRulesRequestObject) (gen.ListNotificationRulesResponseObject, error) {
	return gen.ListNotificationRules403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) CreateNotificationRule(context.Context, gen.CreateNotificationRuleRequestObject) (gen.CreateNotificationRuleResponseObject, error) {
	return gen.CreateNotificationRule403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) ValidateNotificationRule(context.Context, gen.ValidateNotificationRuleRequestObject) (gen.ValidateNotificationRuleResponseObject, error) {
	return gen.ValidateNotificationRule403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) DeleteNotificationRule(context.Context, gen.DeleteNotificationRuleRequestObject) (gen.DeleteNotificationRuleResponseObject, error) {
	return gen.DeleteNotificationRule403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) GetNotificationRule(context.Context, gen.GetNotificationRuleRequestObject) (gen.GetNotificationRuleResponseObject, error) {
	return gen.GetNotificationRule403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) ReplaceNotificationRule(context.Context, gen.ReplaceNotificationRuleRequestObject) (gen.ReplaceNotificationRuleResponseObject, error) {
	return gen.ReplaceNotificationRule403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) ListNotificationRuleActivity(context.Context, gen.ListNotificationRuleActivityRequestObject) (gen.ListNotificationRuleActivityResponseObject, error) {
	return gen.ListNotificationRuleActivity403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) ListSlackChannels(context.Context, gen.ListSlackChannelsRequestObject) (gen.ListSlackChannelsResponseObject, error) {
	return gen.ListSlackChannels403JSONResponse{Body: featureDisabled()}, nil
}
