package client

import (
	"context"
	"net/http"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

type NotificationRuleResult struct {
	Rule apigen.NotificationRule
	ETag string
}

type NotificationRecipientResult struct {
	Recipient apigen.NotificationRecipient
	ETag      string
}

func (c *Client) ListNotificationEventTypes(ctx context.Context) (*apigen.NotificationEventTypeList, error) {
	resp, err := c.api.ListNotificationEventTypesWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200, nil
}

func (c *Client) GetEmailIntegration(ctx context.Context) (*apigen.Integration, error) {
	resp, err := c.api.GetEmailIntegrationWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() == http.StatusNotFound {
		return nil, nil
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200, nil
}

func (c *Client) FindSlackChannels(ctx context.Context, name string, integrationID *string) ([]apigen.SlackChannel, error) {
	resp, err := c.api.ListSlackChannelsWithResponse(ctx, &apigen.ListSlackChannelsParams{Name: name, IntegrationID: integrationID})
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200.Items, nil
}

func (c *Client) GetNotificationRule(ctx context.Context, id string) (*NotificationRuleResult, error) {
	resp, err := c.api.GetNotificationRuleWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() == http.StatusNotFound {
		return nil, nil
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &NotificationRuleResult{Rule: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) CreateNotificationRule(ctx context.Context, body apigen.NotificationRuleWrite, idempotencyKey string) (*NotificationRuleResult, error) {
	resp, err := c.api.CreateNotificationRuleWithResponse(ctx, &apigen.CreateNotificationRuleParams{IdempotencyKey: &idempotencyKey}, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &NotificationRuleResult{Rule: *resp.JSON201, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) ReplaceNotificationRule(ctx context.Context, id, etag string, body apigen.NotificationRuleWrite) (*NotificationRuleResult, error) {
	resp, err := c.api.ReplaceNotificationRuleWithResponse(ctx, id, &apigen.ReplaceNotificationRuleParams{IfMatch: etag}, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &NotificationRuleResult{Rule: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) DeleteNotificationRule(ctx context.Context, id, etag string) error {
	resp, err := c.api.DeleteNotificationRuleWithResponse(ctx, id, &apigen.DeleteNotificationRuleParams{IfMatch: optional(etag)})
	if err != nil {
		return err
	}
	switch resp.StatusCode() {
	case http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return newAPIError(resp.StatusCode(), resp.Body)
	}
}

func (c *Client) GetNotificationRecipient(ctx context.Context, id string) (*NotificationRecipientResult, error) {
	resp, err := c.api.GetNotificationRecipientWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() == http.StatusNotFound {
		return nil, nil
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &NotificationRecipientResult{Recipient: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) CreateNotificationRecipient(ctx context.Context, body apigen.NotificationRecipientWrite, idempotencyKey string) (*NotificationRecipientResult, error) {
	resp, err := c.api.CreateNotificationRecipientWithResponse(ctx, &apigen.CreateNotificationRecipientParams{IdempotencyKey: &idempotencyKey}, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &NotificationRecipientResult{Recipient: *resp.JSON201, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) ReplaceNotificationRecipient(ctx context.Context, id, etag string, body apigen.NotificationRecipientWrite) (*NotificationRecipientResult, error) {
	resp, err := c.api.ReplaceNotificationRecipientWithResponse(ctx, id, &apigen.ReplaceNotificationRecipientParams{IfMatch: etag}, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &NotificationRecipientResult{Recipient: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) DeleteNotificationRecipient(ctx context.Context, id, etag string) error {
	resp, err := c.api.DeleteNotificationRecipientWithResponse(ctx, id, &apigen.DeleteNotificationRecipientParams{IfMatch: optional(etag)})
	if err != nil {
		return err
	}
	switch resp.StatusCode() {
	case http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		return newAPIError(resp.StatusCode(), resp.Body)
	}
}

func optional(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
