package client

import (
	"context"
	"errors"
	"net/http"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

type IntegrationResult struct {
	Integration apigen.Integration
	ETag        string
}

func IsStatus(err error, status int) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Status == status
}

func (c *Client) ListIntegrationTypes(ctx context.Context) ([]apigen.IntegrationTypeInfo, error) {
	resp, err := c.api.ListIntegrationTypesWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200.Items, nil
}

func (c *Client) ListIntegrations(ctx context.Context, kind *apigen.IntegrationType) ([]apigen.Integration, error) {
	items := []apigen.Integration{}
	params := &apigen.ListIntegrationsParams{Type: kind}
	for {
		resp, err := c.api.ListIntegrationsWithResponse(ctx, params)
		if err != nil {
			return nil, err
		}
		if resp.JSON200 == nil {
			return nil, newAPIError(resp.StatusCode(), resp.Body)
		}
		items = append(items, resp.JSON200.Items...)
		if resp.JSON200.NextPageToken == nil {
			return items, nil
		}
		params.PageToken = resp.JSON200.NextPageToken
	}
}

func (c *Client) GetIntegration(ctx context.Context, id string) (*IntegrationResult, error) {
	resp, err := c.api.GetIntegrationWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() == http.StatusNotFound {
		return nil, nil
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &IntegrationResult{Integration: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) CreateIntegration(ctx context.Context, body apigen.IntegrationCreate, idempotencyKey string) (*IntegrationResult, error) {
	resp, err := c.api.CreateIntegrationWithResponse(ctx, &apigen.CreateIntegrationParams{IdempotencyKey: &idempotencyKey}, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &IntegrationResult{Integration: *resp.JSON201, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) UpdateIntegration(ctx context.Context, id, etag string, patch apigen.IntegrationPatch) (*IntegrationResult, error) {
	resp, err := c.api.UpdateIntegrationWithResponse(ctx, id, &apigen.UpdateIntegrationParams{IfMatch: etag}, patch)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &IntegrationResult{Integration: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) DeleteIntegration(ctx context.Context, id string) error {
	resp, err := c.api.DeleteIntegrationWithResponse(ctx, id, &apigen.DeleteIntegrationParams{})
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
