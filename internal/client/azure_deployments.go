package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

func (c *Client) GetAzureOnboarding(ctx context.Context, params apigen.GetAzureOnboardingParams) (*apigen.AzureOnboarding, error) {
	resp, err := c.api.GetAzureOnboardingWithResponse(ctx, &params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200, nil
}

func (c *Client) GetAzureDeployment(ctx context.Context, id string) (*AzureDeploymentResult, error) {
	resp, err := c.api.GetAzureDeploymentWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() == http.StatusNotFound {
		return nil, nil
	}
	return deploymentResult(resp.JSON200, resp.HTTPResponse, resp.Body)
}

func (c *Client) CreateAzureDeployment(ctx context.Context, req DeploymentCreateRequest[apigen.AzureDeploymentCreate]) (*AzureDeploymentResult, error) {
	resp, err := c.api.CreateAzureDeploymentWithResponse(ctx, &apigen.CreateAzureDeploymentParams{IdempotencyKey: req.IdempotencyKey}, req.Body)
	if err != nil {
		return nil, err
	}
	return deploymentResult(resp.JSON201, resp.HTTPResponse, resp.Body)
}

func (c *Client) UpdateAzureDeployment(ctx context.Context, req DeploymentUpdateRequest) (*AzureDeploymentResult, error) {
	body, err := json.Marshal(req.Patch)
	if err != nil {
		return nil, err
	}
	resp, err := c.api.UpdateAzureDeploymentWithBodyWithResponse(ctx, req.ID, &apigen.UpdateAzureDeploymentParams{IfMatch: req.ETag}, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return deploymentResult(resp.JSON200, resp.HTTPResponse, resp.Body)
}

func (c *Client) VerifyAzureDeployment(ctx context.Context, ref DeploymentRef) (*AzureDeploymentResult, error) {
	resp, err := c.api.VerifyAzureDeploymentWithResponse(ctx, ref.ID, &apigen.VerifyAzureDeploymentParams{IfMatch: ref.ETag})
	if err != nil {
		return nil, err
	}
	return deploymentResult(resp.JSON200, resp.HTTPResponse, resp.Body)
}

func (c *Client) DeleteAzureDeployment(ctx context.Context, ref DeploymentRef) ([]apigen.CleanupItem, error) {
	params := &apigen.DeleteAzureDeploymentParams{}
	if ref.ETag != "" {
		params.IfMatch = &ref.ETag
	}
	resp, err := c.api.DeleteAzureDeploymentWithResponse(ctx, ref.ID, params)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.JSON200 != nil:
		return resp.JSON200.CleanupRequired, nil
	case resp.StatusCode() == http.StatusNoContent, resp.StatusCode() == http.StatusNotFound:
		return nil, nil
	default:
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
}
