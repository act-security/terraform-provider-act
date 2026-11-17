package client

import (
	"context"
	"net/http"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

type AzureLogSourcePutRequest struct {
	DeploymentID string
	Body         apigen.AzureLogSourcePut
}

func (c *Client) GetAzureLogSource(ctx context.Context, deploymentID string) (*apigen.AzureLogSource, error) {
	resp, err := c.api.GetAzureLogSourceWithResponse(ctx, deploymentID)
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

func (c *Client) PutAzureLogSource(ctx context.Context, req AzureLogSourcePutRequest) (*apigen.AzureLogSource, error) {
	resp, err := c.api.PutAzureLogSourceWithResponse(ctx, req.DeploymentID, req.Body)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200, nil
}

func (c *Client) DeleteAzureLogSource(ctx context.Context, deploymentID string) ([]apigen.CleanupItem, error) {
	resp, err := c.api.DeleteAzureLogSourceWithResponse(ctx, deploymentID)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.JSON200 != nil:
		return resp.JSON200.CleanupRequired, nil
	case resp.StatusCode() == http.StatusNotFound:
		return nil, nil
	default:
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
}
