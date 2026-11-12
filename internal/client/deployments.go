package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

type AwsDeploymentResult struct {
	Deployment apigen.AwsDeployment
	ETag       string
}

type AwsDeploymentPatch map[string]any

type DeploymentFilter struct {
	Cloud  *apigen.Cloud
	Status *apigen.DeploymentStatus
	Target *string
	Tags   map[string]string
}

func (c *Client) GetAwsOnboarding(ctx context.Context, params apigen.GetAwsOnboardingParams) (*apigen.AwsOnboarding, error) {
	resp, err := c.api.GetAwsOnboardingWithResponse(ctx, &params)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200, nil
}

func (c *Client) ListDeployments(ctx context.Context, filter DeploymentFilter) ([]apigen.DeploymentSummary, error) {
	items := []apigen.DeploymentSummary{}
	params := &apigen.ListDeploymentsParams{Cloud: filter.Cloud, Status: filter.Status, Target: filter.Target}
	if len(filter.Tags) > 0 {
		params.Tag = &filter.Tags
	}
	for {
		resp, err := c.api.ListDeploymentsWithResponse(ctx, params)
		if err != nil {
			return nil, err
		}
		if resp.JSON200 == nil {
			return nil, newAPIError(resp.StatusCode(), resp.Body)
		}
		items = append(items, resp.JSON200.Items...)
		if resp.JSON200.NextPageToken == nil || *resp.JSON200.NextPageToken == "" {
			return items, nil
		}
		params.PageToken = resp.JSON200.NextPageToken
	}
}

func (c *Client) GetAwsDeployment(ctx context.Context, id string) (*AwsDeploymentResult, error) {
	resp, err := c.api.GetAwsDeploymentWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() == http.StatusNotFound {
		return nil, nil
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &AwsDeploymentResult{Deployment: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) CreateAwsDeployment(ctx context.Context, body apigen.AwsDeploymentCreate, idempotencyKey string) (*AwsDeploymentResult, error) {
	resp, err := c.api.CreateAwsDeploymentWithResponse(ctx, &apigen.CreateAwsDeploymentParams{IdempotencyKey: idempotencyKey}, body)
	if err != nil {
		return nil, err
	}
	if resp.JSON201 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &AwsDeploymentResult{Deployment: *resp.JSON201, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) UpdateAwsDeployment(ctx context.Context, id, etag string, patch AwsDeploymentPatch) (*AwsDeploymentResult, error) {
	body, err := json.Marshal(patch)
	if err != nil {
		return nil, err
	}
	resp, err := c.api.UpdateAwsDeploymentWithBodyWithResponse(ctx, id, &apigen.UpdateAwsDeploymentParams{IfMatch: etag}, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &AwsDeploymentResult{Deployment: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) VerifyAwsDeployment(ctx context.Context, id, etag string) (*AwsDeploymentResult, error) {
	resp, err := c.api.VerifyAwsDeploymentWithResponse(ctx, id, &apigen.VerifyAwsDeploymentParams{IfMatch: etag})
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &AwsDeploymentResult{Deployment: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) RotateAwsExternalID(ctx context.Context, id, etag string) (*AwsDeploymentResult, error) {
	resp, err := c.api.RotateAwsExternalIDWithResponse(ctx, id, &apigen.RotateAwsExternalIDParams{IfMatch: etag})
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return &AwsDeploymentResult{Deployment: *resp.JSON200, ETag: resp.HTTPResponse.Header.Get("ETag")}, nil
}

func (c *Client) DeleteAwsDeployment(ctx context.Context, id string) ([]apigen.CleanupItem, error) {
	resp, err := c.api.DeleteAwsDeploymentWithResponse(ctx, id, &apigen.DeleteAwsDeploymentParams{})
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

func (c *Client) GetDeploymentCoverage(ctx context.Context, id string) (*apigen.DeploymentCoverage, error) {
	resp, err := c.api.GetDeploymentCoverageWithResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, newAPIError(resp.StatusCode(), resp.Body)
	}
	return resp.JSON200, nil
}

func (c *Client) ListDeploymentAccounts(ctx context.Context, id string, status *apigen.MemberAccountStatus) ([]apigen.MemberAccount, error) {
	items := []apigen.MemberAccount{}
	params := &apigen.ListDeploymentAccountsParams{Status: status}
	for {
		resp, err := c.api.ListDeploymentAccountsWithResponse(ctx, id, params)
		if err != nil {
			return nil, err
		}
		if resp.JSON200 == nil {
			return nil, newAPIError(resp.StatusCode(), resp.Body)
		}
		items = append(items, resp.JSON200.Items...)
		if resp.JSON200.NextPageToken == nil || *resp.JSON200.NextPageToken == "" {
			return items, nil
		}
		params.PageToken = resp.JSON200.NextPageToken
	}
}
