package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

type DeploymentResult[T any] struct {
	Deployment T
	ETag       string
}

type (
	AwsDeploymentResult   = DeploymentResult[apigen.AwsDeployment]
	AzureDeploymentResult = DeploymentResult[apigen.AzureDeployment]
)

type DeploymentPatch map[string]any

type DeploymentCreateRequest[B any] struct {
	Body           B
	IdempotencyKey string
}

type DeploymentRef struct {
	ID   string
	ETag string
}

type DeploymentUpdateRequest struct {
	DeploymentRef
	Patch DeploymentPatch
}

type DeploymentAccountsQuery struct {
	DeploymentID string
	Status       *apigen.MemberAccountStatus
}

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
	return deploymentResult(resp.JSON200, resp.HTTPResponse, resp.Body)
}

func (c *Client) CreateAwsDeployment(ctx context.Context, req DeploymentCreateRequest[apigen.AwsDeploymentCreate]) (*AwsDeploymentResult, error) {
	resp, err := c.api.CreateAwsDeploymentWithResponse(ctx, &apigen.CreateAwsDeploymentParams{IdempotencyKey: req.IdempotencyKey}, req.Body)
	if err != nil {
		return nil, err
	}
	return deploymentResult(resp.JSON201, resp.HTTPResponse, resp.Body)
}

func (c *Client) UpdateAwsDeployment(ctx context.Context, req DeploymentUpdateRequest) (*AwsDeploymentResult, error) {
	body, err := json.Marshal(req.Patch)
	if err != nil {
		return nil, err
	}
	resp, err := c.api.UpdateAwsDeploymentWithBodyWithResponse(ctx, req.ID, &apigen.UpdateAwsDeploymentParams{IfMatch: req.ETag}, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	return deploymentResult(resp.JSON200, resp.HTTPResponse, resp.Body)
}

func (c *Client) VerifyAwsDeployment(ctx context.Context, ref DeploymentRef) (*AwsDeploymentResult, error) {
	resp, err := c.api.VerifyAwsDeploymentWithResponse(ctx, ref.ID, &apigen.VerifyAwsDeploymentParams{IfMatch: ref.ETag})
	if err != nil {
		return nil, err
	}
	return deploymentResult(resp.JSON200, resp.HTTPResponse, resp.Body)
}

func (c *Client) RotateAwsExternalID(ctx context.Context, ref DeploymentRef) (*AwsDeploymentResult, error) {
	resp, err := c.api.RotateAwsExternalIDWithResponse(ctx, ref.ID, &apigen.RotateAwsExternalIDParams{IfMatch: ref.ETag})
	if err != nil {
		return nil, err
	}
	return deploymentResult(resp.JSON200, resp.HTTPResponse, resp.Body)
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

func (c *Client) ListDeploymentAccounts(ctx context.Context, query DeploymentAccountsQuery) ([]apigen.MemberAccount, error) {
	items := []apigen.MemberAccount{}
	params := &apigen.ListDeploymentAccountsParams{Status: query.Status}
	for {
		resp, err := c.api.ListDeploymentAccountsWithResponse(ctx, query.DeploymentID, params)
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

func deploymentResult[T any](body *T, httpResp *http.Response, raw []byte) (*DeploymentResult[T], error) {
	if body == nil {
		return nil, newAPIError(httpResp.StatusCode, raw)
	}
	return &DeploymentResult[T]{Deployment: *body, ETag: httpResp.Header.Get("ETag")}, nil
}
