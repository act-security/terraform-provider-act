package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/go-cleanhttp"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/retry"
)

const requestTimeout = 30 * time.Second

type TokenSource interface {
	AccessToken(ctx context.Context) (string, error)
	RefreshAccessToken(ctx context.Context) (string, error)
}

type Client struct {
	api *apigen.ClientWithResponses
}

func NewHTTPClient() *http.Client {
	c := cleanhttp.DefaultPooledClient()
	c.Timeout = requestTimeout
	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

func New(baseURL string, tokens TokenSource, httpClient *http.Client, userAgent string, policy retry.Policy) (*Client, error) {
	api, err := apigen.NewClientWithResponses(baseURL,
		apigen.WithHTTPClient(&doer{http: httpClient, tokens: tokens, policy: policy}),
		apigen.WithRequestEditorFn(func(ctx context.Context, req *http.Request) error {
			token, err := tokens.AccessToken(ctx)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("User-Agent", userAgent)
			return nil
		}),
	)
	if err != nil {
		return nil, err
	}
	return &Client{api: api}, nil
}

func (c *Client) Whoami(ctx context.Context) (*apigen.Whoami, error) {
	resp, err := c.api.GetWhoamiWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 != nil {
		return resp.JSON200, nil
	}
	return nil, newAPIError(resp.StatusCode(), resp.Body)
}

type doer struct {
	http   *http.Client
	tokens TokenSource
	policy retry.Policy
}

func (d *doer) Do(req *http.Request) (*http.Response, error) {
	resp, err := retry.Do(d.http, req, d.policy)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return resp, nil
	}
	if _, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)); err != nil {
		return nil, err
	}
	if err = resp.Body.Close(); err != nil {
		return nil, err
	}
	token, err := d.tokens.RefreshAccessToken(req.Context())
	if err != nil {
		return nil, fmt.Errorf("the Act API rejected the token and getting a new one failed: %w", err)
	}
	again := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		again.Body, err = req.GetBody()
		if err != nil {
			return nil, err
		}
	}
	again.Header.Set("Authorization", "Bearer "+token)
	return retry.Do(d.http, again, d.policy)
}
