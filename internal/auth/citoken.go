package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/act-security/terraform-provider-act/internal/retry"
)

const FederatedAssertionType = "urn:act:params:oauth:client-assertion-type:federated-identity-jwt"

var ErrFederationRefused = errors.New("the Act STS refused the CI token for this client_id: check that a trust policy of the service account matches this job and that the token audience is the Act STS origin")

type CITokenSource interface {
	Describe() string
	Token(ctx context.Context, audience string) (string, error)
}

func StaticCIToken(value string) CITokenSource {
	return staticCIToken{value: value, name: "oidc_token"}
}

func EnvCIToken(name string, getenv func(string) string) CITokenSource {
	return envCIToken{name: name, getenv: getenv}
}

func FileCIToken(path string) CITokenSource {
	return fileCIToken{path: path}
}

func GitHubActionsCIToken(requestURL, requestToken string, httpClient *http.Client, policy retry.Policy) CITokenSource {
	return gitHubActionsCIToken{requestURL: requestURL, requestToken: requestToken, httpClient: httpClient, retry: policy}
}

type staticCIToken struct {
	value string
	name  string
}

func (s staticCIToken) Describe() string { return s.name }

func (s staticCIToken) Token(context.Context, string) (string, error) {
	return strings.TrimSpace(s.value), nil
}

type envCIToken struct {
	name   string
	getenv func(string) string
}

func (e envCIToken) Describe() string { return e.name }

func (e envCIToken) Token(context.Context, string) (string, error) {
	value := strings.TrimSpace(e.getenv(e.name))
	if value == "" {
		return "", fmt.Errorf("%s is empty", e.name)
	}
	return value, nil
}

type fileCIToken struct {
	path string
}

func (f fileCIToken) Describe() string { return "oidc_token_file_path" }

func (f fileCIToken) Token(context.Context, string) (string, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return "", fmt.Errorf("reading the OIDC token file: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

type gitHubActionsCIToken struct {
	requestURL   string
	requestToken string
	httpClient   *http.Client
	retry        retry.Policy
}

func (g gitHubActionsCIToken) Describe() string { return "GitHub Actions OIDC" }

func (g gitHubActionsCIToken) Token(ctx context.Context, audience string) (string, error) {
	requestURL, err := withAudience(g.requestURL, audience)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("building the GitHub Actions OIDC request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.requestToken)
	req.Header.Set("Accept", "application/json")
	resp, err := retry.Do(g.httpClient, req, g.retry)
	if err != nil {
		return "", fmt.Errorf("requesting the GitHub Actions OIDC token: %w", err)
	}
	return decodeGitHubActionsToken(resp)
}

func withAudience(requestURL, audience string) (string, error) {
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL is not a URL: %w", err)
	}
	query := u.Query()
	query.Set("audience", audience)
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func decodeGitHubActionsToken(resp *http.Response) (string, error) {
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return "", fmt.Errorf("reading the GitHub Actions OIDC response: %w", readErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("closing the GitHub Actions OIDC response: %w", closeErr)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub Actions answered %d to the OIDC token request; does the job have permissions id-token: write?", resp.StatusCode)
	}
	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.Value == "" {
		return "", errors.New("GitHub Actions returned no OIDC token")
	}
	return payload.Value, nil
}

func checkCITokenAudience(raw, want string) error {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return errors.New("the CI token is not a JWT")
	}
	var claims struct {
		Audience audience `json:"aud"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return fmt.Errorf("the CI token claims: %w", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != want {
		return fmt.Errorf("the CI token audience is %v, not %q; request it for the Act STS origin so it cannot be replayed elsewhere", []string(claims.Audience), want)
	}
	return nil
}
