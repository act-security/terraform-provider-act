package provider

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/act-security/terraform-provider-act/internal/auth"
	"github.com/act-security/terraform-provider-act/internal/retry"
)

var (
	errBothCredentials = errors.New("set either client_secret (ACT_CLIENT_SECRET) or an OIDC token, not both: a CI job that federates must not hold the client secret")
	errNoCredentials   = errors.New("set client_secret in the provider block or ACT_CLIENT_SECRET, or authenticate with an OIDC token: oidc_token, oidc_token_file_path or use_oidc")
	errBothOIDCInputs  = errors.New("set either oidc_token (ACT_OIDC_TOKEN) or oidc_token_file_path (ACT_OIDC_TOKEN_FILE_PATH), not both")
	errNoCIToken       = errors.New("use_oidc is set but this job has no OIDC token: in HCP Terraform set TFC_WORKLOAD_IDENTITY_AUDIENCE_ACT to the Act STS origin; in GitHub Actions grant the job permissions id-token: write")
)

type credentialInputs struct {
	clientSecret  string
	oidcToken     string
	oidcTokenFile string
	useOIDC       string
}

type credential struct {
	clientSecret string
	ciToken      auth.CITokenSource
}

type ciEnvironment struct {
	getenv     func(string) string
	httpClient *http.Client
	retry      retry.Policy
}

func resolveCredential(in credentialInputs, env ciEnvironment) (credential, error) {
	useOIDC, err := parseUseOIDC(in.useOIDC)
	if err != nil {
		return credential{}, err
	}
	federates := in.oidcToken != "" || in.oidcTokenFile != "" || useOIDC
	switch {
	case in.clientSecret != "" && federates:
		return credential{}, errBothCredentials
	case in.clientSecret != "":
		return credential{clientSecret: in.clientSecret}, nil
	case in.oidcToken != "" && in.oidcTokenFile != "":
		return credential{}, errBothOIDCInputs
	case in.oidcToken != "":
		return credential{ciToken: auth.StaticCIToken(in.oidcToken)}, nil
	case in.oidcTokenFile != "":
		return credential{ciToken: auth.FileCIToken(in.oidcTokenFile)}, nil
	case useOIDC:
		return detectCIToken(env)
	}
	return credential{}, errNoCredentials
}

func parseUseOIDC(raw string) (bool, error) {
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("use_oidc (ACT_USE_OIDC) must be true or false, not %q", raw)
	}
	return value, nil
}

func detectCIToken(env ciEnvironment) (credential, error) {
	for _, name := range []string{"TFC_WORKLOAD_IDENTITY_TOKEN_ACT", "TFC_WORKLOAD_IDENTITY_TOKEN"} {
		if env.getenv(name) != "" {
			return credential{ciToken: auth.EnvCIToken(name, env.getenv)}, nil
		}
	}
	requestURL, requestToken := env.getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), env.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if requestURL != "" && requestToken != "" {
		return credential{ciToken: auth.GitHubActionsCIToken(requestURL, requestToken, env.httpClient, env.retry)}, nil
	}
	return credential{}, errNoCIToken
}
