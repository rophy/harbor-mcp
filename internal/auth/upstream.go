package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type UpstreamOIDC struct {
	Issuer                string
	ClientID              string
	ClientSecret          string
	AuthorizationEndpoint string
	TokenEndpoint         string
}

type UpstreamTokens struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func NewUpstreamOIDC(issuer, clientID, clientSecret string) (*UpstreamOIDC, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var disc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
		return nil, fmt.Errorf("decoding OIDC discovery: %w", err)
	}

	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery missing required endpoints")
	}

	return &UpstreamOIDC{
		Issuer:                issuer,
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		AuthorizationEndpoint: disc.AuthorizationEndpoint,
		TokenEndpoint:         disc.TokenEndpoint,
	}, nil
}

func (u *UpstreamOIDC) AuthorizationURL(state, callbackURL string) string {
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {u.ClientID},
		"redirect_uri":  {callbackURL},
		"state":         {state},
		"scope":         {"openid profile email"},
	}
	return u.AuthorizationEndpoint + "?" + v.Encode()
}

func (u *UpstreamOIDC) ExchangeCode(ctx context.Context, code, callbackURL string) (*UpstreamTokens, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {callbackURL},
		"client_id":     {u.ClientID},
		"client_secret": {u.ClientSecret},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned status %d", resp.StatusCode)
	}

	var tokens UpstreamTokens
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	return &tokens, nil
}
