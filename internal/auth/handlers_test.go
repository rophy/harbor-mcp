package auth_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func fakeIDToken(sub string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"sub":%q,"iss":"test"}`, sub)))
	return header + "." + payload + "."
}

type testEnv struct {
	srv *httptest.Server
	idp *httptest.Server
}

func setupOAuthServer(t *testing.T) *httptest.Server {
	t.Helper()
	return setupOAuthServerEnv(t).srv
}

func setupOAuthServerEnv(t *testing.T) *testEnv {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": "https://idp.example.com/authorize",
				"token_endpoint":         "http://" + r.Host + "/token",
			})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "upstream-access-token",
				"id_token":     fakeIDToken("alice"),
				"token_type":   "Bearer",
			})
		}
	}))
	t.Cleanup(idp.Close)

	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
	if err != nil {
		t.Fatalf("upstream setup: %v", err)
	}

	mux := http.NewServeMux()
	handlers := auth.NewOAuthHandlers(provider, store, upstream, "http://localhost:8080")
	handlers.RegisterRoutes(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &testEnv{srv: srv, idp: idp}
}

func TestMetadataEndpoint(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.Get(srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var metadata map[string]any
	json.NewDecoder(resp.Body).Decode(&metadata)

	if metadata["authorization_endpoint"] != "http://localhost:8080/authorize" {
		t.Errorf("authorization_endpoint = %v", metadata["authorization_endpoint"])
	}
	if metadata["token_endpoint"] != "http://localhost:8080/token" {
		t.Errorf("token_endpoint = %v", metadata["token_endpoint"])
	}
}

func TestRegisterEndpoint(t *testing.T) {
	srv := setupOAuthServer(t)

	body := `{"redirect_uris": ["http://localhost:3000/callback"], "client_name": "test"}`
	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	if result["client_id"] == nil || result["client_id"] == "" {
		t.Error("client_id should be set")
	}
}

func TestRegisterEndpoint_MissingRedirectURIs(t *testing.T) {
	srv := setupOAuthServer(t)

	body := `{"client_name": "test"}`
	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRegisterEndpoint_InvalidJSON(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.Post(srv.URL+"/register", "application/json", strings.NewReader("not json"))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeEndpoint_UnknownClient(t *testing.T) {
	srv := setupOAuthServer(t)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(srv.URL + "/authorize?client_id=unknown&response_type=code&redirect_uri=http://localhost/cb&code_challenge=test&code_challenge_method=S256")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("should not redirect for unknown client, got %d", resp.StatusCode)
	}
}

func registerAndGetClientID(t *testing.T, srvURL string) string {
	t.Helper()
	body := `{"redirect_uris": ["http://localhost:9999/callback"], "client_name": "test"}`
	resp, err := http.Post(srvURL+"/register", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result["client_id"].(string)
}

func TestAuthorizeEndpoint_RedirectsToUpstream(t *testing.T) {
	srv := setupOAuthServer(t)
	clientID := registerAndGetClientID(t, srv.URL)

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	authorizeURL := fmt.Sprintf("%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=test-state",
		srv.URL, clientID, url.QueryEscape("http://localhost:9999/callback"))

	resp, err := client.Get(authorizeURL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 302; body: %s", resp.StatusCode, body)
	}

	location := resp.Header.Get("Location")
	if !strings.Contains(location, "idp.example.com/authorize") {
		t.Errorf("expected redirect to upstream IDP, got: %s", location)
	}
	if !strings.Contains(location, "client_id=client-id") {
		t.Errorf("expected upstream client_id in redirect, got: %s", location)
	}
}

func TestTokenEndpoint_InvalidGrant(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"invalid-code"},
		"client_id":  {"nonexistent"},
	})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		t.Fatal("expected error for invalid token request")
	}
}

func TestCallbackEndpoint_MissingParams(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.Get(srv.URL + "/auth/callback")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestCallbackEndpoint_UnknownState(t *testing.T) {
	srv := setupOAuthServer(t)

	resp, err := http.Get(srv.URL + "/auth/callback?state=unknown&code=somecode")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestRequireBearerToken_MissingToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	handler := auth.RequireBearerToken(provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestRequireBearerToken_InvalidToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	handler := auth.RequireBearerToken(provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestCallbackEndpoint_UpstreamTokenExchangeFails(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": "https://idp.example.com/authorize",
				"token_endpoint":         "http://" + r.Host + "/token",
			})
		case "/token":
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	t.Cleanup(idp.Close)

	upstream, err := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
	if err != nil {
		t.Fatalf("upstream setup: %v", err)
	}

	mux := http.NewServeMux()
	handlers := auth.NewOAuthHandlers(provider, store, upstream, "http://localhost:8080")
	handlers.RegisterRoutes(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	clientID := registerAndGetClientID(t, srv.URL)
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authorizeURL := fmt.Sprintf("%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=test-state-value",
		srv.URL, clientID, url.QueryEscape("http://localhost:9999/callback"), codeChallenge)

	resp, err := noFollow.Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize status = %d, want 302 or 303", resp.StatusCode)
	}

	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	upstreamState := location.Query().Get("state")
	if upstreamState == "" {
		t.Fatalf("no state in upstream redirect; Location: %s", resp.Header.Get("Location"))
	}

	callbackURL := fmt.Sprintf("%s/auth/callback?state=%s&code=mock-code", srv.URL, upstreamState)
	resp, err = noFollow.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 502; body: %s", resp.StatusCode, body)
	}
}

func completeOAuthFlow(t *testing.T, env *testEnv) (accessToken string) {
	t.Helper()
	srv := env.srv

	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	clientID := registerAndGetClientID(t, srv.URL)
	redirectURI := "http://localhost:9999/callback"

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authorizeURL := fmt.Sprintf("%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=client-state",
		srv.URL, clientID, url.QueryEscape(redirectURI), codeChallenge)

	resp, err := noFollow.Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	resp.Body.Close()

	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	upstreamState := location.Query().Get("state")

	callbackURL := fmt.Sprintf("%s/auth/callback?state=%s&code=mock-upstream-code", srv.URL, upstreamState)
	resp, err = noFollow.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	resp.Body.Close()

	callbackRedirect, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	authCode := callbackRedirect.Query().Get("code")

	tokenResp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	defer tokenResp.Body.Close()

	var tokenResult map[string]any
	json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	return tokenResult["access_token"].(string)
}

func TestCallbackEndpoint_HappyPath(t *testing.T) {
	env := setupOAuthServerEnv(t)
	srv := env.srv

	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	clientID := registerAndGetClientID(t, srv.URL)
	redirectURI := "http://localhost:9999/callback"

	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authorizeURL := fmt.Sprintf("%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=client-state",
		srv.URL, clientID, url.QueryEscape(redirectURI), codeChallenge)

	resp, err := noFollow.Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}

	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	upstreamState := location.Query().Get("state")
	if upstreamState == "" {
		t.Fatal("no state in upstream redirect")
	}

	callbackURL := fmt.Sprintf("%s/auth/callback?state=%s&code=mock-upstream-code", srv.URL, upstreamState)
	resp, err = noFollow.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 302 or 303", resp.StatusCode)
	}

	callbackRedirect, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	authCode := callbackRedirect.Query().Get("code")
	if authCode == "" {
		t.Fatal("no authorization code in callback redirect")
	}
	if callbackRedirect.Query().Get("state") != "client-state" {
		t.Errorf("state = %q, want client-state", callbackRedirect.Query().Get("state"))
	}

	tokenResp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status = %d, want 200; body: %s", tokenResp.StatusCode, body)
	}

	var tokenResult map[string]any
	json.NewDecoder(tokenResp.Body).Decode(&tokenResult)

	if tokenResult["access_token"] == nil || tokenResult["access_token"] == "" {
		t.Error("expected access_token in response")
	}
	if tokenResult["token_type"] != "bearer" {
		t.Errorf("token_type = %v, want bearer", tokenResult["token_type"])
	}
}

func TestRequireBearerToken_SetsSubjectInContext(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"authorization_endpoint": "https://idp.example.com/authorize",
				"token_endpoint":         "http://" + r.Host + "/token",
			})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"access_token": "upstream-access-token",
				"id_token":     fakeIDToken("alice"),
				"token_type":   "Bearer",
			})
		}
	}))
	t.Cleanup(idp.Close)

	upstream, _ := auth.NewUpstreamOIDC(idp.URL, "client-id", "client-secret", "")
	mux := http.NewServeMux()
	handlers := auth.NewOAuthHandlers(provider, store, upstream, "http://localhost:8080")
	handlers.RegisterRoutes(mux)

	var capturedSubject string
	protectedHandler := auth.RequireBearerToken(provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSubject = auth.SubjectFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	mux.Handle("/protected", protectedHandler)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	clientID := registerAndGetClientID(t, srv.URL)
	redirectURI := "http://localhost:9999/callback"
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authorizeURL := fmt.Sprintf("%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=test-state-value",
		srv.URL, clientID, url.QueryEscape(redirectURI), codeChallenge)
	resp, err := noFollow.Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorize: status %d, want 302 or 303", resp.StatusCode)
	}

	location, _ := url.Parse(resp.Header.Get("Location"))
	upstreamState := location.Query().Get("state")
	if upstreamState == "" {
		t.Fatalf("no state in upstream redirect: %s", resp.Header.Get("Location"))
	}

	callbackURL := fmt.Sprintf("%s/auth/callback?state=%s&code=mock-code", srv.URL, upstreamState)
	resp, err = noFollow.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback: status %d, body: %s", resp.StatusCode, body)
	}

	callbackRedirect, _ := url.Parse(resp.Header.Get("Location"))
	authCode := callbackRedirect.Query().Get("code")

	tokenResp, err := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	})
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer tokenResp.Body.Close()

	var tokenResult map[string]any
	json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	accessToken := tokenResult["access_token"].(string)

	// Use the token against the protected endpoint
	req, _ := http.NewRequest("GET", srv.URL+"/protected", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("protected request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("protected status = %d, want 200", resp.StatusCode)
	}
	if capturedSubject != "alice" {
		t.Errorf("subject = %q, want alice", capturedSubject)
	}
}

func TestRequireBearerToken_NonBearerScheme(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	store := auth.NewMemoryStore()
	provider := auth.NewOAuthProvider(store, key)

	handler := auth.RequireBearerToken(provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestTokenEndpoint_ReplayedCode(t *testing.T) {
	env := setupOAuthServerEnv(t)
	srv := env.srv

	noFollow := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	clientID := registerAndGetClientID(t, srv.URL)
	redirectURI := "http://localhost:9999/callback"
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authorizeURL := fmt.Sprintf("%s/authorize?client_id=%s&response_type=code&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=client-state",
		srv.URL, clientID, url.QueryEscape(redirectURI), codeChallenge)

	resp, err := noFollow.Get(authorizeURL)
	if err != nil {
		t.Fatalf("authorize failed: %v", err)
	}
	resp.Body.Close()
	location, _ := url.Parse(resp.Header.Get("Location"))

	callbackResp, err := noFollow.Get(fmt.Sprintf("%s/auth/callback?state=%s&code=mock-code", srv.URL, location.Query().Get("state")))
	if err != nil {
		t.Fatalf("callback failed: %v", err)
	}
	callbackResp.Body.Close()
	callbackRedirect, _ := url.Parse(callbackResp.Header.Get("Location"))
	authCode := callbackRedirect.Query().Get("code")

	// First exchange succeeds
	resp1, _ := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	})
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first token exchange status = %d, want 200", resp1.StatusCode)
	}

	// Second exchange with same code should fail
	resp2, _ := http.PostForm(srv.URL+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {codeVerifier},
	})
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("expected error for replayed authorization code")
	}
}
