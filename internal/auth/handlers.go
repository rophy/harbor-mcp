package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

type OAuthHandlers struct {
	provider fosite.OAuth2Provider
	store    *MemoryStore
	upstream *UpstreamOIDC
	baseURL  string
	mu       sync.Mutex
	pending  map[string]*pendingAuth // state -> pending authorization
}

type pendingAuth struct {
	fositeReq     fosite.AuthorizeRequester
	upstreamState string
	createdAt     time.Time
}

const pendingAuthTTL = 10 * time.Minute

func NewOAuthHandlers(provider fosite.OAuth2Provider, store *MemoryStore, upstream *UpstreamOIDC, baseURL string) *OAuthHandlers {
	return &OAuthHandlers{
		provider: provider,
		store:    store,
		upstream: upstream,
		baseURL:  strings.TrimRight(baseURL, "/"),
		pending:  make(map[string]*pendingAuth),
	}
}

func (h *OAuthHandlers) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", h.handleMetadata)
	mux.HandleFunc("POST /register", h.handleRegister)
	mux.HandleFunc("GET /authorize", h.handleAuthorize)
	mux.HandleFunc("GET /auth/callback", h.handleCallback)
	mux.HandleFunc("POST /token", h.handleToken)
}

func (h *OAuthHandlers) handleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]any{
		"issuer":                                h.baseURL,
		"authorization_endpoint":                h.baseURL + "/authorize",
		"token_endpoint":                        h.baseURL + "/token",
		"registration_endpoint":                 h.baseURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"harbor:read"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

func (h *OAuthHandlers) handleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris required", http.StatusBadRequest)
		return
	}

	clientID := generateID()
	h.store.RegisterClient(clientID, req.RedirectURIs)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  clientID,
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

func (h *OAuthHandlers) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ar, err := h.provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	ar.GrantScope("harbor:read")

	state := generateID()
	h.mu.Lock()
	h.cleanExpiredPendingLocked()
	h.pending[state] = &pendingAuth{
		fositeReq:     ar,
		upstreamState: state,
		createdAt:     time.Now(),
	}
	h.mu.Unlock()

	callbackURL := h.baseURL + "/auth/callback"
	upstreamURL := h.upstream.AuthorizationURL(state, callbackURL)
	http.Redirect(w, r, upstreamURL, http.StatusFound)
}

func (h *OAuthHandlers) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	if state == "" || code == "" {
		http.Error(w, "missing state or code", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	p, ok := h.pending[state]
	if ok {
		delete(h.pending, state)
	}
	h.mu.Unlock()

	if !ok {
		http.Error(w, "unknown state parameter", http.StatusBadRequest)
		return
	}

	callbackURL := h.baseURL + "/auth/callback"
	_, err := h.upstream.ExchangeCode(ctx, code, callbackURL)
	if err != nil {
		log.Printf("upstream token exchange failed: %v", err)
		http.Error(w, "upstream authentication failed", http.StatusBadGateway)
		return
	}

	session := &openid.DefaultSession{}
	response, err := h.provider.NewAuthorizeResponse(ctx, p.fositeReq, session)
	if err != nil {
		h.provider.WriteAuthorizeError(ctx, w, p.fositeReq, err)
		return
	}

	h.provider.WriteAuthorizeResponse(ctx, w, p.fositeReq, response)
}

func (h *OAuthHandlers) handleToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := &openid.DefaultSession{}

	ar, err := h.provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		h.provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	ar.GrantScope("harbor:read")

	response, err := h.provider.NewAccessResponse(ctx, ar)
	if err != nil {
		h.provider.WriteAccessError(ctx, w, ar, err)
		return
	}

	h.provider.WriteAccessResponse(ctx, w, ar, response)
}

func (h *OAuthHandlers) cleanExpiredPendingLocked() {
	now := time.Now()
	for k, v := range h.pending {
		if now.Sub(v.createdAt) > pendingAuthTTL {
			delete(h.pending, k)
		}
	}
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
