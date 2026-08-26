package auth

import (
	"context"
	"sync"
	"time"

	"github.com/ory/fosite"
)

type authCodeEntry struct {
	req         fosite.Requester
	invalidated bool
}

type MemoryStore struct {
	mu            sync.RWMutex
	clients       map[string]fosite.Client
	authCodes     map[string]*authCodeEntry
	accessTokens  map[string]fosite.Requester
	refreshTokens map[string]fosite.Requester
	pkces         map[string]fosite.Requester
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		clients:       make(map[string]fosite.Client),
		authCodes:     make(map[string]*authCodeEntry),
		accessTokens:  make(map[string]fosite.Requester),
		refreshTokens: make(map[string]fosite.Requester),
		pkces:         make(map[string]fosite.Requester),
	}
}

func (s *MemoryStore) RegisterClient(id string, redirectURIs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[id] = &fosite.DefaultClient{
		ID:            id,
		Public:        true,
		RedirectURIs:  redirectURIs,
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"harbor:read"},
	}
}

func (s *MemoryStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return client, nil
}

func (s *MemoryStore) ClientAssertionJWTValid(_ context.Context, _ string) error {
	return nil
}

func (s *MemoryStore) SetClientAssertionJWT(_ context.Context, _ string, _ time.Time) error {
	return nil
}

func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authCodes[code] = &authCodeEntry{req: req}
	return nil
}

func (s *MemoryStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.authCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if entry.invalidated {
		return entry.req, fosite.ErrInvalidatedAuthorizeCode
	}
	return entry.req, nil
}

func (s *MemoryStore) InvalidateAuthorizeCodeSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.authCodes[code]
	if !ok {
		return fosite.ErrNotFound
	}
	entry.invalidated = true
	return nil
}

func (s *MemoryStore) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkces[code] = req
	return nil
}

func (s *MemoryStore) GetPKCERequestSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.pkces[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) DeletePKCERequestSession(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pkces, code)
	return nil
}

func (s *MemoryStore) CreateAccessTokenSession(_ context.Context, sig string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTokens[sig] = req
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(_ context.Context, sig string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.accessTokens[sig]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, sig string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.accessTokens, sig)
	return nil
}

func (s *MemoryStore) CreateRefreshTokenSession(_ context.Context, sig string, _ string, req fosite.Requester) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[sig] = req
	return nil
}

func (s *MemoryStore) GetRefreshTokenSession(_ context.Context, sig string, _ fosite.Session) (fosite.Requester, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.refreshTokens[sig]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return req, nil
}

func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, sig string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, sig)
	return nil
}

func (s *MemoryStore) RevokeRefreshToken(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sig, req := range s.refreshTokens {
		if req.GetID() == requestID {
			delete(s.refreshTokens, sig)
		}
	}
	return nil
}

func (s *MemoryStore) RotateRefreshToken(_ context.Context, _ string, signature string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, signature)
	return nil
}

func (s *MemoryStore) RevokeAccessToken(_ context.Context, requestID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sig, req := range s.accessTokens {
		if req.GetID() == requestID {
			delete(s.accessTokens, sig)
		}
	}
	return nil
}

var _ fosite.Storage = (*MemoryStore)(nil)
