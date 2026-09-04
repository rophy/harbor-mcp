package auth

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

type Store interface {
	fosite.Storage
	RegisterClient(id string, redirectURIs []string)
}

func NewOAuthProvider(store Store, signingKey *rsa.PrivateKey, globalSecret []byte) fosite.OAuth2Provider {
	config := &fosite.Config{
		AccessTokenLifespan:         time.Hour,
		RefreshTokenLifespan:        24 * time.Hour,
		AuthorizeCodeLifespan:       10 * time.Minute,
		EnforcePKCE:                 true,
		EnforcePKCEForPublicClients: true,
		TokenURL:                    "/token",
		SendDebugMessagesToClients:  false,
		GlobalSecret:                globalSecret,
	}

	keyGetter := func(_ context.Context) (interface{}, error) {
		return signingKey, nil
	}

	hmacStrategy := compose.NewOAuth2HMACStrategy(config)
	jwtStrategy := compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, config)

	return compose.Compose(
		config,
		store,
		&compose.CommonStrategy{
			CoreStrategy: jwtStrategy,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)
}
