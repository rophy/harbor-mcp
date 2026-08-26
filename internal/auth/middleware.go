package auth

import (
	"net/http"
	"strings"

	"github.com/ory/fosite"
	fositeOAuth2 "github.com/ory/fosite/handler/oauth2"
)

func RequireBearerToken(provider fosite.OAuth2Provider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		ctx := r.Context()

		_, _, err := provider.IntrospectToken(ctx, token, fosite.AccessToken, new(fositeOAuth2.JWTSession))
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
