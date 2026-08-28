package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/ory/fosite"
	fositeOAuth2 "github.com/ory/fosite/handler/oauth2"
)

type contextKey struct{ name string }

var subjectKey = &contextKey{"subject"}

func ExportedSubjectKey() any { return subjectKey }

func SubjectFromContext(ctx context.Context) string {
	s, _ := ctx.Value(subjectKey).(string)
	return s
}

func RequireBearerToken(provider fosite.OAuth2Provider, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		ctx := r.Context()

		session := new(fositeOAuth2.JWTSession)
		_, ar, err := provider.IntrospectToken(ctx, token, fosite.AccessToken, session)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		if sub := ar.GetSession().GetSubject(); sub != "" {
			ctx = context.WithValue(ctx, subjectKey, sub)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}
