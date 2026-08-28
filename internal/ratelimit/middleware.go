package ratelimit

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/rophy/harbor-mcp/internal/auth"
)

func Middleware(limiter *Limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := auth.SubjectFromContext(r.Context())
		if key == "" {
			key = "anonymous"
		}

		if limiter.Allow(key) {
			next.ServeHTTP(w, r)
			return
		}

		slog.Warn("rate limit exceeded", "user", key, "rpm", limiter.RPM())

		retryAfter := 60
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]any{
			"error":               "rate_limit_exceeded",
			"error_description":   "Rate limit exceeded. Please retry later.",
			"retry_after_seconds": retryAfter,
		})
	})
}
