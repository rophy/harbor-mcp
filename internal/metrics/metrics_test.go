package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_RecordsMetrics(t *testing.T) {
	handler := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	count := testutil.ToFloat64(HTTPRequestsTotal.WithLabelValues("GET", "/mcp", "200"))
	require.GreaterOrEqual(t, count, float64(1))
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/mcp", "/mcp"},
		{"/authorize", "/authorize"},
		{"/token", "/token"},
		{"/register", "/register"},
		{"/metrics", "/metrics"},
		{"/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server"},
		{"/unknown", "/other"},
		{"/foo/bar", "/other"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, normalizePath(tt.input), "normalizePath(%q)", tt.input)
	}
}

func TestStatusRecorder_CapturesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: http.StatusOK}
	sr.WriteHeader(http.StatusNotFound)
	assert.Equal(t, http.StatusNotFound, sr.status)
}
