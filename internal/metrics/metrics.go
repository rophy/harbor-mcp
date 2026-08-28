package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "harbor_mcp_http_requests_total",
		Help: "Total number of HTTP requests.",
	}, []string{"method", "path", "status"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "harbor_mcp_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	RateLimitHitsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "harbor_mcp_rate_limit_hits_total",
		Help: "Total number of requests rejected by rate limiting.",
	})

	ActiveSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "harbor_mcp_active_sessions",
		Help: "Number of active OAuth sessions.",
	})
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		duration := time.Since(start).Seconds()
		path := normalizePath(r.URL.Path)
		HTTPRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(rec.status)).Inc()
		HTTPRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

func normalizePath(path string) string {
	switch path {
	case "/mcp", "/authorize", "/token", "/register",
		"/auth/callback", "/metrics",
		"/.well-known/oauth-authorization-server":
		return path
	default:
		return "/other"
	}
}
