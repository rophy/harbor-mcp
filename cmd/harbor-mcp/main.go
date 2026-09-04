package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	harbormcp "github.com/rophy/harbor-mcp"
	"github.com/rophy/harbor-mcp/internal/auth"
	"github.com/rophy/harbor-mcp/internal/config"
	"github.com/rophy/harbor-mcp/internal/harbor"
	"github.com/rophy/harbor-mcp/internal/metrics"
	"github.com/rophy/harbor-mcp/internal/ratelimit"
	"github.com/rophy/harbor-mcp/internal/server"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "harbor-mcp",
	Short: "MCP server for Harbor container registry",
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	RunE:  runServe,
}

var helpCmd = &cobra.Command{
	Use:   "help",
	Short: "Show full documentation (README)",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Print(harbormcp.Readme)
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.SetHelpCommand(helpCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	var httpClient *http.Client
	if cfg.TLSSkipVerify {
		slog.Warn("TLS verification disabled")
		httpClient = &http.Client{
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			},
		}
	}

	signingKey, err := loadOrGenerateKey(cfg.OAuthSigningKey, cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to load signing key: %v", err)
	}

	globalSecret, err := loadOrGenerateGlobalSecret(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("failed to load global secret: %v", err)
	}

	var upstreamOpts []*http.Client
	if httpClient != nil {
		upstreamOpts = append(upstreamOpts, httpClient)
	}
	upstream, err := auth.NewUpstreamOIDC(
		cfg.OAuthUpstreamIssuer,
		cfg.OAuthUpstreamClientID,
		cfg.OAuthUpstreamClientSecret,
		cfg.OAuthUpstreamExternalURL,
		upstreamOpts...,
	)
	if err != nil {
		return fmt.Errorf("failed to discover upstream OIDC: %v", err)
	}

	dbPath := filepath.Join(cfg.DataDir, "harbor-mcp.db")
	store, err := auth.NewSQLiteStore(dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}
	defer store.Close()
	provider := auth.NewOAuthProvider(store, signingKey, globalSecret)
	oauthHandlers := auth.NewOAuthHandlers(provider, store, upstream, cfg.ServerBaseURL)

	var harborOpts []harbor.ClientOption
	if httpClient != nil {
		harborOpts = append(harborOpts, harbor.WithHTTPClient(httpClient))
	}
	harborClient := harbor.NewClient(cfg.HarborURL, cfg.HarborRobotName, cfg.HarborRobotSecret, harborOpts...)
	mcpServer := server.NewMCPServer(harborClient)

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{},
	)

	var mcpChain http.Handler = mcpHandler
	if cfg.RateLimitEnabled {
		limiter := ratelimit.New(cfg.RateLimitRPM, cfg.RateLimitBurst)
		mcpChain = ratelimit.Middleware(limiter, mcpChain)
		slog.Info("rate limiting enabled", "rpm", cfg.RateLimitRPM, "burst", cfg.RateLimitBurst)
	}

	httpMux := http.NewServeMux()
	oauthHandlers.RegisterRoutes(httpMux)
	httpMux.Handle("/mcp", auth.RequireBearerToken(provider, mcpChain))
	httpMux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.ServerPort),
		Handler: metrics.Middleware(httpMux),
	}

	shutdownDone := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		close(shutdownDone)
	}()

	slog.Info("harbor-mcp listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	<-shutdownDone
	return nil
}

func parseRSAPrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing key (tried PKCS#1 and PKCS#8): %v", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("PKCS#8 key is not RSA")
	}
	return key, nil
}

func loadOrGenerateKey(pemData string, dataDir string) (*rsa.PrivateKey, error) {
	if pemData != "" {
		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block from OAUTH_SIGNING_KEY")
		}
		slog.Info("using signing key from OAUTH_SIGNING_KEY env var")
		return parseRSAPrivateKey(block)
	}

	keyPath := filepath.Join(dataDir, "signing-key.pem")
	if data, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block from %s", keyPath)
		}
		slog.Info("loaded signing key from file", "path", keyPath)
		return parseRSAPrivateKey(block)
	}

	slog.Info("generating new RSA signing key", "path", keyPath)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(keyPath, pemBytes, 0600); err != nil {
		return nil, fmt.Errorf("failed to save signing key to %s: %v", keyPath, err)
	}
	slog.Info("saved signing key", "path", keyPath)
	return key, nil
}

func loadOrGenerateGlobalSecret(dataDir string) ([]byte, error) {
	secretPath := filepath.Join(dataDir, "global-secret")
	if data, err := os.ReadFile(secretPath); err == nil && len(data) == 32 {
		slog.Info("loaded global secret from file", "path", secretPath)
		return data, nil
	}

	slog.Info("generating new global secret", "path", secretPath)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.WriteFile(secretPath, secret, 0600); err != nil {
		return nil, fmt.Errorf("failed to save global secret to %s: %v", secretPath, err)
	}
	slog.Info("saved global secret", "path", secretPath)
	return secret, nil
}
