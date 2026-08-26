package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	harbormcp "github.com/rophy/harbor-mcp"
	"github.com/rophy/harbor-mcp/internal/auth"
	"github.com/rophy/harbor-mcp/internal/config"
	"github.com/rophy/harbor-mcp/internal/harbor"
	"github.com/rophy/harbor-mcp/internal/server"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "harbor-mcp",
	Short: "MCP server for Harbor container registry",
	Long:  harbormcp.Readme,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %v", err)
	}

	signingKey, err := loadOrGenerateKey(cfg.OAuthSigningKey)
	if err != nil {
		return fmt.Errorf("failed to load signing key: %v", err)
	}

	upstream, err := auth.NewUpstreamOIDC(
		cfg.OAuthUpstreamIssuer,
		cfg.OAuthUpstreamClientID,
		cfg.OAuthUpstreamClientSecret,
		cfg.OAuthUpstreamExternalURL,
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
	provider := auth.NewOAuthProvider(store, signingKey)
	oauthHandlers := auth.NewOAuthHandlers(provider, store, upstream, cfg.ServerBaseURL)

	harborClient := harbor.NewClient(cfg.HarborURL, cfg.HarborRobotName, cfg.HarborRobotSecret)
	mcpServer := server.NewMCPServer(harborClient)

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return mcpServer },
		&mcp.StreamableHTTPOptions{},
	)

	httpMux := http.NewServeMux()
	oauthHandlers.RegisterRoutes(httpMux)
	httpMux.Handle("/mcp", auth.RequireBearerToken(provider, mcpHandler))

	addr := fmt.Sprintf(":%d", cfg.ServerPort)
	log.Printf("harbor-mcp listening on %s", addr)
	return http.ListenAndServe(addr, httpMux)
}

func loadOrGenerateKey(pemData string) (*rsa.PrivateKey, error) {
	if pemData != "" {
		block, _ := pem.Decode([]byte(pemData))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM signing key")
		}
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	log.Println("no OAUTH_SIGNING_KEY set, generating ephemeral RSA key")
	return rsa.GenerateKey(rand.Reader, 2048)
}
