package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	HarborURL                    string
	HarborRobotName              string
	HarborRobotSecret            string
	OAuthUpstreamIssuer          string
	OAuthUpstreamClientID        string
	OAuthUpstreamClientSecret    string
	OAuthUpstreamExternalURL     string // browser-reachable base URL for upstream OIDC (optional, overrides issuer for authorize redirect)
	OAuthSigningKey              string
	DataDir                      string
	ServerBaseURL                string
	ServerPort                   int
}

func Load() (*Config, error) {
	cfg := &Config{
		ServerPort: 8080,
	}

	required := map[string]*string{
		"HARBOR_URL":                   &cfg.HarborURL,
		"HARBOR_ROBOT_NAME":            &cfg.HarborRobotName,
		"HARBOR_ROBOT_SECRET":          &cfg.HarborRobotSecret,
		"OAUTH_UPSTREAM_ISSUER":        &cfg.OAuthUpstreamIssuer,
		"OAUTH_UPSTREAM_CLIENT_ID":     &cfg.OAuthUpstreamClientID,
		"OAUTH_UPSTREAM_CLIENT_SECRET": &cfg.OAuthUpstreamClientSecret,
		"SERVER_BASE_URL":              &cfg.ServerBaseURL,
	}

	for env, ptr := range required {
		val := os.Getenv(env)
		if val == "" {
			return nil, fmt.Errorf("required environment variable %s is not set", env)
		}
		*ptr = val
	}

	cfg.OAuthSigningKey = os.Getenv("OAUTH_SIGNING_KEY")
	cfg.OAuthUpstreamExternalURL = os.Getenv("OAUTH_UPSTREAM_EXTERNAL_URL")
	cfg.DataDir = os.Getenv("DATA_DIR")
	if cfg.DataDir == "" {
		cfg.DataDir = "/data"
	}

	if p := os.Getenv("SERVER_PORT"); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("SERVER_PORT is not a valid integer: %w", err)
		}
		cfg.ServerPort = port
	}

	return cfg, nil
}
