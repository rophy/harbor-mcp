package main

import (
	"fmt"
	"log"
	"os"

	"github.com/rophy/harbor-mcp/internal/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	fmt.Fprintf(os.Stderr, "harbor-mcp starting on port %d\n", cfg.ServerPort)
}
