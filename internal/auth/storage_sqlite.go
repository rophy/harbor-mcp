package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/ory/fosite"
	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	*MemoryStore
	db *sql.DB
}

func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS clients (
		id TEXT PRIMARY KEY,
		redirect_uris TEXT NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("create clients table: %w", err)
	}

	store := &SQLiteStore{
		MemoryStore: NewMemoryStore(),
		db:          db,
	}

	if err := store.loadClients(); err != nil {
		db.Close()
		return nil, fmt.Errorf("load clients: %w", err)
	}

	return store, nil
}

func (s *SQLiteStore) loadClients() error {
	rows, err := s.db.Query("SELECT id, redirect_uris FROM clients")
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var id, urisJSON string
		if err := rows.Scan(&id, &urisJSON); err != nil {
			return err
		}
		var uris []string
		if err := json.Unmarshal([]byte(urisJSON), &uris); err != nil {
			return fmt.Errorf("unmarshal redirect_uris for client %s: %w", id, err)
		}
		s.MemoryStore.RegisterClient(id, uris)
		count++
	}
	if count > 0 {
		slog.Info("loaded OAuth clients from database", "count", count)
	}
	return rows.Err()
}

func (s *SQLiteStore) RegisterClient(id string, redirectURIs []string) {
	s.MemoryStore.RegisterClient(id, redirectURIs)

	urisJSON, err := json.Marshal(redirectURIs)
	if err != nil {
		slog.Error("failed to marshal redirect_uris", "error", err)
		return
	}
	if _, err := s.db.Exec(
		"INSERT OR REPLACE INTO clients (id, redirect_uris) VALUES (?, ?)",
		id, string(urisJSON),
	); err != nil {
		slog.Error("failed to persist client", "client_id", id, "error", err)
	}
}

func (s *SQLiteStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return s.MemoryStore.GetClient(ctx, id)
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
