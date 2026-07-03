// Package db provides the shared Postgres connection pool and schema setup
// used by both audit-sink (writer) and audit-report (reader).
package db

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

// Connect opens a pool against connString and applies schema.sql.
// schema.sql uses CREATE TABLE/INDEX IF NOT EXISTS, so this is safe to run
// on every startup instead of maintaining a separate migration runner.
func Connect(ctx context.Context, connString string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	if _, err := pool.Exec(ctx, schema); err != nil {
		pool.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return pool, nil
}
