// Package ingest normalizes raw Teleport audit event JSON and writes it to
// Postgres, idempotently.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// event mirrors the handful of common fields present across Teleport's
// audit event types (see the "Event Structure" section of Teleport's audit
// event reference). Everything else is preserved verbatim in Raw.
//
// The actor isn't always the top-level `user` field: cert-issuance-shaped
// events (cert.create, and similarly bot-related events) instead nest it
// under `identity.user` — verified against real events from this cluster,
// not assumed from the docs.
type event struct {
	UID         string    `json:"uid"`
	Event       string    `json:"event"`
	Code        string    `json:"code"`
	Time        time.Time `json:"time"`
	ClusterName string    `json:"cluster_name"`
	User        string    `json:"user"`
	Identity    struct {
		User string `json:"user"`
	} `json:"identity"`
	SessionID string          `json:"sid"`
	Success   *bool           `json:"success"`
	Raw       json.RawMessage `json:"-"`
}

func (e *event) actor() string {
	if e.User != "" {
		return e.User
	}
	return e.Identity.User
}

// Store applies schema.sql via db.Connect before this is used.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Upsert parses one JSON audit event and inserts it, ignoring duplicates.
// Duplicates are expected: the Event Handler plugin can resend an entire
// time window after a restart, so dedup on `uid` is required, not optional.
func (s *Store) Upsert(ctx context.Context, body []byte) error {
	var e event
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("parse event json: %w", err)
	}
	if e.UID == "" {
		return fmt.Errorf("event missing uid field")
	}
	e.Raw = body

	_, err := s.pool.Exec(ctx, `
		INSERT INTO events (uid, event_type, event_code, event_time, cluster_name, user_name, session_id, success, raw)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (uid) DO NOTHING
	`, e.UID, e.Event, e.Code, e.Time, e.ClusterName, e.actor(), e.SessionID, e.Success, []byte(e.Raw))
	if err != nil {
		return fmt.Errorf("upsert event %s: %w", e.UID, err)
	}
	return nil
}
