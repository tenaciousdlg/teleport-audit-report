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
// The actor isn't always the top-level `user` field. Verified against real
// events from this cluster, not assumed from the docs:
//   - cert-issuance-shaped events (cert.create, and similarly bot-related
//     events) nest it under `identity.user`
//   - bot.join carries the joining bot's identity under a top-level
//     `user_name` field instead — found as a real bug (every bot.join row
//     showed a blank actor, including in the `user_name` DB column itself,
//     which broke `--user=<bot>` filtering, not just display)
//   - access_request.review has no `user`/`identity.user`/`user_name` at
//     all; the acting identity is the reviewer, under `reviewer`
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
	UserName  string          `json:"user_name"`
	Reviewer  string          `json:"reviewer"`
	SessionID string          `json:"sid"`
	Success   *bool           `json:"success"`
	Raw       json.RawMessage `json:"-"`
}

func (e *event) actor() string {
	switch {
	case e.User != "":
		return e.User
	case e.Identity.User != "":
		return e.Identity.User
	case e.UserName != "":
		return e.UserName
	default:
		return e.Reviewer
	}
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
