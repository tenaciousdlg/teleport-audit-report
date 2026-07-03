// Package report implements the four audit-report queries (activity,
// requests, security, compliance) against the events table populated by
// audit-sink.
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// EventRow is one row from the events table, with Raw left as unparsed JSON
// so each report can pull out only the fields relevant to it.
type EventRow struct {
	UID       string
	Type      string
	Code      string
	Time      time.Time
	User      string
	SessionID string
	Success   *bool
	Raw       json.RawMessage
}

// Filter selects events by time range and, optionally, event type and user.
// An empty Types means "no event-type filter" (used by the compliance report).
type Filter struct {
	From  time.Time
	To    time.Time
	User  string
	Types []string
}

func queryEvents(ctx context.Context, pool *pgxpool.Pool, f Filter) ([]EventRow, error) {
	sql := `
		SELECT uid, event_type, event_code, event_time, user_name, session_id, success, raw
		FROM events
		WHERE event_time >= $1 AND event_time <= $2
		  AND ($3 = '' OR user_name = $3)
		  AND ($4::text[] IS NULL OR event_type = ANY($4))
		ORDER BY event_time ASC
	`
	var types any
	if len(f.Types) > 0 {
		types = f.Types
	}

	rows, err := pool.Query(ctx, sql, f.From, f.To, f.User, types)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var out []EventRow
	for rows.Next() {
		var e EventRow
		if err := rows.Scan(&e.UID, &e.Type, &e.Code, &e.Time, &e.User, &e.SessionID, &e.Success, &e.Raw); err != nil {
			return nil, fmt.Errorf("scan event row: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// rawField best-effort extracts a string field from an event's raw JSON.
// Teleport's event schema varies by event type and version, so callers
// should treat a missing field as "not reported" rather than an error.
func rawField(raw json.RawMessage, key string) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// rawDuration computes a session duration from the gap between a
// session.end-style event's `session_start`/`session_stop` timestamps.
// There is no native numeric duration field: confirmed against
// api/proto/teleport/legacy/types/events/events.proto in
// gravitational/teleport, where SessionEnd, DatabaseSessionEnd, and
// WindowsDesktopSessionEnd all carry only these two RFC3339 timestamps.
// Returns "" if either field is missing or unparseable (e.g. for event
// types that don't carry them at all — see sessionEndTypesWithDuration).
func rawDuration(raw json.RawMessage) string {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	start, sOk := m["session_start"].(string)
	stop, eOk := m["session_stop"].(string)
	if !sOk || !eOk {
		return ""
	}
	startT, err1 := time.Parse(time.RFC3339, start)
	stopT, err2 := time.Parse(time.RFC3339, stop)
	if err1 != nil || err2 != nil {
		return ""
	}
	return stopT.Sub(startT).String()
}
