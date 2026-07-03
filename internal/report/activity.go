package report

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
)

// activityEventTypes covers session lifecycle and in-session actions across
// every protocol Teleport proxies. Verified directly against
// gravitational/teleport's lib/events/api.go (event type constants) and
// https://goteleport.com/docs/reference/audit-events/ (descriptions).
//
// Deliberately excluded: BPF-based enhanced session recording events
// (session.command, session.network, session.disk) and db.session.*.execute
// statement-capture events — these are per-command/per-syscall/per-query
// forensic detail, not session-level activity. They're still visible via
// the compliance report's unfiltered export; curating them into activity
// would make routine sessions look far noisier than they are.
var activityEventTypes = []string{
	// SSH / Kubernetes exec sessions.
	"session.start", "session.end", "session.join", "session.leave",
	"exec", "scp", "sftp",
	// Database sessions and top-level queries (not per-statement capture).
	"db.session.start", "db.session.end",
	"db.session.query", "db.session.query.failed",
	// Application access.
	"app.session.start", "app.session.end",
	// Kubernetes API requests.
	"kube.request",
	// Windows desktop (RDP) sessions.
	"windows.desktop.session.start", "windows.desktop.session.end",
	// MCP (Model Context Protocol) sessions.
	"mcp.session.start", "mcp.session.end",
}

// sessionEndTypesWithDuration are the *.session.end variants confirmed (via
// api/proto/teleport/legacy/types/events/events.proto) to carry
// session_start/session_stop timestamps. app.session.end is deliberately
// excluded: Teleport's own lib/events/api.go documents in its
// SessionRecordingEvents comment that "TCP application sessions emit
// AppSessionEndEvent but produce no recordings" — it carries no timestamp
// fields to compute a duration from. mcp.session.end's shape isn't verified
// either way, so it's excluded rather than assumed.
var sessionEndTypesWithDuration = map[string]bool{
	"session.end":                 true,
	"db.session.end":              true,
	"windows.desktop.session.end": true,
}

func Activity(ctx context.Context, pool *pgxpool.Pool, f Filter) (format.Result, error) {
	f.Types = activityEventTypes
	rows, err := queryEvents(ctx, pool, f)
	if err != nil {
		return format.Result{}, err
	}

	res := format.Result{Columns: []string{"time", "user", "event_type", "session_id", "duration"}}
	for _, e := range rows {
		duration := ""
		if sessionEndTypesWithDuration[e.Type] {
			duration = rawDuration(e.Raw)
		}
		res.Rows = append(res.Rows, []any{e.Time, e.User, e.Type, e.SessionID, duration})
	}
	return res, nil
}
