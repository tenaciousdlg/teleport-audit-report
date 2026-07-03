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

// resourceFields are the per-protocol fields that identify *which* resource
// a session was against — session_id identifies the session, not what it
// was to. Exactly one of these is populated on any given row, so trying
// them in order and taking the first hit is safe. Verified against
// api/proto/teleport/legacy/types/events/events.proto in
// gravitational/teleport: `server_hostname` (ServerMetadata, session.start/
// end/leave, exec/scp/sftp), `db_service` (DatabaseMetadata,
// db.session.start/end/query), `app_name` (AppMetadata — also covers
// mcp.session.* rows, since Teleport models MCP servers as application
// resources sharing the same metadata), `kubernetes_cluster`
// (KubernetesClusterMetadata, kube.request), and `desktop_name`
// (WindowsDesktopSessionStart). This cluster's own captured events only
// exercise server_hostname and app_name so far — the other three are cited
// against the proto, not independently observed here.
var resourceFields = []string{"server_hostname", "db_service", "app_name", "kubernetes_cluster", "desktop_name"}

func resourceOf(raw []byte) string {
	for _, key := range resourceFields {
		if v := rawField(raw, key); v != "" {
			return v
		}
	}
	return ""
}

func Activity(ctx context.Context, pool *pgxpool.Pool, f Filter) (format.Result, error) {
	f.Types = activityEventTypes
	rows, err := queryEvents(ctx, pool, f)
	if err != nil {
		return format.Result{}, err
	}
	return activityResult(rows), nil
}

// activityResult builds the activity report's Result from already-queried
// rows — split out from Activity so it's testable with synthetic EventRows,
// no database needed (same pattern as security.go's filterSecurityRows).
func activityResult(rows []EventRow) format.Result {
	res := format.Result{Columns: []string{"time", "user", "event_type", "resource", "session_id", "duration"}}
	for _, e := range rows {
		duration := ""
		if sessionEndTypesWithDuration[e.Type] {
			duration = rawDuration(e.Raw)
		}
		res.Rows = append(res.Rows, []any{e.Time, e.User, e.Type, resourceOf(e.Raw), e.SessionID, duration})
	}
	return res
}
