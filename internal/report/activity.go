package report

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
)

// activityEventTypes covers session lifecycle events across every protocol
// Teleport proxies. session.end (and its per-protocol equivalents) carry
// duration info; session.start/kube.request don't but are included so the
// report shows activity that hasn't ended yet or has no explicit "end" event.
var activityEventTypes = []string{
	"session.start", "session.end",
	"db.session.start", "db.session.end",
	"app.session.start", "app.session.end",
	"kube.request",
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
		if e.Type == "session.end" || e.Type == "db.session.end" || e.Type == "app.session.end" {
			duration = rawDuration(e.Raw)
		}
		res.Rows = append(res.Rows, []any{e.Time, e.User, e.Type, e.SessionID, duration})
	}
	return res, nil
}
