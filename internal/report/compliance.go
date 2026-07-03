package report

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
)

// Compliance returns every event in range, unfiltered by type — the "hand
// this to an auditor" export. Unlike the other reports it does not curate
// event types since the point is completeness, not readability.
//
// includeRaw controls whether the full JSON payload is attached as its own
// column. A single-line JSON blob per row is unreadable in a terminal
// table, so callers should pass false for table output by default and only
// set it true on explicit request (e.g. --raw) or for csv/json output,
// where completeness is the actual point.
func Compliance(ctx context.Context, pool *pgxpool.Pool, f Filter, includeRaw bool) (format.Result, error) {
	rows, err := queryEvents(ctx, pool, f)
	if err != nil {
		return format.Result{}, err
	}

	columns := []string{"time", "event_type", "event_code", "user", "detail", "session_id", "success"}
	if includeRaw {
		columns = append(columns, "raw")
	}
	res := format.Result{Columns: columns}
	for _, e := range rows {
		success := ""
		if e.Success != nil {
			success = boolString(*e.Success)
		}
		row := []any{e.Time, e.Type, e.Code, actorOf(e.User, e.Raw), complianceDetail(e.Raw), e.SessionID, success}
		if includeRaw {
			row = append(row, e.Raw)
		}
		res.Rows = append(res.Rows, row)
	}
	return res, nil
}

// actorOf falls back to the raw event's `user_name`/`reviewer` fields when
// the database's own `user_name` column is empty. `internal/ingest`'s
// actor() extraction now also checks both (see its doc comment for the two
// real gaps that found: bot.join's actor lives under `user_name`,
// access_request.review's under `reviewer`, neither under `user`/
// `identity.user`), so this only matters for rows ingested before that fix
// shipped — the DB column itself was already wrong for them, and dedup on
// `uid` means they'll never be re-ingested. New rows are correct at the
// column level, and this fallback becomes a no-op for them.
func actorOf(user string, raw []byte) string {
	if user != "" {
		return user
	}
	if v := rawField(raw, "user_name"); v != "" {
		return v
	}
	return rawField(raw, "reviewer")
}

// complianceDetail surfaces one "what happened" field per row, same idea as
// security's detail column but generalized across compliance's full
// unfiltered event set instead of a fixed list of types. Tried in order,
// first hit wins — verified against real captured events for `name`
// (role/lock/etc.), `connector_id`/`connector` (logins, user.update),
// `cert_type` (cert.create), and `method` (bot.join's join method, e.g.
// "kubernetes"); resourceOf's fields are cited against
// api/proto/teleport/legacy/types/events/events.proto per activity.go.
func complianceDetail(raw []byte) string {
	for _, key := range []string{"name", "connector_id", "connector", "cert_type", "method"} {
		if v := rawField(raw, key); v != "" {
			return v
		}
	}
	return resourceOf(raw)
}
