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

	columns := []string{"time", "event_type", "event_code", "user", "session_id", "success"}
	if includeRaw {
		columns = append(columns, "raw")
	}
	res := format.Result{Columns: columns}
	for _, e := range rows {
		success := ""
		if e.Success != nil {
			success = boolString(*e.Success)
		}
		row := []any{e.Time, e.Type, e.Code, e.User, e.SessionID, success}
		if includeRaw {
			row = append(row, e.Raw)
		}
		res.Rows = append(res.Rows, row)
	}
	return res, nil
}
