package report

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
)

// Compliance returns every event in range, unfiltered by type, with the full
// raw payload attached — the "hand this to an auditor" export. Unlike the
// other reports it does not curate event types since the point is
// completeness, not readability.
func Compliance(ctx context.Context, pool *pgxpool.Pool, f Filter) (format.Result, error) {
	rows, err := queryEvents(ctx, pool, f)
	if err != nil {
		return format.Result{}, err
	}

	res := format.Result{Columns: []string{"time", "event_type", "event_code", "user", "session_id", "success", "raw"}}
	for _, e := range rows {
		success := ""
		if e.Success != nil {
			success = boolString(*e.Success)
		}
		res.Rows = append(res.Rows, []any{e.Time, e.Type, e.Code, e.User, e.SessionID, success, e.Raw})
	}
	return res, nil
}
