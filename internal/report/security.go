package report

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
)

// authAttemptTypes are only interesting here when they failed — a successful
// one is normal activity, covered by Activity. Verified against this
// cluster's real events: a denied `tsh ssh` surfaces as `auth` (not
// `user.login`, which only covers the initial SAML login), and MFA/device
// checks surface separately as `device.authenticate`.
var authAttemptTypes = map[string]bool{
	"user.login":          true,
	"auth":                true,
	"device.authenticate": true,
}

// alwaysShowTypes have no meaningful success/failure split — any occurrence
// is privilege-affecting and worth surfacing.
var alwaysShowTypes = []string{
	"lock.created", "lock.deleted",
	"role.created", "role.updated", "role.deleted",
	"user.create", "user.delete",
}

// Security surfaces failed authentication attempts and privilege-affecting
// changes: lock creation/removal, role edits, and user account lifecycle
// events.
func Security(ctx context.Context, pool *pgxpool.Pool, f Filter) (format.Result, error) {
	for t := range authAttemptTypes {
		f.Types = append(f.Types, t)
	}
	f.Types = append(f.Types, alwaysShowTypes...)
	rows, err := queryEvents(ctx, pool, f)
	if err != nil {
		return format.Result{}, err
	}
	return filterSecurityRows(rows), nil
}

// filterSecurityRows drops successful authentication attempts (normal
// activity, not worth surfacing here) and renders everything else. Split
// out from Security so it's testable with synthetic EventRows, no database
// needed.
func filterSecurityRows(rows []EventRow) format.Result {
	res := format.Result{Columns: []string{"time", "event_type", "actor", "detail", "success"}}
	for _, e := range rows {
		if authAttemptTypes[e.Type] && (e.Success == nil || *e.Success) {
			continue
		}
		detail := rawField(e.Raw, "name")
		success := ""
		if e.Success != nil {
			success = boolString(*e.Success)
		}
		res.Rows = append(res.Rows, []any{e.Time, e.Type, e.User, detail, success})
	}
	return res
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
