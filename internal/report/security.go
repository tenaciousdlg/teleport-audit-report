package report

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
)

// authAttemptTypes are only interesting here when they failed — a successful
// one is normal activity, covered by Activity. Verified against this
// cluster's real events (a denied `tsh ssh` surfaces as `auth`, code
// T3007W "Auth Attempt Failed" per
// https://goteleport.com/docs/reference/audit-events/ — not `user.login`,
// which only covers the initial SAML login) and against
// gravitational/teleport's lib/events/api.go for the exact constants.
//
// device.authenticate.confirm and mfa_auth_challenge.validate are included
// on the same "only show if not a confirmed success" basis, even though
// this tool hasn't independently verified they carry a literal `success`
// JSON field — see filterSecurityRows' comment on why that's safe either
// way.
var authAttemptTypes = map[string]bool{
	"user.login":                  true,
	"auth":                        true,
	"device.authenticate":         true,
	"device.authenticate.confirm": true,
	"mfa_auth_challenge.validate": true,
}

// alwaysShowTypes have no meaningful success/failure split — any occurrence
// is privilege- or trust-affecting and worth surfacing. Every constant here
// is verified directly against gravitational/teleport's lib/events/api.go
// (file:line noted per group; line numbers are from the checkout used
// during this research pass and may drift with upstream changes).
var alwaysShowTypes = []string{
	// Locking/unlocking a user or role (api.go ~256-ish "lock.*" block).
	"lock.created", "lock.deleted",
	// Role and local user lifecycle (api.go ~ "role."/"user." CRUD block).
	"role.created", "role.updated", "role.deleted",
	"user.create", "user.delete",
	// Account recovery — generating or using a recovery code bypasses
	// normal MFA (api.go:601,603).
	"recovery_code.generated", "recovery_code.used",
	// Cluster-wide auth policy changes, e.g. disabling a second factor
	// requirement (api.go:802).
	"auth_preference.update",
	// CA overrides affect what's trusted to sign certs cluster-wide
	// (api.go:1063,1066,1072).
	"cert_auth_override.create", "cert_auth_override.update", "cert_auth_override.delete",
	// Trust relationships and join infrastructure: a new trusted cluster or
	// join token materially expands who/what can authenticate
	// (api.go:365,367,375).
	"trusted_cluster.create", "trusted_cluster.delete",
	"join_token.create",
	// Machine ID bot lifecycle — bots are non-human identities with their
	// own role grants (api.go:693,695,697,699).
	"bot.create", "bot.update", "bot.delete",
	// SSO connector changes reroute how users authenticate entirely
	// (api.go:387-403).
	"github.created", "github.updated", "github.deleted",
	"oidc.created", "oidc.updated", "oidc.deleted",
	"saml.created", "saml.updated", "saml.deleted",
	// Access list CRUD — access lists grant roles to their members, so
	// changing one is a privilege change (api.go:746,749,752).
	"access_list.create", "access_list.update", "access_list.delete",
}

// Security surfaces failed authentication attempts and privilege-affecting
// changes: locks, role/user/bot/connector/access-list lifecycle, recovery
// codes, and cluster-wide auth policy or CA changes.
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

// filterSecurityRows drops only *confirmed* successful authentication
// attempts (normal activity, covered by Activity) and renders everything
// else. Deliberately treats a missing/unknown `success` field as "show it"
// rather than "assume success and hide it" — safer default when we're not
// certain every authAttemptTypes member always carries that field. Split
// out from Security so it's testable with synthetic EventRows, no database
// needed.
func filterSecurityRows(rows []EventRow) format.Result {
	res := format.Result{Columns: []string{"time", "event_type", "actor", "detail", "success"}}
	for _, e := range rows {
		if authAttemptTypes[e.Type] && e.Success != nil && *e.Success {
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
