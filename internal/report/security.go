package report

import (
	"context"
	"fmt"

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
// user.login is the one exception to "hide successful attempts" — see
// filterSecurityRows: a *first-ever-seen* successful login is shown
// regardless, since a brand new identity authenticating is itself a
// signal worth surfacing.
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
	// A human's role grants (or other account attributes) changing —
	// found missing during a live-fire exercise: tbot renews its own
	// bot identity via this same event type every ~20 minutes, which
	// would otherwise swamp this report. See botFilteredTypes below —
	// only non-bot occurrences are shown.
	"user.update",
	// Someone (or something) viewing a session recording. Also emitted
	// internally by this tool's own Event Handler when it exports a
	// recording, hence the same bot filtering as user.update above.
	"session.recording.access",
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

// botFilteredTypes are legitimately noisy when emitted by a bot doing its
// own routine self-management (identity renewal, exporting recordings it
// just streamed) but a real signal when the actor is a human. Detected via
// the `bot_name` field, which was present on every bot-attributed
// occurrence of both event types found during live testing against a real
// cluster — not an assumption.
var botFilteredTypes = map[string]bool{
	"user.update":              true,
	"session.recording.access": true,
}

// isBotEvent prefers the official `user_kind` enum (USER_KIND_BOT = 2,
// api/proto/teleport/legacy/types/events/events.proto:70-83) when present —
// verified against real events that it's populated on both
// botFilteredTypes members. Falls back to the `bot_name` field since
// `user_kind` was only added in Teleport v15 and isn't set on every event
// type (e.g. SSO user.login events never set it, per direct inspection of
// lib/auth/github.go) — bot_name remains the safety net, not a redundant
// check.
func isBotEvent(raw []byte) bool {
	if rawField(raw, "user_kind") == "2" {
		return true
	}
	return rawField(raw, "bot_name") != ""
}

// eventSeverity assigns each event type a rough triage priority. This is a
// judgment call by this tool, not a mapping to any named external standard
// (NIST/CIS/MITRE ATT&CK etc.) — there's no single authoritative source for
// "how severe is a role.created event," so the reasoning for each tier is
// spelled out below rather than implying it was independently verified
// against a framework. Adjust freely if your environment's risk model
// differs.
var eventSeverity = map[string]string{
	// Routine RBAC/authn friction: users trying something they don't (yet)
	// have access to, or a login attempt that didn't complete. Expected,
	// frequent, rarely worth individual investigation. A *successful*
	// user.login is handled separately in filterSecurityRows (HIGH if
	// it's this identity's first one in our data, hidden otherwise).
	"user.login": "LOW",
	"auth":       "LOW",

	// A defensive action the system itself took — the notable event is
	// whatever triggered it, not the lock itself.
	"lock.created": "INFO",

	// Somewhat more specific signals: device trust failing, an account
	// being unlocked, provisioning/deprovisioning, someone reviewing a
	// session recording, and machine/access-list changes that are usually
	// routine but worth tracking.
	"device.authenticate":         "MEDIUM",
	"device.authenticate.confirm": "MEDIUM",
	"lock.deleted":                "MEDIUM",
	"user.create":                 "MEDIUM",
	"user.delete":                 "MEDIUM",
	"session.recording.access":    "MEDIUM",
	"join_token.create":           "MEDIUM",
	"bot.create":                  "MEDIUM",
	"bot.update":                  "MEDIUM",
	"bot.delete":                  "MEDIUM",
	"access_list.create":          "MEDIUM",
	"access_list.update":          "MEDIUM",
	"access_list.delete":          "MEDIUM",

	// A stronger signal: MFA failing after primary auth already succeeded
	// is a plausible credential-stuffing/MFA-bypass indicator, not routine
	// friction. Role/connector/trust changes, a human's own account being
	// updated, and recovery-code activity all directly expand or alter who
	// can do what.
	"mfa_auth_challenge.validate": "HIGH",
	"role.created":                "HIGH",
	"role.updated":                "HIGH",
	"role.deleted":                "HIGH",
	"user.update":                 "HIGH",
	"recovery_code.generated":     "HIGH",
	"recovery_code.used":          "HIGH",
	"trusted_cluster.create":      "HIGH",
	"trusted_cluster.delete":      "HIGH",
	"github.created":              "HIGH",
	"github.updated":              "HIGH",
	"github.deleted":              "HIGH",
	"oidc.created":                "HIGH",
	"oidc.updated":                "HIGH",
	"oidc.deleted":                "HIGH",
	"saml.created":                "HIGH",
	"saml.updated":                "HIGH",
	"saml.deleted":                "HIGH",

	// Cluster-wide changes to what's trusted or how auth policy works at
	// all — the largest possible blast radius this report can surface.
	"auth_preference.update":    "CRITICAL",
	"cert_auth_override.create": "CRITICAL",
	"cert_auth_override.update": "CRITICAL",
	"cert_auth_override.delete": "CRITICAL",
}

func severityOf(eventType string) string {
	if s, ok := eventSeverity[eventType]; ok {
		return s
	}
	return "INFO"
}

// Security surfaces failed authentication attempts, first-time-seen
// successful logins, and privilege-affecting changes: locks,
// role/user/bot/connector/access-list lifecycle, recovery codes, and
// cluster-wide auth policy or CA changes.
func Security(ctx context.Context, pool *pgxpool.Pool, f Filter) (format.Result, error) {
	for t := range authAttemptTypes {
		f.Types = append(f.Types, t)
	}
	f.Types = append(f.Types, alwaysShowTypes...)
	rows, err := queryEvents(ctx, pool, f)
	if err != nil {
		return format.Result{}, err
	}

	firstLogins, err := firstLoginUIDs(ctx, pool)
	if err != nil {
		return format.Result{}, err
	}

	return filterSecurityRows(rows, firstLogins), nil
}

// firstLoginUIDs returns, for every user with at least one successful
// user.login in this tool's own ingested history, the uid of their
// earliest one. "History" here means only what this pipeline has actually
// ingested since it started running — there is no way to know from this
// data alone whether an identity authenticated before ingestion began, so
// an existing user will look "new" exactly once, the first time this tool
// happens to observe them, and never again after. That's the honest
// definition of "first-seen" available here; treat it as "new to us," not
// "new to the cluster."
func firstLoginUIDs(ctx context.Context, pool *pgxpool.Pool) (map[string]string, error) {
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT ON (user_name) user_name, uid
		FROM events
		WHERE event_type = 'user.login' AND success = true AND user_name != ''
		ORDER BY user_name, event_time ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("query first login uids: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var user, uid string
		if err := rows.Scan(&user, &uid); err != nil {
			return nil, fmt.Errorf("scan first login uid: %w", err)
		}
		out[user] = uid
	}
	return out, rows.Err()
}

// filterSecurityRows drops confirmed-successful authentication attempts
// (normal activity, covered by Activity) — except a user.login that is
// this identity's first-ever-seen successful login, which is shown
// regardless — and bot-attributed occurrences of botFilteredTypes.
// Deliberately treats a missing/unknown `success` field as "show it"
// rather than "assume success and hide it" — safer default when we're not
// certain every authAttemptTypes member always carries that field. Split
// out from Security so it's testable with synthetic EventRows, no database
// needed.
func filterSecurityRows(rows []EventRow, firstLoginUID map[string]string) format.Result {
	res := format.Result{Columns: []string{"time", "severity", "event_type", "actor", "detail", "source", "success"}}
	for _, e := range rows {
		isSuccess := e.Success != nil && *e.Success

		if e.Type == "user.login" && isSuccess {
			if e.UID == "" || firstLoginUID[e.User] != e.UID {
				continue // this identity has a successful login before this one, in our data
			}
		} else if authAttemptTypes[e.Type] && isSuccess {
			continue
		}

		if botFilteredTypes[e.Type] && isBotEvent(e.Raw) {
			continue
		}

		detail := rawField(e.Raw, "name")
		severity := severityOf(e.Type)
		if e.Type == "user.login" {
			detail = rawField(e.Raw, "connector_id")
			if isSuccess {
				severity = "HIGH" // this identity's first-ever-seen successful login
			}
		}
		// addr.remote (the literal JSON key — verified against real events,
		// not nested under a sub-object) is where an auth attempt actually
		// came from. Confirmed present on user.login and auth; confirmed
		// ABSENT on device.authenticate — rawField already returns "" for
		// event types that don't carry it, so this is safe to try
		// unconditionally rather than hand-listing which types have it.
		source := rawField(e.Raw, "addr.remote")

		success := ""
		if e.Success != nil {
			success = boolString(*e.Success)
		}
		res.Rows = append(res.Rows, []any{e.Time, severity, e.Type, e.User, detail, source, success})
	}
	return res
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
