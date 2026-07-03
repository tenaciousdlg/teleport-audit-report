# What each report covers, and why

Every report queries the same `events` table (see `internal/db/schema.sql`)
— the difference between `activity`, `requests`, `security`, and
`compliance` is which Teleport audit event types each one curates, and how
it interprets them. This doc explains that curation and cites where each
claim comes from: Teleport's own source
([gravitational/teleport](https://github.com/gravitational/teleport),
specifically `lib/events/api.go` for event type constants and
`api/proto/teleport/legacy/types/events/events.proto` for field shapes) and
its published docs (mainly
[goteleport.com/docs/reference/audit-events](https://goteleport.com/docs/reference/audit-events/)).
Where something couldn't be verified against either source, that's called
out explicitly rather than presented as fact — see the code comments in
`internal/report/*.go` for the same citations at the point they're used.

## `activity` — session/access activity

**Use it to answer:** who accessed what, when, and for how long, across
every protocol Teleport proxies.

Covers SSH/Kubernetes exec sessions (`session.start`, `session.end`,
`session.join`, `session.leave`, plus in-session actions `exec`, `scp`,
`sftp`), database sessions and top-level queries (`db.session.start`,
`db.session.end`, `db.session.query`, `db.session.query.failed`),
application access (`app.session.start`, `app.session.end`), Kubernetes API
requests (`kube.request`), Windows desktop/RDP sessions
(`windows.desktop.session.start`, `windows.desktop.session.end`), and MCP
sessions (`mcp.session.start`, `mcp.session.end`).

**Deliberately excluded:** BPF-based enhanced session recording events
(`session.command`, `session.network`, `session.disk`) and per-statement
database query capture (`db.session.postgres.statements.execute` and
similar). These are forensic, per-command/per-syscall/per-query detail —
including them would make a routine session look far noisier than it is.
They're still available, unfiltered, via `compliance`.

**Duration** is computed by subtracting `session_start` from
`session_stop` on the session's end event. This only works for
`session.end`, `db.session.end`, and `windows.desktop.session.end` —
confirmed via `events.proto` that these three carry both timestamp fields.
`app.session.end` does not: Teleport's own source documents, in
`lib/events/api.go`'s `SessionRecordingEvents` list comment, that "TCP
application sessions emit `AppSessionEndEvent` but produce no
recordings" — there's nothing to compute a duration from. There is no
native numeric `duration` field on any of these event types (a claim this
tool's code briefly and incorrectly assumed before this was checked
directly against the proto source) — timestamp subtraction is the only
correct method.

## `requests` — access-request lifecycle

**Use it to answer:** who asked for elevated access, who reviewed it, and
how long that took — a request's full story in one row instead of scattered
across several audit log lines.

Covers `access_request.create`, `access_request.update`,
`access_request.review`, `access_request.expire`, and
`access_request.delete` (`lib/events/api.go:206-214`; create/update/review
are also documented at
[the audit events reference](https://goteleport.com/docs/reference/audit-events/)).
`access_request.search` is deliberately excluded — it's emitted for
resource-search UI queries, not a lifecycle transition.

Each request's events are grouped by request ID and folded into one row:
requester, requested roles, the stated `reason` (if given), reviewer(s),
final `state`, and time-to-decision. Field names — `id`, `roles`, `reason`,
`reviewer`, `state`, `proposed_state` — are confirmed against the
`AccessRequestCreate` proto message
(`api/proto/teleport/legacy/types/events/events.proto:1588-1683`), which is
the shared struct behind the create/update/review event variants.

**A request's `state` reflects the latest event seen in your queried time
window, not a permanently frozen outcome.** An approved request that later
expires will show as `EXPIRED`, not `APPROVED`, once your `--to` extends
past its `access_request.expire` event — that's an accurate reflection of
what actually happened (it was approved, used, and then its access window
ended), not a bug losing the approval.

**`--user` filters by requester, applied after aggregation, not before.**
A request's create event is logged under the requester but its review
events are logged under the reviewer — filtering the underlying events by
one user before aggregating would silently drop the other's event for the
same request, making an actually-approved request look stuck at `PENDING`.
See `internal/report/requests.go`'s `aggregateRequests`/`buildRequestsResult`
split and the regression tests in `requests_test.go`.

## `security` — failed authentication and privilege-affecting changes

**Use it to answer:** did anyone fail to get in, and did anyone change who
can get in or what they can do.

Two categories, handled differently:

**Authentication attempts** (`user.login`, `auth`, `device.authenticate`,
`device.authenticate.confirm`, `mfa_auth_challenge.validate`) are only
shown when *not* a confirmed success — a successful login is normal
activity, not a security event. Note that a denied action (e.g. `tsh ssh`
to a node you don't have a role for) surfaces as event type `auth`, code
`T3007W` ("Auth Attempt Failed"), **not** `user.login` — `user.login`
covers only the initial SAML/OIDC/local login, confirmed at
[the audit events reference](https://goteleport.com/docs/reference/audit-events/)
and by the `AuthAttempt` emission call site at `lib/srv/authhandlers.go:483-484`
in the Teleport source. A missing/unknown `success` field is treated as
"show it," not "assume success and hide it" — safer given this tool hasn't
independently confirmed every one of these event types always carries that
field.

**Privilege- and trust-affecting changes** are always shown, since they
have no meaningful success/failure split — any occurrence is worth
knowing about:
- Locking/unlocking a user (`lock.created`, `lock.deleted`)
- Role and local user lifecycle (`role.created/updated/deleted`,
  `user.create/delete`)
- Account recovery (`recovery_code.generated`, `recovery_code.used`) —
  bypasses normal MFA
- Cluster-wide auth policy changes (`auth_preference.update`), e.g.
  disabling a second-factor requirement
- CA overrides (`cert_auth_override.create/update/delete`) — affects what's
  trusted to sign certificates cluster-wide
- Trust and join infrastructure (`trusted_cluster.create/delete`,
  `join_token.create`) — expands who/what can authenticate
- Machine ID bot lifecycle (`bot.create/update/delete`) — bots are
  non-human identities with their own role grants
- SSO connector changes (`github.*`, `oidc.*`, `saml.*` `.created/updated/deleted`)
  — reroutes how users authenticate entirely
- Access list changes (`access_list.create/update/delete`) — access lists
  grant roles to their members

All of the above are verified event-type constants from
`lib/events/api.go` (exact line numbers are in the code comments in
`internal/report/security.go`, since line numbers drift with upstream
changes). This selection is also consistent with Teleport's own published
guidance on what to monitor: Identity Security's alerting
([goteleport.com/docs/identity-security/usage/alerts](https://goteleport.com/docs/identity-security/usage/alerts/))
lists "unusual authentication patterns, privilege escalations,
configuration changes that affect security, account compromises" as its
alert categories, and specifically calls out "authentication without MFA
for local accounts" and "unusual authentication failure patterns" as
triggers — the same shape of signal this report curates.

## `compliance` — raw, filtered export

**Use it to answer:** "give me everything for this time range/user" — no
curation, no event-type filter, just the full JSON payload alongside the
common indexed fields. This is the "hand it to an auditor" report, and also
the fallback for anything the other three reports intentionally leave out
(enhanced session recording detail, per-statement query capture, event
types not yet covered by this tool at all).

## `--watch`: live mode vs. a point-in-time report

Every report defaults to a single point-in-time query over `--from`..`--to`.
Add `--watch` to instead poll on an interval (`--interval`, default 5s) and
re-render continuously against a `--to` that keeps advancing to "now" —
useful when you want to *watch something happen* rather than look back at
what already did:

- `audit-report security --watch` while investigating a live incident, to
  see new failures/lockouts/role changes as they land instead of re-running
  the command
- `audit-report requests --watch` while waiting on an access request you
  just submitted, to see the moment it's reviewed
- `audit-report activity --watch` to eyeball who's actively on the cluster
  right now

It re-queries and fully reprints the whole window every tick rather than
diffing/tailing individual events — deliberately, for robustness (see
`watchLoop`'s doc comment in `cmd/audit-report/main.go` for the tradeoff
against Postgres `LISTEN`/`NOTIFY`). Keep `--from` recent when watching so
each refresh stays a reasonable size.

## Sources

- Teleport audit event reference: <https://goteleport.com/docs/reference/audit-events/>
- Identity Security alerting (what Teleport recommends monitoring):
  <https://goteleport.com/docs/identity-security/usage/alerts/>
- Access monitoring / Privileged Access Report:
  <https://goteleport.com/docs/identity-governance/access-monitoring/>
- Event type constants: `lib/events/api.go` in
  [gravitational/teleport](https://github.com/gravitational/teleport)
- Event field shapes: `api/proto/teleport/legacy/types/events/events.proto`
  in the same repo
