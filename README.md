# teleport-audit-report

Audit reporting for a Teleport cluster: session/access activity,
access-request workflow, security/anomalies, and raw compliance export,
backed by a queryable Postgres database fed by Teleport's own supported
audit-event export mechanism.

## How it works

Teleport's [Event Handler plugin](https://goteleport.com/docs/management/export-audit-events/fluentd/)
streams audit events out of the Auth Service via gRPC and forwards them as
JSON over mutual TLS — normally to Fluentd/Logstash for a SIEM. Here it
forwards to **audit-sink**, a small Go service that speaks the same
HTTPS+mTLS contract and writes events into Postgres instead. **audit-report**
is a CLI that queries that Postgres database on demand.

```
event-handler --(gRPC)--> Teleport Auth Service
     |
     | HTTPS + mTLS, POST /events.log, /session.log
     v
audit-sink (Go) --> postgres
                        ^
                        | localhost:5432
                        |
              audit-report CLI (run on demand)
```

Everything runs as a local Docker Compose stack. Event Handler only needs
outbound access to your Teleport proxy; it reaches `audit-sink` over the
Compose network, so nothing needs to be exposed publicly.

## Prerequisites

- Docker and Docker Compose
- Go 1.25+ — `audit-report` isn't containerized (it's meant to run on your
  machine against the published Postgres port), so this is required, not
  optional
- OpenSSL — needed once during setup to decrypt a generated key (see
  `event-handler/README.md`)
- `tsh`/`tctl` logged into the target Teleport cluster, with a role that can
  create bots/tokens/roles (e.g. the built-in `editor` role — the same
  rights `tctl terraform env` itself relies on)
- Terraform >= 1.6

## Setup

1. **Copy `.env.example` to `.env`** and fill in your cluster's proxy
   address, a Postgres password, and matching Event Handler/tbot version
   (default is pinned to 18.6.4 — bump it to track your cluster's version if
   needed; the plugin shouldn't be newer than the Auth Service).

2. **Bootstrap the Teleport role + Machine ID bot** the Event Handler will
   authenticate as:

   ```sh
   cd terraform
   tctl terraform env    # populates TF_TELEPORT_* for this shell
   terraform init
   terraform apply
   terraform output -raw join_token   # save this for the next step
   cd ..
   ```

3. **Generate `tbot/tbot.yaml`** from the join token above — see
   [`tbot/README.md`](tbot/README.md).

4. **Generate the Event Handler's certs and config.** Follow
   [`event-handler/README.md`](event-handler/README.md) — verified against
   the real plugin image — to produce everything else `docker-compose.yml`
   expects to find in `event-handler/`.

5. **Bring up the stack:**

   ```sh
   docker compose up -d --build
   docker compose logs -f tbot event-handler audit-sink
   ```

   Look for `tbot` joining successfully, Event Handler connecting without
   auth errors, and audit-sink logging incoming `POST` requests with `200`
   responses.

## Running reports

`audit-report` connects to Postgres on `localhost:5432` (published by
Compose), so it just runs as a local binary — no need to containerize it.
It reads `DATABASE_URL` from your environment (or pass `--db` directly), so
source `.env` first:

```sh
set -a; source .env; set +a

go run ./cmd/audit-report activity   --from=2026-07-01T00:00:00Z --to=2026-07-03T00:00:00Z
go run ./cmd/audit-report requests   --from=2026-07-01T00:00:00Z --to=2026-07-03T00:00:00Z
go run ./cmd/audit-report security   --from=2026-07-01T00:00:00Z --to=2026-07-03T00:00:00Z
go run ./cmd/audit-report compliance --from=2026-07-01T00:00:00Z --to=2026-07-03T00:00:00Z --user=alice@example.com --format=csv > alice-july.csv
```

Flags across all four subcommands:

| Flag        | Default                  | Notes                                  |
| ----------- | ------------------------ | --------------------------------------- |
| `--from`    | 24h ago                  | RFC3339                                 |
| `--to`      | now                      | RFC3339                                 |
| `--user`    | (all users)              | For `requests`, filters by requester — a request's own review/approval events by a *different* user still count, so its state is never shown incomplete |
| `--format`  | `table`                  | `table`, `csv`, or `json`               |
| `--db`      | `$DATABASE_URL`          | Postgres connection string              |

Or build a binary once: `go build -o audit-report ./cmd/audit-report`.

## Verifying it's actually working

1. Generate some real events against your cluster — `tsh ssh`/`tsh login` a
   couple of times, submit and approve an access request.
2. Confirm rows landed (no local `psql` install needed — this runs it
   inside the `postgres` container):
   ```sh
   docker compose exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
     -c "select event_type, count(*) from events group by 1 order by 2 desc;"
   ```
3. Run each report subcommand and check the output matches what you just
   did — e.g. `requests` should show the approval, `activity` the session.
4. Restart `event-handler` (`docker compose restart event-handler`) and
   re-check the count query — it shouldn't grow (dedup on `uid` via
   `ON CONFLICT DO NOTHING` in `internal/ingest`), and `audit-sink`'s logs
   shouldn't show a retry storm.

## Known gotchas (from Teleport's own docs on this plugin)

- **Respond with exactly `200`.** Some Fluentd-alike receivers return `201`
  for a successful POST; Event Handler treats anything but `200` as a
  failure and retries, duplicating events. `audit-sink` always returns `200`
  on success — don't change this.
- **`--dns-names` must include `audit-sink`** when generating certs, since
  that's the hostname Event Handler connects to over the Compose network
  (not `localhost`, which is `configure`'s default).
- **Signing an identity for a different identity than your own requires
  impersonation rights**, which most admin-ish roles (including the
  built-in `editor`) don't grant — that's why this uses a Machine ID bot
  (`tbot`) instead of a plain `tctl auth sign --user=...` identity file.
  Creating a bot/token is just a resource-create permission, not
  impersonation, and tbot renews its own identity indefinitely once joined.
