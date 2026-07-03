# Event Handler bootstrap

Everything in this directory except this file is generated locally and
gitignored (certs, private keys, and the ingestion cursor storage
directory) — regenerate it yourself rather than expecting it in the repo.
The identity file itself lives in a separate Docker volume owned by `tbot`
(see `../tbot/README.md`), not here.

Run this once, from the repo root, after `terraform apply` in
`../terraform` has created the `teleport-event-handler` role/bot:

**Generate the mTLS cert bundle + starter config**, verified against
`teleport-plugin-event-handler:18.6.4` directly — this is the same
`configure` subcommand documented in Teleport's
[Export Audit Events with Fluentd](https://goteleport.com/docs/management/export-audit-events/fluentd/)
guide. `--dns-names` must include `audit-sink`, the Compose service name
the plugin will connect to:

```sh
docker run --rm -v "$(pwd)/event-handler:/opt/teleport-plugin" -w /opt/teleport-plugin \
  public.ecr.aws/gravitational/teleport-plugin-event-handler:${EVENT_HANDLER_VERSION} \
  configure --dns-names=audit-sink,localhost . ${PROXY_ADDR}
```

This writes `ca.crt`/`ca.key`, `server.crt`/`server.key` (audit-sink's TLS
identity), `client.crt`/`client.key` (the plugin's TLS identity),
`fluent.conf` (unused — we don't run Fluentd, delete it), a sample
`teleport-event-handler-role.yaml` (unused — the real role is in
`../terraform/main.tf`, delete it), and `teleport-event-handler.toml`.

Then edit `teleport-event-handler.toml`:

```toml
[forward.fluentd]
url = "https://audit-sink:8443/events.log"
session-url = "https://audit-sink:8443/session.log"

[teleport]
identity = "/identity/identity"   # tbot's shared volume, not a local file
```

Leave `storage` and the cert paths as generated — they're already correct
for how `docker-compose.yml` mounts this directory.

After this, and after generating `../tbot/tbot.yaml` per its README,
`docker compose up` should bring up a working pipeline. See the top-level
README for verification steps.
