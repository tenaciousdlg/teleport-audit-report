# Event Handler bootstrap

Everything in this directory except this file is generated locally and
gitignored (certs, private keys, and the ingestion cursor storage
directory) — regenerate it yourself rather than expecting it in the repo.
The identity file itself lives in a separate Docker volume owned by `tbot`
(see `../tbot/README.md`), not here.

Run this once, from the repo root, after `terraform apply` in
`../terraform` has created the `teleport-event-handler` role/bot:

1. **Generate the mTLS cert bundle + starter config**, verified against
   `teleport-plugin-event-handler:18.6.4` directly — this is the same
   `configure` subcommand documented in Teleport's
   [Export Audit Events with Fluentd](https://goteleport.com/docs/management/export-audit-events/fluentd/)
   guide. `--dns-names` must include `audit-sink`, the Compose service name
   the plugin will connect to:

   ```sh
   set -a; source .env; set +a
   docker run --rm -v "$(pwd)/event-handler:/opt/teleport-plugin" -w /opt/teleport-plugin \
     public.ecr.aws/gravitational/teleport-plugin-event-handler:${EVENT_HANDLER_VERSION} \
     configure --dns-names=audit-sink,localhost . ${PROXY_ADDR}
   ```

   This writes `ca.crt`/`ca.key`, `server.crt`/`server.key` (audit-sink's TLS
   identity), `client.crt`/`client.key` (the plugin's TLS identity),
   `fluent.conf`, a sample `teleport-event-handler-role.yaml` (unused — the
   real role is in `../terraform/main.tf`), and `teleport-event-handler.toml`.

2. **Decrypt `server.key`.** `configure` generates it as a
   passphrase-protected legacy PEM key, which Go's TLS library (used by
   `audit-sink`) cannot load directly — `audit-sink` will crash-loop with
   `tls: failed to parse private key` if you skip this. The passphrase is
   in the `fluent.conf` you just generated (grep it out before deleting
   that file in the next step):

   ```sh
   PASSPHRASE=$(grep private_key_passphrase event-handler/fluent.conf | sed 's/.*"\(.*\)".*/\1/')
   openssl rsa -in event-handler/server.key -out /tmp/server-decrypted.key -passin "pass:${PASSPHRASE}"
   mv /tmp/server-decrypted.key event-handler/server.key
   ```

   Decrypt to a temp file and `mv` it into place — don't point `-out` at the
   same path as `-in`; openssl can truncate the input while still reading it.

3. **Delete the now-unused generated files:**

   ```sh
   rm -f event-handler/fluent.conf event-handler/teleport-event-handler-role.yaml
   ```

   (We don't run Fluentd, and the real role/bot live in Terraform, not this
   sample YAML.)

4. **Point the generated config at audit-sink.** `configure` defaults
   `[forward.fluentd]` to `https://localhost:8888/...` and `[teleport]`
   to a local `identity` file; edit `teleport-event-handler.toml`:

   ```toml
   [forward.fluentd]
   url = "https://audit-sink:8443/events.log"
   session-url = "https://audit-sink:8443/session.log"

   [teleport]
   identity = "/identity/identity"   # tbot's shared volume, not a local file
   ```

   Leave `storage` and the cert paths as generated — they're already correct
   for how `docker-compose.yml` mounts this directory.

If regenerating this bundle later (e.g. to rotate certs), delete the
*entire* directory contents first and redo all four steps in one pass.
Regenerating `configure` output while some files (like `server.crt`) still
exist from a previous run reuses them instead of creating a matching set —
if you'd also deleted `ca.key` in between, you can end up with a CA that
doesn't match the leftover certs, and a `fluent.conf` passphrase that
doesn't match the leftover key.

After this, and after generating `../tbot/tbot.yaml` per its README,
`docker compose up` should bring up a working pipeline. See the top-level
README for verification steps.
