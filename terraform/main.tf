# Minimal-scope role + Machine ID bot for the Teleport Event Handler plugin.
#
# The role mirrors exactly what `teleport-plugin-event-handler configure`
# generates as its sample role (verified by running the real 18.6.4 image) —
# read-only on audit events and session recordings, nothing else.
#
# The plugin authenticates via a bot rather than a plain local user +
# `tctl auth sign`: creating a bot/token only needs resource-create rights
# (which `editor` already has — the same rights `tctl terraform env` uses to
# bootstrap itself), not impersonation. tbot then keeps the identity file
# renewed on its own for as long as it runs, so there's no manual re-signing
# step and no temporary RBAC changes to anyone's account.

resource "teleport_role" "event_handler" {
  version = "v4"
  metadata = {
    name        = "teleport-event-handler"
    description = "Read-only audit event/session access for the audit-report Event Handler"
  }
  spec = {
    allow = {
      rules = [
        { resources = ["event", "session"], verbs = ["list", "read"] },
      ]
    }
  }
}

resource "teleport_bot" "event_handler" {
  metadata = {
    name = "event-handler"
  }
  spec = {
    roles = [teleport_role.event_handler.id]
  }
}

# Token join: simplest bootstrap for a bot running outside any cloud/k8s
# environment tbot could otherwise attest against. It's single-purpose (only
# usable to join as this bot) and only needed once — tbot doesn't reuse it
# after the initial join, it renews via its own certs from then on.
#
# The token's name is the join secret for this method, so it must be
# unguessable rather than a readable label (same pattern as rev-tech's
# modules/machineid-bot random_string.bot_token).
resource "random_string" "join_token" {
  length  = 32
  special = false
}

resource "teleport_provision_token" "event_handler" {
  version = "v2"
  metadata = {
    name = random_string.join_token.result
  }
  spec = {
    roles       = ["Bot"]
    bot_name    = teleport_bot.event_handler.metadata.name
    join_method = "token"
  }
}
