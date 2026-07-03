output "bot_name" {
  description = "Machine ID bot the Event Handler joins as"
  value       = teleport_bot.event_handler.metadata.name
}

output "join_token" {
  description = "Provision token name tbot uses to join (see ../event-handler/README.md)"
  value       = teleport_provision_token.event_handler.metadata.name
  sensitive   = true
}
