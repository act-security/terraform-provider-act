data "act_slack_channel" "security" {
  name = "#security-alerts"
}

output "security_channel_id" {
  value = data.act_slack_channel.security.id
}
