variable "slack_bot_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "act_slack_integration" "this" {
  bot_token_wo         = var.slack_bot_token
  bot_token_wo_version = 1
}
