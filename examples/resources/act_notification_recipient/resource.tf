data "act_user" "lee" {
  email = "lee@example.com"
}

resource "act_notification_recipient" "platform" {
  name     = "Platform team"
  user_ids = [data.act_user.lee.id]
  emails   = ["platform@example.com"]

  slack_channel {
    integration_id = act_slack_integration.this.id
    channel_id     = "C05PLATGRD2"
  }
}
