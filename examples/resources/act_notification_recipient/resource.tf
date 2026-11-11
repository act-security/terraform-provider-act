data "act_email_integration" "this" {}

resource "act_notification_recipient" "platform" {
  name = "Platform team"

  email {
    integration_id = data.act_email_integration.this.id
    recipients     = ["platform@example.com"]
  }

  slack {
    integration_id = act_slack_integration.this.id
    channel_ids    = ["C05PLATGRD2"]
  }
}
