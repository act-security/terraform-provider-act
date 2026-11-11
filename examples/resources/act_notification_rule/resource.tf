data "act_email_integration" "this" {}

data "act_slack_channel" "security" {
  name = "#security-alerts"
}

resource "act_notification_rule" "simulations" {
  name        = "Policy simulations finished"
  event_types = ["simulation.finished", "policy.drift_detected"]

  condition {
    event_type = "simulation.finished"
    field      = "source"
    values     = ["policy_mgmt"]
  }

  email {
    integration_id = data.act_email_integration.this.id
    recipients     = ["secops@example.com"]
  }

  slack {
    integration_id = act_slack_integration.this.id
    channel_ids    = [data.act_slack_channel.security.id]
  }

  recipient_ids = [act_notification_recipient.platform.id]
}
