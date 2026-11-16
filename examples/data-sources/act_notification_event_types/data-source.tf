data "act_notification_event_types" "all" {}

output "event_types" {
  value = data.act_notification_event_types.all.event_types[*].event_type
}
