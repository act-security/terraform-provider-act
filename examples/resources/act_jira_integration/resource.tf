variable "jira_api_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "act_jira_integration" "this" {
  base_url             = "https://acme.atlassian.net"
  email                = "act-bot@acme.com"
  api_token_wo         = var.jira_api_token
  api_token_wo_version = 1
}
