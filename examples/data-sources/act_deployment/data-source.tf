data "act_deployment" "production" {
  cloud  = "aws"
  target = "111111111111"
}

check "act_production_connected" {
  assert {
    condition     = data.act_deployment.production.status == "active"
    error_message = "Act cannot scan the production account."
  }
}
