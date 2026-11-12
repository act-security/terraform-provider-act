data "act_aws_onboarding_parameters" "this" {
  account_id = "111111111111"
}

resource "aws_iam_role" "act" {
  name               = data.act_aws_onboarding_parameters.this.role_name
  assume_role_policy = data.act_aws_onboarding_parameters.this.assume_role_policy_json
}

resource "aws_iam_role_policy_attachment" "act" {
  for_each   = toset(data.act_aws_onboarding_parameters.this.managed_policy_arns)
  role       = aws_iam_role.act.name
  policy_arn = each.value
}

resource "aws_iam_role_policy" "act" {
  for_each = data.act_aws_onboarding_parameters.this.custom_policy_documents
  role     = aws_iam_role.act.name
  name     = each.key
  policy   = each.value
}

resource "act_aws_account_deployment" "this" {
  deployment_id           = data.act_aws_onboarding_parameters.this.deployment_id
  account_id              = "111111111111"
  role_arn                = aws_iam_role.act.arn
  external_id_key_version = data.act_aws_onboarding_parameters.this.external_id_key_version
  tags                    = { team = "platform" }

  depends_on = [aws_iam_role_policy_attachment.act, aws_iam_role_policy.act]
}
