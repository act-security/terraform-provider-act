data "act_user" "lee" {
  email = "lee@example.com"
}

output "lee_user_id" {
  value = data.act_user.lee.id
}
