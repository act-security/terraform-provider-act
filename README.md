# terraform-provider-act

The Terraform and OpenTofu provider for [Act Security](https://act.security). It manages Act deployments for AWS, Azure and GCP as code, authenticated with an Act API key.

Published as `act-security/act` on registry.terraform.io and registry.opentofu.org.

## Usage

```hcl
terraform {
  required_providers {
    act = {
      source = "act-security/act"
    }
  }
}

provider "act" {}

data "act_current_identity" "this" {}
```

Create an API key in the Act console under Settings → API keys and set `ACT_CLIENT_ID` and `ACT_CLIENT_SECRET` from it. The provider learns the tenant from the key and asks the Act STS which regional API serves it, so there is no tenant ID, region or endpoint to configure.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Mozilla Public License 2.0. See [LICENSE](LICENSE).
