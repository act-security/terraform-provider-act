terraform {
  required_providers {
    act = {
      source  = "act-security/act"
      version = "~> 0.3"
    }
  }
}

provider "act" {}
