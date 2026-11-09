terraform {
  required_providers {
    act = {
      source  = "act-security/act"
      version = "~> 0.2"
    }
  }
}

provider "act" {}
