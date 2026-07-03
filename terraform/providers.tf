terraform {
  required_version = ">= 1.6.0"
  required_providers {
    teleport = {
      source = "terraform.releases.teleport.dev/gravitational/teleport"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

# No static credentials here on purpose: run `tctl terraform env` in this
# shell first (using your own logged-in `tsh` session) to populate the
# TF_TELEPORT_* environment variables the provider reads automatically.
provider "teleport" {}
