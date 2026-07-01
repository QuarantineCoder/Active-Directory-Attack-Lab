terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4"
    }
  }
}

provider "azurerm" {
  # subscription_id comes from the ARM_SUBSCRIPTION_ID env var, so the ID
  # never lands in git. Run: export ARM_SUBSCRIPTION_ID=<your-sub-id>

  # Don't bulk-register every Azure resource provider. Register only the ones
  # each resource needs, by hand (e.g. `az provider register --namespace
  # Microsoft.OperationalInsights`). Least-privilege and explicit.
  resource_provider_registrations = "none"

  features {}
}