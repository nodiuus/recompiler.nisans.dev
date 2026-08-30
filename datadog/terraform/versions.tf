terraform {
  required_version = ">= 1.5.0"

  required_providers {
    datadog = {
      source  = "DataDog/datadog"
      version = "~> 4.18"
    }
  }
}

# The provider reads DD_API_KEY and DD_APP_KEY from the environment.
provider "datadog" {}
