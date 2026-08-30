variable "environment" {
  description = "The Datadog environment tag used by the deployed backend."
  type        = string
  default     = "production"
}

variable "service" {
  description = "The Datadog service name used by the Go backend."
  type        = string
  default     = "binary-analysis-api"
}

variable "notification" {
  description = "Optional Datadog notification target, such as @slack-binary-analysis."
  type        = string
  default     = ""
}

variable "public_base_url" {
  description = "Public site origin. Leave empty to create the Synthetic test in a paused state with a placeholder URL."
  type        = string
  default     = "https://recompiler.nisans.dev"
}

variable "synthetics_locations" {
  description = "Datadog managed locations that run the health check."
  type        = set(string)
  default     = ["aws:us-east-1"]
}
