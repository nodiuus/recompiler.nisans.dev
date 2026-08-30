output "dashboard_url" {
  description = "The Datadog dashboard URL."
  value       = datadog_dashboard_json.binary_analysis.url
}

output "api_slo_id" {
  description = "The API success SLO ID."
  value       = datadog_service_level_objective.api_success.id
}

output "synthetic_test_id" {
  description = "The public health check test ID."
  value       = datadog_synthetics_test.health.id
}
