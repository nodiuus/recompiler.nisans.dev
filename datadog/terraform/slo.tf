resource "datadog_service_level_objective" "api_success" {
  name        = "Binary analysis API successful requests"
  type        = "metric"
  description = "The percentage of API requests that do not return a 5xx response."

  query {
    numerator   = "sum:binary_analysis.http.success{*}.as_count()"
    denominator = "sum:binary_analysis.http.requests{*}.as_count()"
  }

  thresholds {
    timeframe = "7d"
    target    = 99.0
    warning   = 99.5
  }

  thresholds {
    timeframe = "30d"
    target    = 99.0
    warning   = 99.5
  }

  timeframe         = "30d"
  target_threshold  = 99.0
  warning_threshold = 99.5
  tags              = local.common_tags

  depends_on = [
    datadog_logs_metric.http_requests,
    datadog_logs_metric.http_success,
  ]
}
