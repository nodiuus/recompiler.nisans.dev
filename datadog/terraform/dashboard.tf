resource "datadog_dashboard_json" "binary_analysis" {
  dashboard = jsonencode({
    title              = "Binary analysis service"
    description        = "API, analysis engine, queue, host, and error telemetry. Managed by Terraform."
    layout_type        = "ordered"
    notify_list        = null
    template_variables = null
    widgets = [
      {
        definition = {
          type      = "query_value"
          title     = "Requests"
          autoscale = true
          precision = 0
          requests  = [{ q = "sum:binary_analysis.http.requests{*}.as_count()", aggregator = "sum" }]
        }
      },
      {
        definition = {
          type      = "query_value"
          title     = "Server errors"
          autoscale = true
          precision = 0
          requests  = [{ q = "sum:binary_analysis.http.errors{*}.as_count()", aggregator = "sum" }]
        }
      },
      {
        definition = {
          type        = "query_value"
          title       = "Analysis p95"
          precision   = 0
          custom_unit = "ms"
          requests    = [{ q = "p95:binary_analysis.analysis.duration{*}", aggregator = "last" }]
        }
      },
      {
        definition = {
          type        = "query_value"
          title       = "Queue p95"
          precision   = 0
          custom_unit = "ms"
          requests    = [{ q = "p95:binary_analysis.queue.duration{*}", aggregator = "last" }]
        }
      },
      {
        definition = {
          type        = "timeseries"
          title       = "Request latency by route"
          show_legend = true
          requests = [
            { q = "p50:binary_analysis.request.duration{*} by {route}", display_type = "line" },
            { q = "p95:binary_analysis.request.duration{*} by {route}", display_type = "line" },
          ]
        }
      },
      {
        definition = {
          type        = "timeseries"
          title       = "Analysis and queue latency"
          show_legend = true
          requests = [
            { q = "p95:binary_analysis.analysis.duration{*}", display_type = "line" },
            { q = "p95:binary_analysis.queue.duration{*}", display_type = "line" },
          ]
        }
      },
      {
        definition = {
          type        = "timeseries"
          title       = "Host CPU"
          show_legend = true
          requests = [
            { q = "100 - avg:system.cpu.idle{*} by {host}", display_type = "line" },
          ]
        }
      },
      {
        definition = {
          type            = "log_stream"
          title           = "Recent backend errors"
          query           = "service:${var.service} env:${var.environment} status:error"
          columns         = ["status", "service", "event", "http.status_code", "error.message", "dd.trace_id"]
          indexes         = ["*"]
          message_display = "expanded-md"
          sort            = { column = "timestamp", order = "desc" }
        }
      },
      {
        definition = {
          type               = "slo"
          title              = "30-day API success SLO"
          slo_id             = datadog_service_level_objective.api_success.id
          view_type          = "detail"
          view_mode          = "overall"
          time_windows       = ["7d", "30d"]
          global_time_target = "0"
          show_error_budget  = true
        }
      },
    ]
  })
}
