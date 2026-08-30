resource "datadog_monitor" "backend_errors" {
  name    = "Binary analysis API: server errors"
  type    = "log alert"
  message = "The API returned a server error. Inspect the correlated log and APM trace. ${var.notification}"
  query   = "logs(\"service:${var.service} env:${var.environment} @event:http.request.completed @http.status_code:[500 TO 599]\").index(\"*\").rollup(\"count\").last(\"5m\") > 0"

  monitor_thresholds {
    critical = 0
  }

  enable_logs_sample  = true
  include_tags        = true
  notify_audit        = false
  on_missing_data     = "resolve"
  require_full_window = false
  tags                = local.common_tags
}

resource "datadog_monitor" "analysis_latency" {
  name    = "Binary analysis API: high analysis latency"
  type    = "metric alert"
  message = "The p95 analysis time is above two minutes. Check CPU, disk, queue time, PDB parsing, and APM spans. ${var.notification}"
  query   = "percentile(last_15m):p95:binary_analysis.analysis.duration{*} > 120000"

  monitor_thresholds {
    warning  = 90000
    critical = 120000
  }

  evaluation_delay    = 60
  include_tags        = true
  notify_no_data      = false
  require_full_window = false
  tags                = local.common_tags

  depends_on = [datadog_logs_metric.analysis_duration]
}

resource "datadog_monitor" "queue_latency" {
  name    = "Binary analysis API: analysis queue pressure"
  type    = "metric alert"
  message = "The p95 analysis queue wait is above five seconds. The host is receiving more analysis work than its configured concurrency can process. ${var.notification}"
  query   = "percentile(last_10m):p95:binary_analysis.queue.duration{*} > 5000"

  monitor_thresholds {
    warning  = 2000
    critical = 5000
  }

  evaluation_delay    = 60
  include_tags        = true
  notify_no_data      = false
  require_full_window = false
  tags                = local.common_tags

  depends_on = [datadog_logs_metric.queue_duration]
}

resource "datadog_monitor" "host_cpu" {
  name    = "Binary analysis host: high CPU"
  type    = "metric alert"
  message = "Average host CPU use is above 90 percent. Compare this period with analysis throughput and queue time. ${var.notification}"
  query   = "avg(last_10m):100 - avg:system.cpu.idle{*} by {host} > 90"

  monitor_thresholds {
    warning  = 80
    critical = 90
  }

  include_tags        = true
  notify_no_data      = false
  require_full_window = true
  tags                = local.common_tags
}
