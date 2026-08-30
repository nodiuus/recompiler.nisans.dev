locals {
  analysis_log_filter = "service:${var.service} env:${var.environment}"
  common_tags         = ["env:${var.environment}", "service:${var.service}", "managed-by:terraform"]
}

resource "datadog_logs_metric" "http_requests" {
  name = "binary_analysis.http.requests"

  compute {
    aggregation_type = "count"
  }

  filter {
    query = "${local.analysis_log_filter} @event:http.request.completed"
  }
}

resource "datadog_logs_metric" "http_success" {
  name = "binary_analysis.http.success"

  compute {
    aggregation_type = "count"
  }

  filter {
    query = "${local.analysis_log_filter} @event:http.request.completed @http.status_code:[200 TO 499]"
  }
}

resource "datadog_logs_metric" "http_errors" {
  name = "binary_analysis.http.errors"

  compute {
    aggregation_type = "count"
  }

  filter {
    query = "${local.analysis_log_filter} @event:http.request.completed @http.status_code:[500 TO 599]"
  }
}

resource "datadog_logs_metric" "request_duration" {
  name = "binary_analysis.request.duration"

  compute {
    aggregation_type    = "distribution"
    path                = "@request.duration_ms"
    include_percentiles = true
  }

  filter {
    query = "${local.analysis_log_filter} @event:http.request.completed"
  }

  group_by {
    path     = "@http.route"
    tag_name = "route"
  }
}

resource "datadog_logs_metric" "analysis_duration" {
  name = "binary_analysis.analysis.duration"

  compute {
    aggregation_type    = "distribution"
    path                = "@analysis.duration_ms"
    include_percentiles = true
  }

  filter {
    query = "${local.analysis_log_filter} @event:analysis.engine.completed"
  }
}

resource "datadog_logs_metric" "queue_duration" {
  name = "binary_analysis.queue.duration"

  compute {
    aggregation_type    = "distribution"
    path                = "@queue.duration_ms"
    include_percentiles = true
  }

  filter {
    query = "${local.analysis_log_filter} @event:analysis.engine.completed"
  }
}
