resource "datadog_synthetics_test" "health" {
  name      = "Binary analysis API health"
  type      = "api"
  subtype   = "http"
  status    = var.public_base_url == "" ? "paused" : "live"
  message   = "The public API health endpoint is unavailable. ${var.notification}"
  locations = var.synthetics_locations
  tags      = local.common_tags

  request_definition {
    method = "GET"
    url    = "${var.public_base_url == "" ? "https://example.invalid" : trimsuffix(var.public_base_url, "/")}/api/health"
  }

  assertion {
    type     = "statusCode"
    operator = "is"
    target   = "200"
  }

  assertion {
    type     = "responseTime"
    operator = "lessThan"
    target   = "3000"
  }

  options_list {
    tick_every = 300

    retry {
      count    = 2
      interval = 300
    }

    monitor_options {
      renotify_interval = 0
    }
  }
}
