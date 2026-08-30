# Datadog setup

This directory contains the Datadog Agent log configuration and Terraform
resources for the binary analysis service.

The application supports these Datadog products:

- Infrastructure Monitoring
- Log Management
- Application Performance Monitoring (APM)
- Continuous Profiler
- Browser Real User Monitoring (RUM)
- Synthetic Monitoring
- Dashboards, monitors, and service-level objectives (SLOs)

## 1. Configure the Agent

Install the Datadog Agent on the computer that runs the backend. Keep the API
key in the Agent configuration. Do not put the API key in a frontend file.

Set these values in C:\ProgramData\Datadog\datadog.yaml:

    logs_enabled: true

    apm_config:
      enabled: true

    tags:
      - env:production
      - service:binary-analysis-api

Copy the included log integration. Run PowerShell as an administrator:

    New-Item -ItemType Directory -Force 'C:\ProgramData\Datadog\conf.d\go.d'
    Copy-Item 'datadog\conf.d\go.d\conf.yaml' 'C:\ProgramData\Datadog\conf.d\go.d\conf.yaml' -Force
    Restart-Service DatadogAgent

Set these backend values for a production deployment:

    DD_TRACE_ENABLED=true
    DD_PROFILING_ENABLED=true
    DD_AGENT_HOST=127.0.0.1
    DD_TRACE_AGENT_PORT=8126
    DD_SERVICE=binary-analysis-api
    DD_ENV=production
    DD_VERSION=your-release-version

Use the same DD_SERVICE, DD_ENV, and DD_VERSION values for each instance of one
release. The backend sends telemetry to the Agent. It does not send the
Datadog API key.

## 2. Configure Browser RUM

Create a Browser RUM application in Datadog. Copy frontend/.env.example to
frontend/.env.local. Add the application ID and RUM client token:

    VITE_DD_RUM_APPLICATION_ID=your-application-id
    VITE_DD_RUM_CLIENT_TOKEN=your-client-token
    VITE_DD_SITE=datadoghq.com
    VITE_DD_SERVICE=binary-analysis-web
    VITE_DD_ENV=production
    VITE_DD_VERSION=your-release-version

The RUM client token is designed for browser use. A Datadog API key is not.
Vite exposes every VITE_ value in the compiled JavaScript.

The frontend allows Datadog trace headers for its configured API origin. If
the frontend and API use different origins, the API proxy must allow the
Datadog and W3C trace headers in its CORS policy.

The RUM configuration uses mask-user-input. Session Replay has a zero sample
rate. The application sends file sizes, operation duration, HTTP status, and
success state for an analysis action. It does not send file names or contents.

## 3. Create the Datadog resources

The Terraform configuration creates these resources:

- Request, success, and server-error counters
- Request, analysis, and queue-time distributions with percentiles
- Server-error, analysis-latency, queue-pressure, and host-CPU monitors
- A 99 percent, 30-day request-success SLO
- A dashboard for traffic, errors, latency, queue time, CPU, logs, and the SLO
- A five-minute public health Synthetic test

Datadog charges for log ingestion, indexed logs, APM, profiling, RUM,
Synthetics, and custom metrics according to the account plan. The six
log-based metrics in this configuration are custom metrics. The request
duration metric groups only by the small, fixed route set. Do not add file
names, function names, addresses, cache IDs, or user IDs as metric tags.

Terraform needs a Datadog API key and application key. Set them only in the
current shell or in a secret manager:

    $env:DD_API_KEY = 'your-api-key'
    $env:DD_APP_KEY = 'your-application-key'

Do not add these values to terraform.tfvars. Copy the example values and apply
the resources:

    Set-Location datadog\terraform
    Copy-Item terraform.tfvars.example terraform.tfvars
    terraform init
    terraform plan
    terraform apply

Set public_base_url to the deployed site origin. Set notification to a Datadog
notification target. Change the monitor thresholds after the service has
enough production data to show its normal latency and queue behavior.

## 4. Verify telemetry

Start the backend and make one analysis request. Then verify these items:

1. The Agent status shows the log file integration.
2. Log Explorer shows service:binary-analysis-api.
3. APM Service Catalog shows binary-analysis-api.
4. A request trace contains queue and analysis engine child spans.
5. A correlated error log opens its trace.
6. Continuous Profiler shows profiles after the first profile interval.
7. RUM Explorer shows binary-analysis-web after a configured browser visit.
8. Synthetic Monitoring shows a successful /api/health test.

The Terraform resources use log fields that the backend emits. Do not rename
event, request.duration_ms, analysis.duration_ms, queue.duration_ms, or the
dd.* correlation fields without an update to terraform/log_metrics.tf.
