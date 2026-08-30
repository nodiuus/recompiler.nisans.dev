package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	ddhttp "github.com/DataDog/dd-trace-go/contrib/net/http/v2"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
	"github.com/DataDog/dd-trace-go/v2/profiler"
)

type datadogRuntimeConfig struct {
	tracing bool
	service string
	env     string
	version string
}

var datadogRuntime = datadogRuntimeConfig{
	service: "binary-analysis-api",
	env:     "development",
	version: "dev",
}

func startDatadogObservability() func() {
	datadogRuntime.service = environmentOrDefault("DD_SERVICE", "binary-analysis-api")
	datadogRuntime.env = environmentOrDefault("DD_ENV", "development")
	datadogRuntime.version = environmentOrDefault("DD_VERSION", "dev")

	traceStarted := false
	if environmentBoolean("DD_TRACE_ENABLED") {
		if err := tracer.Start(
			tracer.WithService(datadogRuntime.service),
			tracer.WithEnv(datadogRuntime.env),
			tracer.WithServiceVersion(datadogRuntime.version),
			tracer.WithRuntimeMetrics(),
		); err != nil {
			logEvent("warn", "datadog.apm.started", "Datadog APM is unavailable.", map[string]any{
				"error.message": safeLogMessage(err.Error()),
			})
		} else {
			datadogRuntime.tracing = true
			traceStarted = true
			logEvent("info", "datadog.apm.started", "Datadog APM started.", nil)
		}
	}

	profileStarted := false
	if environmentBoolean("DD_PROFILING_ENABLED") {
		options := []profiler.Option{
			profiler.WithService(datadogRuntime.service),
			profiler.WithEnv(datadogRuntime.env),
			profiler.WithVersion(datadogRuntime.version),
			profiler.WithAgentAddr(datadogAgentAddress()),
		}
		if err := profiler.Start(options...); err != nil {
			logEvent("warn", "datadog.profiler.started", "Datadog continuous profiler is unavailable.", map[string]any{
				"error.message": safeLogMessage(err.Error()),
			})
		} else {
			profileStarted = true
			logEvent("info", "datadog.profiler.started", "Datadog continuous profiler started.", nil)
		}
	}

	return func() {
		if profileStarted {
			profiler.Stop()
		}
		if traceStarted {
			tracer.Stop()
		}
	}
}

func wrapDatadogHandler(handler http.Handler) http.Handler {
	if !datadogRuntime.tracing {
		return handler
	}
	return ddhttp.WrapHandler(
		handler,
		datadogRuntime.service,
		"http.request",
		ddhttp.WithResourceNamer(func(request *http.Request) string {
			return request.Method + " " + logRoute(request.URL.Path)
		}),
		ddhttp.WithIgnoreRequest(func(request *http.Request) bool {
			return request.URL.Path == "/api/health"
		}),
	)
}

func startObservedSpan(ctx context.Context, operation, resource string, tags map[string]any) (*tracer.Span, context.Context) {
	if !datadogRuntime.tracing {
		return nil, ctx
	}
	options := []tracer.StartSpanOption{
		tracer.ResourceName(resource),
		tracer.ServiceName(datadogRuntime.service),
	}
	for key, value := range tags {
		options = append(options, tracer.Tag(key, value))
	}
	return tracer.StartSpanFromContext(ctx, operation, options...)
}

func finishObservedSpan(span *tracer.Span, err error) {
	if span == nil {
		return
	}
	if err != nil {
		span.Finish(tracer.WithError(err))
		return
	}
	span.Finish()
}

func addDatadogCorrelation(ctx context.Context, record map[string]any) {
	record["dd.service"] = datadogRuntime.service
	record["dd.env"] = datadogRuntime.env
	record["dd.version"] = datadogRuntime.version
	if !datadogRuntime.tracing || ctx == nil {
		return
	}
	span, ok := tracer.SpanFromContext(ctx)
	if !ok {
		return
	}
	spanContext := span.Context()
	record["dd.trace_id"] = strconv.FormatUint(spanContext.TraceIDLower(), 10)
	record["dd.span_id"] = strconv.FormatUint(spanContext.SpanID(), 10)
}

func environmentOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func environmentBoolean(name string) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return false
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		log.Printf("ignoring invalid %s=%q; expected true or false", name, value)
		return false
	}
	return enabled
}

func datadogAgentAddress() string {
	host := environmentOrDefault("DD_AGENT_HOST", "127.0.0.1")
	port := environmentOrDefault("DD_TRACE_AGENT_PORT", "8126")
	return fmt.Sprintf("%s:%s", host, port)
}
