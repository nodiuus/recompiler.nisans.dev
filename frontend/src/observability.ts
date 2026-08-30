import { datadogRum } from "@datadog/browser-rum";

const applicationId = import.meta.env.VITE_DD_RUM_APPLICATION_ID?.trim();
const clientToken = import.meta.env.VITE_DD_RUM_CLIENT_TOKEN?.trim();
const apiBase = (import.meta.env.VITE_API_URL ?? "").replace(/\/$/, "");
const rumEnabled = Boolean(applicationId && clientToken);

function sampleRate(name: string, fallback: number): number {
  const value = Number(import.meta.env[name]);
  return Number.isFinite(value) ? Math.min(100, Math.max(0, value)) : fallback;
}

if (rumEnabled) {
  datadogRum.init({
    applicationId,
    clientToken,
    site: import.meta.env.VITE_DD_SITE?.trim() || "datadoghq.com",
    service: import.meta.env.VITE_DD_SERVICE?.trim() || "binary-analysis-web",
    env: import.meta.env.VITE_DD_ENV?.trim() || "development",
    version: import.meta.env.VITE_DD_VERSION?.trim() || "dev",
    sessionSampleRate: sampleRate("VITE_DD_SESSION_SAMPLE_RATE", 100),
    sessionReplaySampleRate: 0,
    traceSampleRate: sampleRate("VITE_DD_TRACE_SAMPLE_RATE", 100),
    trackUserInteractions: true,
    trackResources: true,
    trackLongTasks: true,
    defaultPrivacyLevel: "mask-user-input",
    allowedTracingUrls: [apiBase || window.location.origin],
  });
}

export function recordRumAction(name: string, context: Record<string, unknown>): void {
  if (rumEnabled) datadogRum.addAction(name, context);
}
