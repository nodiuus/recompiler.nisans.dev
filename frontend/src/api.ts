import type { AnalyzedFunction, AnalysisResult, DisassemblyResult, TransformationPass } from "./types";
import { recordRumAction } from "./observability";

const API_BASE = (import.meta.env.VITE_API_URL ?? "").replace(/\/$/, "");

export async function analyzeBinary(binary: File, pdb: File | null): Promise<AnalysisResult> {
  const startedAt = performance.now();
  const form = new FormData();
  form.append("binary", binary);
  if (pdb) form.append("pdb", pdb);

  const response = await fetch(`${API_BASE}/api/analyze`, {
    method: "POST",
    body: form,
  });
  const body = await response.json().catch(() => null) as AnalysisResult | { error?: string } | null;

  recordRumAction("binary_analysis.completed", {
    duration_ms: Math.round(performance.now() - startedAt),
    binary_bytes: binary.size,
    pdb_bytes: pdb?.size ?? 0,
    has_pdb: Boolean(pdb),
    status_code: response.status,
    success: response.ok,
  });

  if (!response.ok) {
    const message = body && "error" in body ? body.error : undefined;
    throw new Error(message || `Analysis failed with HTTP ${response.status}`);
  }
  if (!body || !("functions" in body)) {
    throw new Error("The backend returned an invalid analysis response.");
  }
  return body;
}

export async function transformBinary(
  binary: File,
  pdb: File | null,
  functions: AnalyzedFunction[],
  passes: TransformationPass[],
  options: { nopCount: number; obfReps: number },
  cacheId?: string,
): Promise<Blob> {
  const form = new FormData();
  if (cacheId) {
    form.append("cacheId", cacheId);
  } else {
    form.append("binary", binary);
    if (pdb) form.append("pdb", pdb);
  }
  for (const fn of functions) form.append("address", fn.address);
  form.append("nopCount", String(options.nopCount));
  form.append("obfReps", String(options.obfReps));
  for (const pass of passes) form.append("pass", pass);

  const response = await fetch(`${API_BASE}/api/transform`, {
    method: "POST",
    body: form,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { error?: string } | null;
    throw new Error(body?.error || `Transformation failed with HTTP ${response.status}`);
  }
  return response.blob();
}

export async function disassembleFunction(
  binary: File,
  pdb: File | null,
  fn: AnalyzedFunction,
  cacheId?: string,
): Promise<DisassemblyResult> {
  const form = new FormData();
  if (cacheId) {
    form.append("cacheId", cacheId);
  } else {
    form.append("binary", binary);
    if (pdb) form.append("pdb", pdb);
  }
  form.append("address", fn.address);

  const response = await fetch(`${API_BASE}/api/disassemble`, {
    method: "POST",
    body: form,
  });
  const body = await response.json().catch(() => null) as DisassemblyResult | { error?: string } | null;
  if (!response.ok) {
    const message = body && "error" in body ? body.error : undefined;
    throw new Error(message || `Disassembly failed with HTTP ${response.status}`);
  }
  if (!body || !("instructions" in body) || !("blocks" in body)) {
    throw new Error("The backend returned an invalid disassembly response.");
  }
  return body;
}
