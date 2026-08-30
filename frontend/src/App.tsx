import { createEffect, createMemo, createSignal, For, Show, type JSX } from "solid-js";
import "./App.css";
import FileDropZone from "./components/FileDropZone";
import FunctionList from "./components/FunctionList";
import ObfuscationPanel, { type PanelRequestedView } from "./components/ObfuscationPanel";
import { analyzeBinary } from "./api";
import { CATEGORY_LABELS, FUNCTION_CATEGORIES, classifyFunction, type FunctionCategory } from "./functionCategory";
import type { AnalyzedFunction, AnalysisResult } from "./types";

const DEFAULT_HIDDEN_CATEGORIES: FunctionCategory[] = ["crt"];
const MAX_BATCH_FUNCTIONS = 32;
const FUNCTIONS_PER_PAGE = 500;

function App(): JSX.Element {
  const [binaryFile, setBinaryFile] = createSignal<File | null>(null);
  const [debugFile, setDebugFile] = createSignal<File | null>(null);
  const [analyzing, setAnalyzing] = createSignal(false);
  const [result, setResult] = createSignal<AnalysisResult | null>(null);
  const [selectedFns, setSelectedFns] = createSignal<AnalyzedFunction[]>([]);
  const [panelView, setPanelView] = createSignal<PanelRequestedView>("details");
  const [checkedIds, setCheckedIds] = createSignal<Set<string>>(new Set());
  const [error, setError] = createSignal<string | null>(null);
  const [functionPage, setFunctionPage] = createSignal(1);
  const [hiddenCategories, setHiddenCategories] = createSignal<Set<FunctionCategory>>(
    new Set(DEFAULT_HIDDEN_CATEGORIES),
  );

  const toggleCategory = (category: FunctionCategory) => {
    setHiddenCategories((current) => {
      const next = new Set(current);
      if (next.has(category)) {
        next.delete(category);
      } else {
        next.add(category);
      }
      return next;
    });
    setFunctionPage(1);
  };

  const readyToAnalyze = createMemo(() => !!binaryFile() && !analyzing());
  const visibleFunctions = createMemo(() => {
    const functions = result()?.functions ?? [];
    const hidden = hiddenCategories();
    if (hidden.size === 0) return functions;
    return functions.filter((fn) => !hidden.has(classifyFunction(fn)));
  });
  const activeIds = createMemo(() => new Set(selectedFns().map((fn) => fn.id)));
  const batchLimitReached = createMemo(() => checkedIds().size >= MAX_BATCH_FUNCTIONS);
  const totalFunctionPages = createMemo(() => Math.max(1, Math.ceil(visibleFunctions().length / FUNCTIONS_PER_PAGE)));
  const pagedFunctions = createMemo(() => {
    const start = (functionPage() - 1) * FUNCTIONS_PER_PAGE;
    return visibleFunctions().slice(start, start + FUNCTIONS_PER_PAGE);
  });

  createEffect(() => {
    if (functionPage() > totalFunctionPages()) setFunctionPage(totalFunctionPages());
  });

  const setFunctionChecked = (fn: AnalyzedFunction, checked: boolean) => {
    setCheckedIds((current) => {
      if (checked === current.has(fn.id)) return current;
      const next = new Set(current);
      if (checked) {
        if (next.size < MAX_BATCH_FUNCTIONS) next.add(fn.id);
      } else {
        next.delete(fn.id);
      }
      return next;
    });
  };

  const toggleAllChecked = (checked: boolean) => {
    setCheckedIds((current) => {
      const next = new Set(current);
      for (const fn of pagedFunctions()) {
        if (checked) {
          if (next.size < MAX_BATCH_FUNCTIONS) next.add(fn.id);
        } else {
          next.delete(fn.id);
        }
      }
      return next;
    });
  };

  const openBatch = () => {
    const ids = checkedIds();
    setPanelView("details");
    setSelectedFns((result()?.functions ?? []).filter((fn) => ids.has(fn.id)));
  };

  const runAnalysis = async () => {
    const binary = binaryFile();
    const debugInfo = debugFile();
    if (!binary) return;

    setAnalyzing(true);
    setResult(null);
    setSelectedFns([]);
    setCheckedIds(new Set<string>());
    setError(null);
    setFunctionPage(1);
    try {
      setResult(await analyzeBinary(binary, debugInfo));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Analysis failed.");
    } finally {
      setAnalyzing(false);
    }
  };

  const resetInput = (setter: (f: File | null) => void) => (file: File | null) => {
    setter(file);
    setResult(null);
    setSelectedFns([]);
    setCheckedIds(new Set<string>());
    setError(null);
    setFunctionPage(1);
  };

  return (
    <div class="app">
      <header class="app-header">
        <h1>Recompiler</h1>
        <p class="app-subtitle">Inspect a Windows binary directly, or add its matching PDB for complete function symbols.</p>
      </header>

      <main class="app-main">
        <section class="upload-section">
          <FileDropZone
            label="Binary"
            hint="Drop the compiled binary here, or click to browse"
            accept=".exe,.dll,.sys,application/vnd.microsoft.portable-executable,application/x-msdownload"
            file={binaryFile()}
            onFile={resetInput(setBinaryFile)}
          />
          <FileDropZone
            label="PDB debug info (optional)"
            hint="Add a matching native .pdb for richer names, modules, and boundaries"
            accept=".pdb"
            file={debugFile()}
            onFile={resetInput(setDebugFile)}
          />
        </section>

        <div class="analyze-row">
          <button
            type="button"
            class="analyze-button"
            disabled={!readyToAnalyze()}
            onClick={runAnalysis}
          >
            {analyzing() ? "Analyzing…" : "Analyze"}
          </button>
        </div>

        <Show when={error()}>
          {(message) => <div class="analysis-error" role="alert">{message()}</div>}
        </Show>

        <Show when={result()}>
          {(analysis) => (
            <section class="results-section">
              <div class="results-heading">
                <div>
                  <h2 class="results-title">Functions</h2>
                  <p class="results-hint">
                    {visibleFunctions().length.toLocaleString()} of {analysis().functions.length.toLocaleString()} symbols match the filters. Showing up to {FUNCTIONS_PER_PAGE.toLocaleString()} per page.
                  </p>
                  <div class="category-filter" role="group" aria-label="Filter functions by category">
                    <span class="category-filter-label">Show:</span>
                    <For each={FUNCTION_CATEGORIES}>
                      {(category) => (
                        <label class="category-filter-toggle">
                          <input
                            type="checkbox"
                            checked={!hiddenCategories().has(category)}
                            onChange={() => toggleCategory(category)}
                          />
                          {CATEGORY_LABELS[category]}
                        </label>
                      )}
                    </For>
                  </div>
                </div>
                <dl class="binary-summary">
                  <div><dt>Target</dt><dd>{analysis().binary.machine}</dd></div>
                  <div><dt>Image base</dt><dd>{analysis().binary.imageBase}</dd></div>
                  <div><dt>Symbols</dt><dd>{analysis().binary.symbols}</dd></div>
                  <div><dt>PDB</dt><dd>{analysis().binary.hasPdb ? analysis().binary.pdbPath : "Not supplied"}</dd></div>
                  <Show when={analysis().binary.hasPdb}>
                    <div><dt>GUID</dt><dd>{analysis().binary.guid}</dd></div>
                    <div><dt>Age</dt><dd>{analysis().binary.age}</dd></div>
                  </Show>
                  <div><dt>Upload cache</dt><dd>{analysis().cacheId ? "Ready" : "Unavailable"}</dd></div>
                </dl>
              </div>

              <Show when={checkedIds().size > 0}>
                <div class="batch-bar">
                  <span>
                    {checkedIds().size.toLocaleString()} function{checkedIds().size === 1 ? "" : "s"} selected
                    {batchLimitReached() ? ` · ${MAX_BATCH_FUNCTIONS} function limit reached` : ""}
                  </span>
                  <div class="batch-bar-actions">
                    <button type="button" class="batch-clear-button" onClick={() => setCheckedIds(new Set<string>())}>
                      Clear
                    </button>
                    <button type="button" class="batch-transform-button" onClick={openBatch}>
                      Transform selected
                    </button>
                  </div>
                </div>
              </Show>

              <FunctionList
                functions={pagedFunctions()}
                activeIds={activeIds()}
                checkedIds={checkedIds()}
                onSelect={(fn) => {
                  setPanelView("details");
                  setSelectedFns([fn]);
                }}
                onSetChecked={setFunctionChecked}
                onToggleAll={toggleAllChecked}
                selectionLimitReached={batchLimitReached()}
              />
              <Show when={totalFunctionPages() > 1}>
                <nav class="function-pagination" aria-label="Function pages">
                  <button type="button" disabled={functionPage() === 1} onClick={() => setFunctionPage((page) => page - 1)}>Previous</button>
                  <span>
                    Page {functionPage().toLocaleString()} of {totalFunctionPages().toLocaleString()}
                    {` · ${((functionPage() - 1) * FUNCTIONS_PER_PAGE + 1).toLocaleString()}–${Math.min(functionPage() * FUNCTIONS_PER_PAGE, visibleFunctions().length).toLocaleString()}`}
                  </span>
                  <button type="button" disabled={functionPage() === totalFunctionPages()} onClick={() => setFunctionPage((page) => page + 1)}>Next</button>
                </nav>
              </Show>
            </section>
          )}
        </Show>
      </main>

      <ObfuscationPanel
        fns={selectedFns()}
        functions={result()?.functions ?? []}
        binary={binaryFile()}
        pdb={debugFile()}
        cacheId={result()?.cacheId ?? null}
        requestedView={panelView()}
        onNavigateFunction={(fn) => {
          setPanelView("cfg");
          setSelectedFns([fn]);
        }}
        onClose={() => setSelectedFns([])}
      />
    </div>
  );
}

export default App;
