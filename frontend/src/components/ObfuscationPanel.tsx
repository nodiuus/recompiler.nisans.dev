import { createEffect, createMemo, createSignal, For, Show, type JSX } from "solid-js";
import { disassembleFunction, transformBinary } from "../api";
import type { AnalyzedFunction, DisassemblyResult, TransformationPass } from "../types";
import ControlFlowGraph from "./ControlFlowGraph";

interface ObfuscationPanelProps {
  fns: AnalyzedFunction[];
  functions: AnalyzedFunction[];
  binary: File | null;
  pdb: File | null;
  cacheId: string | null;
  requestedView: PanelRequestedView;
  onNavigateFunction: (fn: AnalyzedFunction) => void;
  onClose: () => void;
}

type PanelTab = "details" | "disassembly" | "cfg" | "transformations";
type TransformationMode = "obfuscate" | "deobfuscate";
export type PanelRequestedView = "details" | "cfg";

const OBFUSCATION_PASSES: Array<{ id: TransformationPass; name: string; description: string }> = [
  { id: "mutate", name: "MBA mutation", description: "Expand binary operations using different types of identities." },
  { id: "opaque-predicates", name: "Opaque predicates", description: "Insert opaque-true predicates and dead edges." },
  { id: "dead-code", name: "Dead code", description: "Inject junk instructions kept live by a volatile sink." },
  { id: "nop-sled", name: "NOP sled", description: "Pad each basic block with side-effect NOPs." },
];

export default function ObfuscationPanel(props: ObfuscationPanelProps): JSX.Element {
  const [activeTab, setActiveTab] = createSignal<PanelTab>("details");
  const [disassembly, setDisassembly] = createSignal<DisassemblyResult | null>(null);
  const [analysisLoading, setAnalysisLoading] = createSignal(false);
  const [analysisError, setAnalysisError] = createSignal<string | null>(null);
  const [selectedObfuscation, setSelectedObfuscation] = createSignal<Set<TransformationPass>>(new Set());
  const [deobfuscationEnabled, setDeobfuscationEnabled] = createSignal(false);
  const [transformationMode, setTransformationMode] = createSignal<TransformationMode>("obfuscate");
  const [nopCount, setNopCount] = createSignal(3);
  const [obfReps, setObfReps] = createSignal(1);
  const [transforming, setTransforming] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);
  const [complete, setComplete] = createSignal(false);
  const singleFn = createMemo(() => (props.fns.length === 1 ? props.fns[0] : null));
  let functionVersion = 0;

  const openTab = async (tab: PanelTab) => {
    if (tab !== activeTab()) {
      setError(null);
      setComplete(false);
    }
    setActiveTab(tab);
    const fn = singleFn();
    const binary = props.binary;
    const pdb = props.pdb;
    if (!fn || !binary) return;

    const version = functionVersion;
    if ((tab === "disassembly" || tab === "cfg") && !disassembly() && !analysisLoading()) {
      setAnalysisLoading(true);
      setAnalysisError(null);
      try {
        const result = await disassembleFunction(binary, pdb, fn, props.cacheId ?? undefined);
        if (version === functionVersion) setDisassembly(result);
      } catch (cause) {
        if (version === functionVersion) {
          setAnalysisError(cause instanceof Error ? cause.message : "Disassembly failed.");
        }
      } finally {
        if (version === functionVersion) setAnalysisLoading(false);
      }
    }
  };

  createEffect(() => {
    const functionKey = props.fns.map((fn) => fn.id).join("|");
    const requestedView = props.requestedView;
    void functionKey;
    functionVersion += 1;
    setActiveTab(props.fns.length > 1 ? "transformations" : requestedView);
    setDisassembly(null);
    setAnalysisLoading(false);
    setAnalysisError(null);
    setError(null);
    setComplete(false);

    if (props.fns.length === 1 && requestedView === "cfg") {
      queueMicrotask(() => void openTab("cfg"));
    }
  });

  const toggle = (pass: TransformationPass) => {
    setSelectedObfuscation((current) => {
      const next = new Set(current);
      if (next.has(pass)) next.delete(pass);
      else next.add(pass);
      return next;
    });
    setComplete(false);
    setError(null);
  };

  const runTransformation = async () => {
    const fns = props.fns;
    const mode = transformationMode();
    const passes: TransformationPass[] = mode === "deobfuscate"
      ? deobfuscationEnabled() ? ["deobfuscate"] : []
      : [...selectedObfuscation()];
    if (fns.length === 0 || !props.binary || passes.length === 0) return;
    setTransforming(true);
    setError(null);
    setComplete(false);
    try {
      const blob = await transformBinary(
        props.binary,
        props.pdb,
        fns,
        passes,
        { nopCount: nopCount(), obfReps: obfReps() },
        props.cacheId ?? undefined,
      );
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${mode === "deobfuscate" ? "deobfuscated" : "obfuscated"}-${props.binary.name}`;
      link.click();
      URL.revokeObjectURL(url);
      setComplete(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Transformation failed.");
    } finally {
      setTransforming(false);
    }
  };

  const transformationStatus = () => (
    <>
      <Show when={error()}>
        {(message) => <div class="transform-error" role="alert">{message()}</div>}
      </Show>
      <Show when={complete()}>
        <div class="transform-success">The transformed binary was downloaded.</div>
      </Show>
    </>
  );

  const obfuscationControls = () => (
    <section class="transform-section">
      <h3>Obfuscation passes</h3>
      <div class="transform-passes">
        <For each={OBFUSCATION_PASSES}>
          {(pass) => (
            <label class="transform-pass">
              <input
                type="checkbox"
                checked={selectedObfuscation().has(pass.id)}
                onChange={() => toggle(pass.id)}
              />
              <span><strong>{pass.name}</strong><small>{pass.description}</small></span>
            </label>
          )}
        </For>
      </div>

      <div class="transform-options">
        <Show when={selectedObfuscation().has("mutate")}>
          <label>
            Mutation repetitions
            <input type="number" min="1" max="3" value={obfReps()} onInput={(event) => setObfReps(event.currentTarget.valueAsNumber)} />
          </label>
        </Show>
        <Show when={selectedObfuscation().has("nop-sled")}>
          <label>
            NOPs per block
            <input type="number" min="1" max="64" value={nopCount()} onInput={(event) => setNopCount(event.currentTarget.valueAsNumber)} />
          </label>
        </Show>
      </div>

      {transformationStatus()}
    </section>
  );

  const deobfuscationControls = () => (
    <section class="transform-section deobfuscation-section">
      <h3>Deobfuscation passes</h3>
      <div class="transform-passes">
        <label class="transform-pass">
          <input
            type="checkbox"
            checked={deobfuscationEnabled()}
            onChange={(event) => {
              setDeobfuscationEnabled(event.currentTarget.checked);
              setComplete(false);
              setError(null);
            }}
          />
          <span>
            <strong>MBA simplifier</strong>
            <small>Recognize and fold PERSES mixed-boolean arithmetic identities back into ordinary operations.</small>
          </span>
        </label>
      </div>
      <p class="deobfuscation-note">
        This runs the recompiler's dedicated deobfuscation pipeline. It is kept separate from obfuscation so the two transformations cannot cancel or interfere with each other in one request.
      </p>
      {transformationStatus()}
    </section>
  );

  const transformationControls = () => (
    <div class="transformations-view">
      <div class="transformation-mode-tabs" role="group" aria-label="Transformation type">
        <button
          type="button"
          classList={{ active: transformationMode() === "obfuscate" }}
          disabled={transforming()}
          onClick={() => {
            setTransformationMode("obfuscate");
            setError(null);
            setComplete(false);
          }}
        >
          Obfuscation passes
        </button>
        <button
          type="button"
          classList={{ active: transformationMode() === "deobfuscate" }}
          disabled={transforming()}
          onClick={() => {
            setTransformationMode("deobfuscate");
            setError(null);
            setComplete(false);
          }}
        >
          Deobfuscation passes
        </button>
      </div>
      <Show when={transformationMode() === "obfuscate"} fallback={deobfuscationControls()}>
        {obfuscationControls()}
      </Show>
    </div>
  );

  return (
    <>
      <div
        class="panel-backdrop"
        classList={{ "panel-backdrop-open": props.fns.length > 0 }}
        onClick={props.onClose}
      />
      <aside
        class="panel"
        classList={{
          "panel-open": props.fns.length > 0,
          "panel-analysis-wide": !!singleFn() && (activeTab() === "disassembly" || activeTab() === "cfg"),
        }}
      >
        <Show when={props.fns.length > 0}>
          <header class="panel-header">
            <div>
              <Show
                when={singleFn()}
                fallback={
                  <>
                    <div class="panel-eyebrow">Batch transform</div>
                    <h2 class="panel-title">{props.fns.length} functions selected</h2>
                  </>
                }
              >
                {(fn) => (
                  <>
                    <div class="panel-eyebrow">Function analysis</div>
                    <h2 class="panel-title">{fn().name}</h2>
                    <div class="panel-subtitle">
                      {fn().address}{fn().size > 0 ? ` · ${fn().size} B` : ""}
                    </div>
                  </>
                )}
              </Show>
            </div>
            <button type="button" class="panel-close" onClick={props.onClose} aria-label="Close">
              &times;
            </button>
          </header>

          <nav class="panel-tabs" aria-label={singleFn() ? "Function views" : "Batch transformation views"}>
            <Show when={singleFn()}>
              <button classList={{ active: activeTab() === "details" }} onClick={() => void openTab("details")}>Details</button>
              <button classList={{ active: activeTab() === "disassembly" }} onClick={() => void openTab("disassembly")}>Disassembly</button>
              <button classList={{ active: activeTab() === "cfg" }} onClick={() => void openTab("cfg")}>Control flow</button>
            </Show>
            <button classList={{ active: activeTab() === "transformations" }} onClick={() => void openTab("transformations")}>Transformations</button>
          </nav>

          <div class="panel-body">
            <Show
              when={singleFn()}
              fallback={
                <>
                  <ul class="batch-function-list">
                    <For each={props.fns}>
                      {(fn) => (
                        <li>
                          <span class="fn-name">{fn.name}</span>
                          <span class="fn-mono">{fn.address}</span>
                        </li>
                      )}
                    </For>
                  </ul>
                  <Show when={activeTab() === "transformations"}>{transformationControls()}</Show>
                </>
              }
            >
              {(fn) => (
                <>
                  <Show when={activeTab() === "details"}>
                    <dl class="function-details">
                      <div><dt>Virtual address</dt><dd>{fn().address}</dd></div>
                      <div><dt>Relative address</dt><dd>{fn().rva}</dd></div>
                      <div><dt>Code size</dt><dd>{fn().size > 0 ? `${fn().size} bytes` : "Unknown"}</dd></div>
                      <div><dt>PE section</dt><dd>{fn().section}</dd></div>
                      <div><dt>Visibility</dt><dd>{fn().visibility}</dd></div>
                      <div><dt>Symbol source</dt><dd>{fn().source || "pdb"}</dd></div>
                      <div><dt>Object module</dt><dd>{fn().module || "Not available"}</dd></div>
                      <Show when={fn().decoratedName}>
                        <div><dt>Decorated/public name</dt><dd class="detail-wrap">{fn().decoratedName}</dd></div>
                      </Show>
                    </dl>
                  </Show>

                  <Show when={activeTab() === "disassembly" || activeTab() === "cfg"}>
                    <Show when={analysisLoading()}>
                      <div class="panel-loading">Disassembling and deriving basic blocks…</div>
                    </Show>
                    <Show when={analysisError()}>
                      {(message) => <div class="transform-error analysis-tab-error" role="alert">{message()}</div>}
                    </Show>
                  </Show>

                  <Show when={activeTab() === "disassembly" && disassembly()}>
                    {(data) => (
                      <div class="disassembly-view">
                        <div class="analysis-summary">
                          <span>{data().instructions.length.toLocaleString()} instructions</span>
                          <span>{data().blocks.length.toLocaleString()} basic blocks</span>
                          <span>Boundary: {data().boundary}</span>
                          <Show when={data().truncated}><strong>Truncated</strong></Show>
                        </div>
                        <div class="disassembly-table-wrap">
                          <table class="disassembly-table">
                            <thead><tr><th>Address</th><th>Offset</th><th>Bytes</th><th>Instruction</th></tr></thead>
                            <tbody>
                              <For each={data().instructions}>
                                {(instruction, index) => (
                                  <tr classList={{ "disassembly-block-start": index() === 0 || data().instructions[index() - 1]?.blockId !== instruction.blockId }}>
                                    <td>{instruction.address}</td>
                                    <td>+0x{instruction.offset.toString(16)}</td>
                                    <td class="instruction-bytes">{instruction.bytes}</td>
                                    <td><b>{instruction.mnemonic}</b>{instruction.operands ? ` ${instruction.operands}` : ""}</td>
                                  </tr>
                                )}
                              </For>
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </Show>

                  <Show when={activeTab() === "cfg" && disassembly()}>
                    {(data) => (
                      <ControlFlowGraph
                        analysis={data()}
                        functions={props.functions}
                        onNavigateFunction={props.onNavigateFunction}
                      />
                    )}
                  </Show>

                  <Show when={activeTab() === "transformations"}>
                    {transformationControls()}
                  </Show>
                </>
              )}
            </Show>
          </div>

          <Show when={activeTab() === "transformations"}>
            <footer class="panel-footer">
              <button
                type="button"
                class="apply-button"
                disabled={transforming() || (transformationMode() === "deobfuscate" ? !deobfuscationEnabled() : selectedObfuscation().size === 0)}
                onClick={runTransformation}
              >
                {transforming()
                  ? `${transformationMode() === "deobfuscate" ? "Deobfuscating" : "Obfuscating"}${props.fns.length > 1 ? ` ${props.fns.length} functions` : ""}…`
                  : `${transformationMode() === "deobfuscate" ? "Deobfuscate" : "Obfuscate"}${props.fns.length > 1 ? ` ${props.fns.length} functions` : ""} and download`}
              </button>
            </footer>
          </Show>
        </Show>
      </aside>
    </>
  );
}
