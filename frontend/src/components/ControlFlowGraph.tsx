import { createMemo, createSignal, For, onCleanup, onMount, type JSX } from "solid-js";
import type { AnalyzedFunction, BasicBlock, ControlFlowEdge, DisassembledInstruction, DisassemblyResult } from "../types";

interface ControlFlowGraphProps {
  analysis: DisassemblyResult;
  functions: AnalyzedFunction[];
  onNavigateFunction: (fn: AnalyzedFunction) => void;
}

const NODE_GAP = 64;
const ROW_GAP = 64;
const SIDE_PADDING = 72;
const TOP_PADDING = 116;

interface PositionedBlock {
  block: BasicBlock;
  index: number;
  level: number;
  x: number;
  y: number;
  width: number;
  height: number;
}

interface GraphLayout {
  nodes: PositionedBlock[];
  width: number;
  height: number;
  layoutTimeMs: number;
}

function blockLabel(analysis: DisassemblyResult, index: number): string {
  return index === 0 ? `"${analysis.functionName}":` : `.L${index + 1}:`;
}

function internalLabelMap(analysis: DisassemblyResult): Map<string, string> {
  return new Map(analysis.blocks.map((block, index) => [block.startAddress.toLowerCase(), blockLabel(analysis, index).slice(0, -1)]));
}

function displayOperands(instruction: DisassembledInstruction, labels: Map<string, string>): string {
  if (!/^(?:j|loop)/i.test(instruction.mnemonic) || !instruction.operands) return instruction.operands ?? "";
  return instruction.operands.replace(/0x[0-9a-f]+(?:\s+<[^>]+>)?/i, (target) => {
    const address = target.match(/^0x[0-9a-f]+/i)?.[0].toLowerCase();
    return address ? labels.get(address) ?? target : target;
  });
}

function blockDimensions(analysis: DisassemblyResult, index: number, labels: Map<string, string>): { width: number; height: number } {
  const block = analysis.blocks[index];
  const instructions = analysis.instructions.slice(block.instructionStart, block.instructionEnd);
  let longest = blockLabel(analysis, index).length;
  for (const instruction of instructions) {
    longest = Math.max(longest, 7 + instruction.mnemonic.length + displayOperands(instruction, labels).length);
  }
  const shown = Math.max(1, instructions.length);
  return {
    width: Math.min(370, Math.max(126, Math.ceil(longest * 6.25 + 24))),
    height: 15 + shown * 13 + 12,
  };
}

function buildLayout(analysis: DisassemblyResult): GraphLayout {
  const started = performance.now();
  const blocks = analysis.blocks;
  const indices = new Map(blocks.map((block, index) => [block.id, index]));
  const levels = blocks.map(() => 0);

  blocks.forEach((block, index) => {
    for (const edge of analysis.edges) {
      if (edge.from !== block.id || !edge.to || edge.external) continue;
      const target = indices.get(edge.to);
      if (target !== undefined && target > index) levels[target] = Math.max(levels[target], levels[index] + 1);
    }
  });

  let lastReachableLevel = 0;
  blocks.forEach((block, index) => {
    if (block.reachable) lastReachableLevel = Math.max(lastReachableLevel, levels[index]);
  });
  let unreachableLevel = lastReachableLevel + 1;
  blocks.forEach((block, index) => {
    if (!block.reachable) levels[index] = unreachableLevel++;
  });

  const incomingPriority = new Map<number, number>();
  for (const edge of analysis.edges) {
    if (!edge.to || edge.external) continue;
    const target = indices.get(edge.to);
    if (target === undefined) continue;
    const priority = edge.type === "taken" ? 0 : edge.type === "jump" ? 1 : 2;
    incomingPriority.set(target, Math.min(incomingPriority.get(target) ?? 9, priority));
  }
  const grouped = new Map<number, number[]>();
  levels.forEach((level, index) => grouped.set(level, [...(grouped.get(level) ?? []), index]));
  for (const row of grouped.values()) {
    row.sort((left, right) => (incomingPriority.get(left) ?? 9) - (incomingPriority.get(right) ?? 9) || left - right);
  }

  const labels = internalLabelMap(analysis);
  const dimensions = blocks.map((_, index) => blockDimensions(analysis, index, labels));
  const levelNumbers = [...grouped.keys()].sort((a, b) => a - b);
  const rowWidths = levelNumbers.map((level) => {
    const row = grouped.get(level) ?? [];
    return row.reduce((total, index) => total + dimensions[index].width, 0) + Math.max(0, row.length - 1) * NODE_GAP;
  });
  const width = Math.max(820, SIDE_PADDING * 2 + Math.max(0, ...rowWidths));
  const levelY = new Map<number, number>();
  let y = TOP_PADDING;
  for (const level of levelNumbers) {
    levelY.set(level, y);
    const rowHeight = Math.max(...(grouped.get(level) ?? []).map((index) => dimensions[index].height));
    y += rowHeight + ROW_GAP;
  }

  const nodes: PositionedBlock[] = [];
  levelNumbers.forEach((level, rowIndex) => {
    const row = grouped.get(level) ?? [];
    let x = (width - rowWidths[rowIndex]) / 2;
    for (const blockIndex of row) {
      nodes.push({
        block: blocks[blockIndex],
        index: blockIndex,
        level,
        x,
        y: levelY.get(level) ?? TOP_PADDING,
        ...dimensions[blockIndex],
      });
      x += dimensions[blockIndex].width + NODE_GAP;
    }
  });
  nodes.sort((left, right) => left.index - right.index);
  return {
    nodes,
    width,
    height: Math.max(620, y - ROW_GAP + 112),
    layoutTimeMs: performance.now() - started,
  };
}

function renderOperands(
  value: string,
  linkDirectTargets: boolean,
  resolveFunction: (address: string) => AnalyzedFunction | undefined,
  navigate: (fn: AnalyzedFunction) => void,
): Array<string | JSX.Element> {
  const parts = value.split(/(0x[0-9a-f]+(?:\s+<[^>]+>)?|\.L\d+|\b(?:r(?:1[0-5]|[89]|ax|bx|cx|dx|si|di|sp|bp|ip)|e(?:ax|bx|cx|dx|si|di|sp|bp|ip)|(?:[abcd][lh])|[xyz]mm\d+|st\(\d+\))\b)/gi);
  return parts.map((part) => {
    if (linkDirectTargets && /^0x[0-9a-f]+/i.test(part)) {
      const address = part.match(/^0x[0-9a-f]+/i)?.[0] ?? "";
      const target = resolveFunction(address);
      if (target) {
        return (
          <button
            type="button"
            class="cfg-address-link"
            title={`Open ${target.name} (${target.address})`}
            onPointerDown={(event) => event.stopPropagation()}
            onClick={(event) => {
              event.stopPropagation();
              navigate(target);
            }}
          >
            {part}
          </button>
        );
      }
    }
    if (/^\.L\d+$/i.test(part)) return <span class="cfg-target">{part}</span>;
    if (/^(?:r(?:1[0-5]|[89]|ax|bx|cx|dx|si|di|sp|bp|ip)|e(?:ax|bx|cx|dx|si|di|sp|bp|ip)|(?:[abcd][lh])|[xyz]mm\d+|st\(\d+\))$/i.test(part)) {
      return <span class="cfg-register">{part}</span>;
    }
    return part;
  });
}

export default function ControlFlowGraph(props: ControlFlowGraphProps): JSX.Element {
  const [zoom, setZoom] = createSignal(1);
  const [panning, setPanning] = createSignal(false);
  const [panOffset, setPanOffset] = createSignal({ x: 0, y: 0 });
  const layout = createMemo(() => buildLayout(props.analysis));
  const nodeMap = createMemo(() => new Map(layout().nodes.map((node) => [node.block.id, node])));
  const labels = createMemo(() => internalLabelMap(props.analysis));
  const internalEdges = createMemo(() => props.analysis.edges.filter((edge) => edge.to && !edge.external));
  const outgoingCounts = createMemo(() => {
    const counts = new Map<string, number>();
    for (const edge of props.analysis.edges) counts.set(edge.from, (counts.get(edge.from) ?? 0) + 1);
    return counts;
  });
  const functionRanges = createMemo(() => props.functions.flatMap((fn) => {
    try {
      const start = BigInt(fn.address);
      return [{ fn, start, end: start + BigInt(Math.max(1, fn.size)) }];
    } catch {
      return [];
    }
  }));
  let scrollRef: HTMLDivElement | undefined;
  let dragStart: { x: number; y: number; panX: number; panY: number; pointerId: number } | null = null;

  const visualEdgeType = (edge: ControlFlowEdge): "taken" | "fallthrough" | "jump" | "linear" => {
    if (edge.type === "fallthrough" && (outgoingCounts().get(edge.from) ?? 0) === 1) return "linear";
    return edge.type;
  };

  const resolveFunction = (rawAddress: string): AnalyzedFunction | undefined => {
    try {
      const address = BigInt(rawAddress);
      const exact = functionRanges().find((candidate) => candidate.start === address);
      if (exact) return exact.fn;
      return functionRanges().find((candidate) => address >= candidate.start && address < candidate.end)?.fn;
    } catch {
      return undefined;
    }
  };

  const edgePath = (edge: ControlFlowEdge, index: number): string => {
    const from = nodeMap().get(edge.from);
    const to = edge.to ? nodeMap().get(edge.to) : undefined;
    if (!from || !to) return "";
    const kind = visualEdgeType(edge);
    const portOffset = kind === "taken" ? -7 : kind === "fallthrough" ? 7 : 0;
    const startX = from.x + from.width / 2 + portOffset;
    const startY = from.y + from.height;
    const endX = to.x + to.width / 2;
    const endY = to.y;
    if (to.level === from.level + 1) {
      const middleY = startY + Math.max(18, (endY - startY) / 2) + (index % 3 - 1) * 3;
      return `M ${startX} ${startY} V ${middleY} H ${endX} V ${endY}`;
    }
    const routesLeft = endX < startX;
    const spread = 22 + (index % 7) * 9;
    const laneX = routesLeft
      ? Math.max(12, Math.min(from.x, to.x) - spread)
      : Math.min(layout().width - 12, Math.max(from.x + from.width, to.x + to.width) + spread);
    return `M ${startX} ${startY} V ${startY + 17} H ${laneX} V ${endY - 15} H ${endX} V ${endY}`;
  };

  const setGraphZoom = (next: number) => setZoom(Math.min(1.8, Math.max(0.25, next)));
  const fitGraph = () => {
    if (!scrollRef) return;
    setPanOffset({ x: 0, y: 0 });
    setGraphZoom(Math.min(1, (scrollRef.clientWidth - 28) / layout().width, (scrollRef.clientHeight - 28) / layout().height));
    queueMicrotask(() => {
      if (!scrollRef) return;
      scrollRef.scrollLeft = Math.max(0, (layout().width * zoom() - scrollRef.clientWidth) / 2);
      scrollRef.scrollTop = Math.max(0, (layout().height * zoom() - scrollRef.clientHeight) / 2);
    });
  };
  const handleWheel = (event: WheelEvent) => {
    if (!event.ctrlKey || !scrollRef) return;
    event.preventDefault();
    const previous = zoom();
    const next = Math.min(1.8, Math.max(0.25, previous + (event.deltaY < 0 ? 0.1 : -0.1)));
    const bounds = scrollRef.getBoundingClientRect();
    const graphX = (scrollRef.scrollLeft + event.clientX - bounds.left) / previous;
    const graphY = (scrollRef.scrollTop + event.clientY - bounds.top) / previous;
    setZoom(next);
    queueMicrotask(() => {
      if (!scrollRef) return;
      scrollRef.scrollLeft = graphX * next - (event.clientX - bounds.left);
      scrollRef.scrollTop = graphY * next - (event.clientY - bounds.top);
    });
  };
  const beginPan = (event: PointerEvent) => {
    if (!scrollRef || event.button !== 0 || (event.target as Element).closest(".cfg-address-link")) return;
    const currentPan = panOffset();
    dragStart = { x: event.clientX, y: event.clientY, panX: currentPan.x, panY: currentPan.y, pointerId: event.pointerId };
    scrollRef.setPointerCapture(event.pointerId);
    setPanning(true);
    event.preventDefault();
  };
  const movePan = (event: PointerEvent) => {
    if (!scrollRef || !dragStart || dragStart.pointerId !== event.pointerId) return;
    setPanOffset({
      x: dragStart.panX + event.clientX - dragStart.x,
      y: dragStart.panY + event.clientY - dragStart.y,
    });
  };
  const endPan = (event: PointerEvent) => {
    if (!scrollRef || !dragStart || dragStart.pointerId !== event.pointerId) return;
    if (scrollRef.hasPointerCapture(event.pointerId)) scrollRef.releasePointerCapture(event.pointerId);
    dragStart = null;
    setPanning(false);
  };

  onMount(() => {
    const timer = window.setTimeout(fitGraph, 0);
    onCleanup(() => window.clearTimeout(timer));
  });

  return (
    <div class="cfg-frame">
      <div
        ref={scrollRef}
        class="cfg-scroll"
        classList={{ "cfg-panning": panning() }}
        aria-label="Control-flow graph"
        onWheel={handleWheel}
        onPointerDown={beginPan}
        onPointerMove={movePan}
        onPointerUp={endPan}
        onPointerCancel={endPan}
      >
        <div class="cfg-stage" style={{ width: `${layout().width * zoom()}px`, height: `${layout().height * zoom()}px` }}>
          <div
            class="cfg-canvas"
            style={{
              width: `${layout().width}px`,
              height: `${layout().height}px`,
              left: `calc(50% + ${panOffset().x}px)`,
              top: `calc(50% + ${panOffset().y}px)`,
              transform: `translate(-50%, -50%) scale(${zoom()})`,
            }}
          >
          <svg class="cfg-edges" width={layout().width} height={layout().height} aria-hidden="true">
            <defs>
              <For each={["taken", "fallthrough", "jump", "linear"]}>
                {(kind) => <marker id={`cfg-arrow-${kind}`} markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M 0 0 L 6 3 L 0 6 z" /></marker>}
              </For>
            </defs>
            <For each={internalEdges()}>
              {(edge, index) => {
                const kind = visualEdgeType(edge);
                return <path class={`cfg-edge cfg-edge-${kind}`} d={edgePath(edge, index())} marker-end={`url(#cfg-arrow-${kind})`} />;
              }}
            </For>
          </svg>

          <For each={layout().nodes}>
            {(node) => {
              const instructions = () => props.analysis.instructions.slice(node.block.instructionStart, node.block.instructionEnd);
              return (
                <article
                  class="cfg-node"
                  classList={{ "cfg-node-unreachable": !node.block.reachable }}
                  style={{ left: `${node.x}px`, top: `${node.y}px`, width: `${node.width}px`, height: `${node.height}px` }}
                >
                  <div class="cfg-node-label">{blockLabel(props.analysis, node.index)}</div>
                  <div class="cfg-node-code">
                    <For each={instructions()}>
                      {(instruction) => {
                        const operands = displayOperands(instruction, labels());
                        const hasDirectControlTarget = /^(?:call|j|loop)/i.test(instruction.mnemonic)
                          && /^\s*0x[0-9a-f]+/i.test(operands);
                        return (
                          <div title={`${instruction.address}: ${instruction.mnemonic} ${instruction.operands ?? ""}`}>
                            <b>{instruction.mnemonic}</b>
                            <span>{renderOperands(operands, hasDirectControlTarget, resolveFunction, props.onNavigateFunction)}</span>
                          </div>
                        );
                      }}
                    </For>
                  </div>
                </article>
              );
            }}
          </For>

          </div>
        </div>
      </div>
      <div class="cfg-status">
        <div>Layout time: {layout().layoutTimeMs < 1 ? "<1" : Math.round(layout().layoutTimeMs)}ms</div>
        <div>Basic blocks: {props.analysis.blocks.length}</div>
      </div>
    </div>
  );
}
