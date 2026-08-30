import { createEffect, createSignal, onCleanup, onMount, For, type JSX } from "solid-js";
import { CATEGORY_LABELS, classifyFunction } from "../functionCategory";
import type { AnalyzedFunction } from "../types";

interface FunctionListProps {
  functions: AnalyzedFunction[];
  activeIds: Set<string>;
  checkedIds: Set<string>;
  onSelect: (fn: AnalyzedFunction) => void;
  onSetChecked: (fn: AnalyzedFunction, checked: boolean) => void;
  onToggleAll: (checked: boolean) => void;
  selectionLimitReached: boolean;
}

export default function FunctionList(props: FunctionListProps): JSX.Element {
  let selectAllRef: HTMLInputElement | undefined;
  const [isDragSelecting, setIsDragSelecting] = createSignal(false);

  // Plain (non-reactive) drag state: mousemove/mouseenter can fire dozens of
  // times per drag, and only the checkbox target under the pointer needs it.
  let dragging = false;
  let dragValue = false;
  // A same-cell mousedown+mouseup (a plain click, no drag) still fires a
  // native "click" afterwards, whose default action toggles the checkbox a
  // second time on top of the mousedown-driven toggle below. Flag that we
  // already applied the change so the click handler can cancel that native
  // toggle; a keyboard-activated click (no preceding mousedown) leaves the
  // flag unset and is left to toggle natively, synced via the input's onChange.
  let handledByMouseDown = false;

  const beginDrag = (fn: AnalyzedFunction) => (e: MouseEvent) => {
    if (e.button !== 0) return;
    e.preventDefault();
    handledByMouseDown = true;
    dragging = true;
    dragValue = !props.checkedIds.has(fn.id);
    setIsDragSelecting(true);
    props.onSetChecked(fn, dragValue);
  };

  const continueDrag = (fn: AnalyzedFunction) => () => {
    if (!dragging) return;
    props.onSetChecked(fn, dragValue);
  };

  const endDrag = () => {
    dragging = false;
    setIsDragSelecting(false);
    // A multi-row drag never fires a "click" on either endpoint (mousedown
    // and mouseup landed on different elements), so nothing clears the flag
    // above. Clear it after this task finishes, once any same-cell click has
    // already had its chance to run (click follows mouseup synchronously).
    setTimeout(() => {
      handledByMouseDown = false;
    }, 0);
  };

  onMount(() => window.addEventListener("mouseup", endDrag));
  onCleanup(() => window.removeEventListener("mouseup", endDrag));

  createEffect(() => {
    if (!selectAllRef) return;
    const total = props.functions.length;
    const checked = props.functions.filter((fn) => props.checkedIds.has(fn.id)).length;
    selectAllRef.checked = total > 0 && checked === total;
    selectAllRef.indeterminate = checked > 0 && checked < total;
  });

  return (
    <div class="function-list" classList={{ "function-list-dragging": isDragSelecting() }}>
      <table>
        <thead>
          <tr>
            <th class="fn-check-col">
              <input
                ref={selectAllRef}
                type="checkbox"
                aria-label="Select all visible functions"
                onChange={(e) => props.onToggleAll(e.currentTarget.checked)}
              />
            </th>
            <th>Function</th>
            <th>Address</th>
            <th>RVA</th>
            <th>Size</th>
            <th>Section</th>
            <th>Module</th>
            <th>Visibility</th>
            <th>Source</th>
            <th>Category</th>
          </tr>
        </thead>
        <tbody>
          <For each={props.functions}>
            {(fn) => (
              <tr
                classList={{ "row-selected": props.activeIds.has(fn.id) }}
                onClick={() => props.onSelect(fn)}
              >
                <td
                  class="fn-check-col"
                  onClick={(e) => {
                    e.stopPropagation();
                    if (handledByMouseDown) {
                      e.preventDefault();
                      handledByMouseDown = false;
                    }
                  }}
                  onMouseDown={beginDrag(fn)}
                  onMouseEnter={continueDrag(fn)}
                >
                  <input
                    type="checkbox"
                    checked={props.checkedIds.has(fn.id)}
                    disabled={props.selectionLimitReached && !props.checkedIds.has(fn.id)}
                    onChange={(e) => props.onSetChecked(fn, e.currentTarget.checked)}
                  />
                </td>
                <td class="fn-name">{fn.name}</td>
                <td class="fn-mono">{fn.address}</td>
                <td class="fn-mono">{fn.rva}</td>
                <td class="fn-mono">{fn.size > 0 ? `${fn.size} B` : "—"}</td>
                <td class="fn-mono">{fn.section}</td>
                <td class="fn-module" title={fn.module}>{fn.module || "—"}</td>
                <td><span class={`badge badge-${fn.visibility}`}>{fn.visibility}</span></td>
                <td><span class="badge badge-source">{fn.source || "pdb"}</span></td>
                <td>
                  {(() => {
                    const category = classifyFunction(fn);
                    return <span class={`badge badge-cat-${category}`}>{CATEGORY_LABELS[category]}</span>;
                  })()}
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}
