import { createSignal, Show, type JSX } from "solid-js";

interface FileDropZoneProps {
  label: string;
  hint: string;
  accept?: string;
  file: File | null;
  onFile: (file: File | null) => void;
}

export default function FileDropZone(props: FileDropZoneProps): JSX.Element {
  const [dragOver, setDragOver] = createSignal(false);
  let inputRef: HTMLInputElement | undefined;

  const handleFiles = (files: FileList | null) => {
    props.onFile(files && files.length > 0 ? files[0] : null);
  };

  return (
    <div
      class="drop-zone"
      classList={{ "drop-zone-active": dragOver(), "drop-zone-filled": !!props.file }}
      onClick={() => inputRef?.click()}
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragOver(false);
        handleFiles(e.dataTransfer?.files ?? null);
      }}
    >
      <input
        ref={inputRef}
        type="file"
        class="drop-zone-input"
        accept={props.accept}
        onChange={(e) => handleFiles(e.currentTarget.files)}
      />
      <Show
        when={props.file}
        fallback={
          <>
            <div class="drop-zone-label">{props.label}</div>
            <div class="drop-zone-hint">{props.hint}</div>
          </>
        }
      >
        <div class="drop-zone-filename">{props.file!.name}</div>
        <div class="drop-zone-hint">
          {formatBytes(props.file!.size)} &middot; click or drop to replace
        </div>
        <button
          type="button"
          class="drop-zone-clear"
          onClick={(e) => {
            e.stopPropagation();
            props.onFile(null);
            if (inputRef) inputRef.value = "";
          }}
        >
          Remove
        </button>
      </Show>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
