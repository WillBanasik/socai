<script lang="ts">
  let { files, onfileschange }: { files: File[]; onfileschange: (files: File[]) => void } = $props();

  let dragging = $state(false);
  let fileInput: HTMLInputElement;

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    dragging = false;
    if (e.dataTransfer?.files) {
      onfileschange([...files, ...Array.from(e.dataTransfer.files)]);
    }
  }

  function handleSelect(e: Event) {
    const input = e.target as HTMLInputElement;
    if (input.files) {
      onfileschange([...files, ...Array.from(input.files)]);
    }
  }

  function removeFile(idx: number) {
    onfileschange(files.filter((_, i) => i !== idx));
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<!-- svelte-ignore a11y_click_events_have_key_events -->
<div
  class="border-2 border-dashed rounded-xl p-6 text-center transition-colors cursor-pointer
    {dragging ? 'border-accent-400 bg-accent-500/5' : 'border-surface-500 hover:border-surface-400'}"
  ondragover={(e) => { e.preventDefault(); dragging = true; }}
  ondragleave={() => dragging = false}
  ondrop={handleDrop}
  onclick={() => fileInput.click()}
  role="button"
  tabindex="0"
>
  <svg class="w-8 h-8 mx-auto text-gray-500 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
  </svg>
  <p class="text-sm text-gray-400">Drop files here or click to browse</p>
  <p class="text-[10px] text-gray-600 mt-1">.zip .eml .exe .dll .pdf .csv .json .xlsx</p>
</div>

<input
  bind:this={fileInput}
  type="file"
  multiple
  class="hidden"
  accept=".zip,.eml,.exe,.dll,.pdf,.csv,.json,.xlsx"
  onchange={handleSelect}
/>

{#if files.length > 0}
  <div class="mt-3 space-y-1">
    {#each files as file, i}
      <div class="flex items-center gap-2 px-3 py-2 bg-surface-700 rounded-lg text-xs">
        <svg class="w-4 h-4 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        <span class="text-gray-300 flex-1 truncate">{file.name}</span>
        <span class="text-gray-500">{(file.size / 1024).toFixed(1)} KB</span>
        <button class="text-gray-500 hover:text-red-400" onclick={(e) => { e.stopPropagation(); removeFile(i); }}>&times;</button>
      </div>
    {/each}
  </div>
{/if}
