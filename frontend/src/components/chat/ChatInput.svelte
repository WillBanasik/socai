<script lang="ts">
  import { streaming, pendingFiles, modelTier } from '../../lib/stores/chat';
  import FileUploadPill from './FileUploadPill.svelte';

  let { onsend }: { onsend: (text: string) => void } = $props();

  let text = $state('');
  let fileInput: HTMLInputElement;

  function handleKeyDown(e: KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  }

  function send() {
    const trimmed = text.trim();
    if (!trimmed || $streaming) return;
    onsend(trimmed);
    text = '';
  }

  function handleFiles(files: FileList | null) {
    if (!files) return;
    pendingFiles.update((f) => [...f, ...Array.from(files)]);
  }

  function removeFile(idx: number) {
    pendingFiles.update((f) => f.filter((_, i) => i !== idx));
  }

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    handleFiles(e.dataTransfer?.files || null);
  }

  function handleDragOver(e: DragEvent) {
    e.preventDefault();
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="border-t border-surface-600 bg-surface-800 px-4 py-3"
  ondrop={handleDrop}
  ondragover={handleDragOver}
>
  {#if $pendingFiles.length > 0}
    <div class="flex flex-wrap gap-1 mb-2">
      {#each $pendingFiles as file, i}
        <FileUploadPill filename={file.name} onremove={() => removeFile(i)} />
      {/each}
    </div>
  {/if}

  <div class="flex items-end gap-2">
    <button
      class="flex-shrink-0 p-2 text-gray-400 hover:text-gray-200 hover:bg-surface-600 rounded-lg transition-colors"
      onclick={() => fileInput.click()}
      title="Upload file"
    >
      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
      </svg>
    </button>

    <textarea
      bind:value={text}
      onkeydown={handleKeyDown}
      placeholder="Type a message... (Enter to send, Shift+Enter for newline)"
      disabled={$streaming}
      rows="1"
      class="flex-1 resize-none bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-gray-200
        placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-accent-500/50 focus:border-accent-500
        disabled:opacity-50 min-h-[40px] max-h-[200px]"
      style="field-sizing: content;"
    ></textarea>

    <!-- Model tier selector -->
    <select
      bind:value={$modelTier}
      class="flex-shrink-0 bg-surface-700 border border-surface-600 rounded-lg px-2 py-2 text-xs text-gray-300
        focus:outline-none focus:ring-2 focus:ring-accent-500/50"
    >
      <option value="fast">Fast</option>
      <option value="standard">Standard</option>
      <option value="heavy">Heavy</option>
    </select>

    <button
      onclick={send}
      disabled={!text.trim() || $streaming}
      class="flex-shrink-0 p-2.5 bg-accent-500 hover:bg-accent-600 disabled:opacity-30 disabled:cursor-not-allowed
        rounded-xl text-white transition-colors"
      title="Send message"
    >
      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
      </svg>
    </button>
  </div>

  <input
    bind:this={fileInput}
    type="file"
    multiple
    class="hidden"
    onchange={(e) => handleFiles((e.target as HTMLInputElement).files)}
  />
</div>
