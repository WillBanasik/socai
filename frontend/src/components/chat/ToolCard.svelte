<script lang="ts">
  import type { ToolCall } from '../../lib/types';
  import { apiFetch } from '../../lib/api/client';

  let { tool }: { tool: ToolCall } = $props();
  let expanded = $state(false);
  let screenshotBlobs = $state<string[]>([]);
  let triedScreenshots = $state(false);

  function extractCaseId(result: string | undefined): string {
    if (!result) return '';
    // Try JSON parse first
    try {
      const data = JSON.parse(result);
      return data?.backing_case_id || data?.case_id || data?.result?.case_id || '';
    } catch {}
    // Fallback: regex
    const m = result.match(/C\d{3,}/);
    return m ? m[0] : '';
  }

  async function loadScreenshots() {
    if (triedScreenshots) return;
    if (tool.name !== 'capture_urls') return;
    if (!tool.result || !tool.input?.urls?.length) return;

    triedScreenshots = true;
    const caseId = extractCaseId(tool.result);
    if (!caseId) return;

    const urls: string[] = tool.input.urls;
    const blobs: string[] = [];

    for (const u of urls) {
      try {
        const hostname = new URL(u.startsWith('http') ? u : `https://${u}`).hostname;
        const apiUrl = `/api/cases/${caseId}/artefacts/web/${hostname}/screenshot.png`;
        const resp = await apiFetch(apiUrl);
        if (resp.ok) {
          const blob = await resp.blob();
          blobs.push(URL.createObjectURL(blob));
        }
      } catch {}
    }
    screenshotBlobs = blobs;
  }

  // Trigger screenshot loading when result becomes available
  $effect(() => {
    if (tool.result && tool.name === 'capture_urls' && !triedScreenshots) {
      loadScreenshots();
    }
  });
</script>

<div class="border border-tool/30 bg-tool-bg rounded-lg overflow-hidden text-sm my-2">
  <button
    class="w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-tool/10 transition-colors"
    onclick={() => expanded = !expanded}
  >
    <span class="w-1.5 h-1.5 rounded-full bg-tool flex-shrink-0"></span>
    <span class="text-tool font-medium flex-1 truncate">{tool.name}</span>
    <svg
      class="w-4 h-4 text-gray-400 transition-transform {expanded ? 'rotate-180' : ''}"
      fill="none" stroke="currentColor" viewBox="0 0 24 24"
    >
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
    </svg>
  </button>

  {#if screenshotBlobs.length > 0}
    <div class="px-3 pb-2 space-y-2">
      {#each screenshotBlobs as blobUrl}
        <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
        <img
          src={blobUrl}
          alt="Captured screenshot"
          class="rounded border border-surface-600 max-h-96 w-auto cursor-pointer hover:opacity-90 transition-opacity"
          onclick={() => window.open(blobUrl, '_blank')}
          onkeydown={() => {}}
        />
      {/each}
    </div>
  {/if}

  {#if expanded}
    <div class="px-3 pb-3 space-y-2 border-t border-tool/20">
      {#if tool.input && Object.keys(tool.input).length > 0}
        <div class="mt-2">
          <span class="text-[10px] font-semibold text-gray-500 uppercase">Input</span>
          <pre class="mt-1 text-xs text-gray-300 bg-surface-800 rounded p-2 overflow-x-auto max-h-40 overflow-y-auto">{JSON.stringify(tool.input, null, 2)}</pre>
        </div>
      {/if}
      {#if tool.result}
        <div>
          <span class="text-[10px] font-semibold text-gray-500 uppercase">Result</span>
          <pre class="mt-1 text-xs text-gray-300 bg-surface-800 rounded p-2 overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap">{tool.result}</pre>
        </div>
      {/if}
    </div>
  {/if}
</div>
