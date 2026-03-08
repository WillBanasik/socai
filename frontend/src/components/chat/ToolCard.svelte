<script lang="ts">
  import type { ToolCall } from '../../lib/types';
  import { getToolLabel } from '../../lib/utils/toolLabels';
  import { apiFetch } from '../../lib/api/client';

  let { tool }: { tool: ToolCall } = $props();
  let expanded = $state(false);
  let screenshotBlobs = $state<string[]>([]);
  let triedScreenshots = $state(false);

  const label = $derived(getToolLabel(tool.name));

  /** Extract a one-line summary from tool input for the header. */
  function inputSummary(input: any): string {
    if (!input) return '';
    if (input.query) return input.query.length > 80 ? input.query.slice(0, 80) + '...' : input.query;
    if (input.urls?.length) return input.urls.join(', ').slice(0, 80);
    if (input.workspace) return `workspace: ${input.workspace}`;
    if (input.case_id) return input.case_id;
    if (input.title) return input.title.slice(0, 60);
    if (input.file_path) return input.file_path.split('/').pop() || input.file_path;
    return '';
  }

  function extractCaseId(result: string | undefined): string {
    if (!result) return '';
    try {
      const data = JSON.parse(result);
      return data?.backing_case_id || data?.case_id || data?.result?.case_id || '';
    } catch {}
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

  $effect(() => {
    if (tool.result && tool.name === 'capture_urls' && !triedScreenshots) {
      loadScreenshots();
    }
  });

  const summary = $derived(inputSummary(tool.input));
</script>

<div class="border border-surface-600/50 bg-surface-800/50 rounded-lg overflow-hidden text-sm my-2">
  <button
    class="w-full flex items-center gap-2.5 px-3 py-2 text-left hover:bg-surface-700/50 transition-colors"
    onclick={() => expanded = !expanded}
  >
    <span class="w-1.5 h-1.5 rounded-full bg-tool flex-shrink-0"></span>
    <span class="text-tool font-medium flex-shrink-0">{label.agent}</span>
    <span class="text-gray-400 truncate flex-1">{label.task}{summary ? ` — ${summary}` : ''}</span>
    <svg
      class="w-3.5 h-3.5 text-gray-500 transition-transform flex-shrink-0 {expanded ? 'rotate-180' : ''}"
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
    <div class="px-3 pb-3 space-y-2 border-t border-surface-600/30">
      <div class="mt-2 flex items-center gap-2">
        <span class="text-[10px] font-semibold text-gray-500 uppercase">Tool</span>
        <code class="text-[11px] text-gray-400">{tool.name}</code>
      </div>
      {#if tool.input && Object.keys(tool.input).length > 0}
        <div>
          <span class="text-[10px] font-semibold text-gray-500 uppercase">Input</span>
          <pre class="mt-1 text-xs text-gray-400 bg-surface-900 rounded p-2 overflow-x-auto max-h-40 overflow-y-auto">{JSON.stringify(tool.input, null, 2)}</pre>
        </div>
      {/if}
      {#if tool.result}
        <div>
          <span class="text-[10px] font-semibold text-gray-500 uppercase">Result</span>
          <pre class="mt-1 text-xs text-gray-400 bg-surface-900 rounded p-2 overflow-x-auto max-h-60 overflow-y-auto whitespace-pre-wrap">{tool.result}</pre>
        </div>
      {/if}
    </div>
  {/if}
</div>
