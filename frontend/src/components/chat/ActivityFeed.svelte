<script lang="ts">
  import type { ActivityItem } from '../../lib/types';
  import { getToolLabel } from '../../lib/utils/toolLabels';

  let { items }: { items: ActivityItem[] } = $props();

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
</script>

<div class="mb-3 space-y-1">
  {#each items as item}
    {@const label = getToolLabel(item.name)}
    {@const summary = inputSummary(item.input)}
    <div class="flex items-center gap-2.5 px-3 py-2 rounded-lg border border-surface-600/50 bg-surface-800/50 text-xs">
      {#if item.status === 'running'}
        <span class="w-2 h-2 rounded-full bg-yellow-400 pulse-amber flex-shrink-0"></span>
      {:else if item.status === 'done'}
        <span class="w-2 h-2 rounded-full bg-green-500 flex-shrink-0"></span>
      {:else}
        <span class="w-2 h-2 rounded-full bg-red-500 flex-shrink-0"></span>
      {/if}
      <span class="text-tool font-medium flex-shrink-0">{label.agent}</span>
      <span class="text-gray-400 truncate flex-1">{label.task}{summary ? ` — ${summary}` : ''}</span>
    </div>
  {/each}
</div>
