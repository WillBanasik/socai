<script lang="ts">
  import type { KQLQuery } from '../../lib/types';

  let { queries }: { queries: KQLQuery[] } = $props();
  let expanded: Record<number, boolean> = $state({});
</script>

<div class="space-y-3">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">KQL Queries</h3>
  {#if queries.length === 0}
    <p class="text-xs text-gray-500">No queries available</p>
  {:else}
    {#each queries as q, i}
      <div class="bg-surface-700 rounded-lg overflow-hidden">
        <button
          class="w-full flex items-center gap-2 px-3 py-2 text-left text-xs hover:bg-surface-600 transition-colors"
          onclick={() => expanded[i] = !expanded[i]}
        >
          <span class="px-1.5 py-0.5 rounded text-[10px] font-medium
            {q.status === 'executed' ? 'bg-green-500/20 text-green-400' : 'bg-blue-500/20 text-blue-400'}">
            {q.status}
          </span>
          <span class="text-gray-300 truncate flex-1">{q.description || 'Query'}</span>
        </button>
        {#if expanded[i]}
          <pre class="px-3 pb-3 text-xs text-gray-300 overflow-x-auto whitespace-pre-wrap">{q.query}</pre>
        {/if}
      </div>
    {/each}
  {/if}
</div>
