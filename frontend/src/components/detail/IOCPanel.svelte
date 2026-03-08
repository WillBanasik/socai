<script lang="ts">
  import type { IOCSet } from '../../lib/types';

  let { iocs }: { iocs: IOCSet } = $props();

  const types = $derived(
    Object.entries(iocs).filter(([_, v]) => v && v.length > 0)
  );

  let expanded: Record<string, boolean> = $state({});
</script>

<div class="space-y-3">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">IOCs</h3>
  {#each types as [type, items]}
    <div>
      <button
        class="flex items-center gap-2 text-xs font-medium text-gray-300 hover:text-gray-100 w-full text-left"
        onclick={() => expanded[type] = !expanded[type]}
      >
        <svg class="w-3 h-3 transition-transform {expanded[type] ? 'rotate-90' : ''}" fill="currentColor" viewBox="0 0 20 20">
          <path d="M6 6l8 4-8 4V6z" />
        </svg>
        {type} <span class="text-gray-500">({(items || []).length})</span>
      </button>
      {#if expanded[type]}
        <div class="mt-1 ml-5 space-y-0.5">
          {#each (items || []).slice(0, 20) as ioc}
            <div class="text-xs font-mono text-gray-300 bg-surface-700 px-2 py-1 rounded truncate">{ioc}</div>
          {/each}
          {#if (items || []).length > 20}
            <span class="text-[10px] text-gray-500">+{(items || []).length - 20} more</span>
          {/if}
        </div>
      {/if}
    </div>
  {/each}
  {#if types.length === 0}
    <p class="text-xs text-gray-500">No IOCs extracted</p>
  {/if}
</div>
