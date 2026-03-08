<script lang="ts">
  import type { ActivityItem } from '../../lib/types';

  let { items }: { items: ActivityItem[] } = $props();
</script>

<div class="mb-3 space-y-1">
  {#each items as item}
    <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-700/50 text-xs">
      {#if item.status === 'running'}
        <span class="w-2 h-2 rounded-full bg-yellow-400 pulse-amber"></span>
        <span class="text-yellow-300 font-medium">{item.name}</span>
        <span class="text-gray-500">running...</span>
      {:else if item.status === 'done'}
        <span class="w-2 h-2 rounded-full bg-green-500"></span>
        <span class="text-green-300 font-medium">{item.name}</span>
        <span class="text-gray-500">done</span>
      {:else}
        <span class="w-2 h-2 rounded-full bg-red-500"></span>
        <span class="text-red-300 font-medium">{item.name}</span>
        <span class="text-gray-500">error</span>
      {/if}
    </div>
  {/each}
</div>
