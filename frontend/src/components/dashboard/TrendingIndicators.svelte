<script lang="ts">
  let { items }: { items: any[] } = $props();
</script>

<div class="bg-surface-700 border border-surface-600 rounded-xl p-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Trending Indicators</h3>
  <div class="space-y-2 max-h-80 overflow-y-auto">
    {#each items.slice(0, 15) as item}
      <div class="flex items-center gap-3 text-sm">
        <span class="w-8 text-right text-xs font-mono text-accent-400">{item.score ?? '-'}</span>
        <span class="text-gray-200 flex-1 truncate font-mono text-xs" title={item.name}>{item.name}</span>
        {#if item.author}
          <span class="text-[10px] text-gray-500">{item.author}</span>
        {/if}
      </div>
    {/each}
    {#if items.length === 0}
      <p class="text-xs text-gray-500 text-center py-4">No trending data</p>
    {/if}
  </div>
</div>
