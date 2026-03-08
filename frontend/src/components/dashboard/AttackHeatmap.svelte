<script lang="ts">
  let { data }: { data: any } = $props();

  const techniques = $derived(data?.top_techniques || []);

  function heatColour(count: number): string {
    if (count <= 100) return 'bg-red-900/30';
    if (count <= 500) return 'bg-red-800/40';
    if (count <= 1000) return 'bg-red-700/50';
    return 'bg-red-600/60';
  }
</script>

<div class="bg-surface-700 border border-surface-600 rounded-xl p-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">MITRE ATT&CK Top Techniques</h3>
  {#if techniques.length === 0}
    <p class="text-xs text-gray-500 text-center py-4">No heatmap data available</p>
  {:else}
    <div class="space-y-1.5">
      {#each techniques.slice(0, 15) as tech}
        <div class="flex items-center gap-2">
          <span class="text-[10px] font-mono text-gray-400 w-12 flex-shrink-0">{tech.id || tech.name}</span>
          <div class="flex-1 h-5 rounded overflow-hidden bg-surface-800">
            <div
              class="{heatColour(tech.count)} h-full rounded flex items-center px-2"
              style="width: {Math.min(100, (tech.count / (techniques[0]?.count || 1)) * 100)}%"
            >
              <span class="text-[10px] text-gray-200 font-mono">{tech.count}</span>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>
