<script lang="ts">
  let { verdicts }: { verdicts: any } = $props();
</script>

<div class="space-y-3">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Verdicts</h3>

  {#if verdicts?.high?.length}
    <div class="bg-red-500/5 border border-red-500/20 rounded-lg p-3">
      <p class="text-xs font-semibold text-red-400 mb-1">High Priority</p>
      {#each verdicts.high as v}
        <p class="text-xs text-gray-300">{v}</p>
      {/each}
    </div>
  {/if}

  {#if verdicts?.medium?.length}
    <div class="bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-3">
      <p class="text-xs font-semibold text-yellow-400 mb-1">Medium Priority</p>
      {#each verdicts.medium as v}
        <p class="text-xs text-gray-300">{v}</p>
      {/each}
    </div>
  {/if}

  {#if verdicts?.low?.length}
    <div class="bg-green-500/5 border border-green-500/20 rounded-lg p-3">
      <p class="text-xs font-semibold text-green-400 mb-1">Low Priority</p>
      {#each verdicts.low as v}
        <p class="text-xs text-gray-300">{v}</p>
      {/each}
    </div>
  {/if}

  {#if !verdicts?.high?.length && !verdicts?.medium?.length && !verdicts?.low?.length}
    <p class="text-xs text-gray-500">No verdicts available</p>
  {/if}
</div>
