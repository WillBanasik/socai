<script lang="ts">
  import { getLandscape } from '../../lib/api/landscape';
  import { onMount } from 'svelte';

  let data = $state<any>(null);
  let loading = $state(true);
  let error = $state(false);

  onMount(async () => {
    try {
      data = await getLandscape();
    } catch {
      error = true;
    }
    loading = false;
  });
</script>

<div class="bg-surface-700 border border-surface-600 rounded-xl p-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Internal Intelligence</h3>
  {#if loading}
    <p class="text-xs text-gray-500">Loading...</p>
  {:else if data}
    <div class="space-y-3 text-xs text-gray-300">
      {#if data.case_stats}
        <div>
          <span class="text-gray-400 font-medium">Case Stats:</span>
          <div class="mt-1 grid grid-cols-2 gap-2">
            {#each Object.entries(data.case_stats) as [key, val]}
              <div class="flex justify-between">
                <span class="text-gray-400">{key}</span>
                <span class="font-mono">{val}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
      {#if data.high_risk_iocs}
        <div>
          <span class="text-gray-400 font-medium">High-Risk IOCs:</span>
          <div class="mt-1 space-y-0.5">
            {#each (Array.isArray(data.high_risk_iocs) ? data.high_risk_iocs : []).slice(0, 10) as ioc}
              <div class="font-mono text-gray-300 bg-surface-800 px-2 py-1 rounded truncate">{typeof ioc === 'string' ? ioc : JSON.stringify(ioc)}</div>
            {/each}
          </div>
        </div>
      {/if}
    </div>
  {:else if error}
    <p class="text-xs text-gray-500">Failed to load landscape data (timed out or unavailable)</p>
  {:else}
    <p class="text-xs text-gray-500">No internal intelligence data</p>
  {/if}
</div>
