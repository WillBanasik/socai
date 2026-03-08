<script lang="ts">
  import type { Finding } from '../../lib/types';

  let { findings }: { findings: Finding[] } = $props();
</script>

<div class="space-y-3">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Findings</h3>
  {#if findings.length === 0}
    <p class="text-xs text-gray-500">No findings recorded</p>
  {:else}
    {#each findings as f}
      <div class="bg-surface-700 rounded-lg p-3">
        <span class="text-[10px] font-semibold text-accent-400 uppercase">{f.type}</span>
        <p class="text-xs text-gray-200 mt-1">{f.summary}</p>
        {#if f.detail}
          <p class="text-xs text-gray-400 mt-1">{f.detail}</p>
        {/if}
      </div>
    {/each}
  {/if}
</div>
