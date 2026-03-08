<script lang="ts">
  let { data }: { data: any } = $props();

  const items = $derived(Array.isArray(data) ? data : []);
</script>

<div class="bg-surface-700 border border-surface-600 rounded-xl p-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">IOC Cross-Reference</h3>
  {#if items.length === 0}
    <p class="text-xs text-gray-500 text-center py-4">No cross-references found</p>
  {:else}
    <div class="overflow-x-auto max-h-80">
      <table class="w-full text-xs">
        <thead>
          <tr class="text-gray-400 border-b border-surface-600">
            <th class="text-left p-2">IOC</th>
            <th class="text-left p-2">Type</th>
            <th class="text-left p-2">Case</th>
            <th class="text-left p-2">CTI Verdict</th>
          </tr>
        </thead>
        <tbody>
          {#each items.slice(0, 30) as item}
            <tr class="border-b border-surface-700/50">
              <td class="p-2 font-mono text-gray-300 truncate max-w-[200px]">{item.value || ''}</td>
              <td class="p-2 text-gray-400">{item.type || ''}</td>
              <td class="p-2 text-accent-400 font-mono">{item.case_id || ''}</td>
              <td class="p-2 text-gray-400">{item.opencti_verdict || '-'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if items.length > 30}
      <p class="text-[10px] text-gray-500 mt-2 text-center">Showing 30 of {items.length}</p>
    {/if}
  {/if}
</div>
