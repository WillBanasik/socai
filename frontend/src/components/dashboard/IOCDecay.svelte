<script lang="ts">
  let { data }: { data: any } = $props();

  const summary = $derived(data?.summary || {});
  const indicators = $derived(data?.indicators || []);

  const statusColours: Record<string, string> = {
    active: 'text-green-400',
    expired: 'text-gray-400',
    revoked: 'text-red-400',
    not_in_cti: 'text-yellow-400',
    error: 'text-orange-400',
  };

  const dotColours: Record<string, string> = {
    active: 'bg-green-500',
    expired: 'bg-gray-500',
    revoked: 'bg-red-500',
    not_in_cti: 'bg-yellow-500',
    error: 'bg-orange-500',
  };
</script>

<div class="bg-surface-700 border border-surface-600 rounded-xl p-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">IOC Decay</h3>

  {#if Object.keys(summary).length > 0}
    <div class="flex gap-4 mb-3">
      {#each Object.entries(summary) as [status, count]}
        {#if status !== 'total'}
          <div class="text-center">
            <p class="text-lg font-bold {statusColours[status] || 'text-gray-300'}">{count}</p>
            <p class="text-[10px] text-gray-500">{status.replace(/_/g, ' ')}</p>
          </div>
        {/if}
      {/each}
    </div>
  {/if}

  {#if indicators.length > 0}
    <div class="max-h-48 overflow-y-auto space-y-1">
      {#each indicators.slice(0, 30) as entry}
        <div class="flex items-center gap-2 text-xs">
          <span class="w-2 h-2 rounded-full flex-shrink-0 {dotColours[entry.status] || 'bg-gray-500'}"></span>
          <span class="text-gray-300 font-mono truncate flex-1">{entry.ioc}</span>
          <span class="text-gray-500 flex-shrink-0">{entry.status}</span>
        </div>
      {/each}
    </div>
  {:else}
    <p class="text-xs text-gray-500 text-center">No decay data</p>
  {/if}
</div>
