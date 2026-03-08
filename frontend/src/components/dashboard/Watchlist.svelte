<script lang="ts">
  import { addToWatchlist, removeFromWatchlist } from '../../lib/api/cti';
  import { addToast } from '../../lib/stores/toasts';
  import { relativeTime } from '../../lib/utils/time';

  let { items = [], onrefresh }: { items: any[]; onrefresh: () => void } = $props();

  let newName = $state('');

  async function handleAdd() {
    if (!newName.trim()) return;
    try {
      await addToWatchlist(newName.trim(), '');
      newName = '';
      onrefresh();
    } catch (e: any) {
      addToast('error', e.message);
    }
  }

  async function handleRemove(name: string) {
    try {
      await removeFromWatchlist(name);
      onrefresh();
    } catch (e: any) {
      addToast('error', e.message);
    }
  }
</script>

<div class="bg-surface-700 border border-surface-600 rounded-xl p-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">Watchlist</h3>

  <div class="flex gap-2 mb-3">
    <input
      bind:value={newName}
      placeholder="Threat actor name"
      class="flex-1 px-2 py-1.5 bg-surface-800 border border-surface-600 rounded text-xs text-gray-200
        placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-accent-500/50"
      onkeydown={(e) => e.key === 'Enter' && handleAdd()}
    />
    <button
      onclick={handleAdd}
      disabled={!newName.trim()}
      class="px-3 py-1.5 bg-accent-500/20 hover:bg-accent-500/30 border border-accent-500/40
        rounded text-xs text-accent-300 disabled:opacity-30 transition-colors"
    >Add</button>
  </div>

  <div class="space-y-2 max-h-60 overflow-y-auto">
    {#each items as entry}
      <div class="p-2 bg-surface-800 rounded">
        <div class="flex items-center gap-2">
          <span class="text-sm text-gray-200 font-medium flex-1">{entry.name}</span>
          <button
            class="text-gray-500 hover:text-red-400 text-xs"
            onclick={() => handleRemove(entry.name)}
          >&times;</button>
        </div>
        {#if entry.description}
          <p class="text-[10px] text-gray-400 mt-1 line-clamp-2">{entry.description}</p>
        {/if}
        {#if entry.added}
          <span class="text-[10px] text-gray-500">{relativeTime(entry.added)}</span>
        {/if}
      </div>
    {/each}
    {#if items.length === 0}
      <p class="text-xs text-gray-500 text-center py-2">No actors on watchlist</p>
    {/if}
  </div>
</div>
