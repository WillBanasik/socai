<script lang="ts">
  import type { CommandAction } from '../../lib/types';

  let { action, active = false }: { action: CommandAction; active?: boolean } = $props();
</script>

<button
  class="w-full flex items-center gap-3 px-4 py-2.5 text-left text-sm transition-colors
    {active ? 'bg-accent-500/15 text-accent-300' : 'text-gray-300 hover:bg-surface-600'}"
  onclick={action.action}
>
  <span class="flex-1">{action.label}</span>
  {#if action.shortcut}
    <kbd class="text-[10px] text-gray-500 bg-surface-700 px-1.5 py-0.5 rounded border border-surface-600">{action.shortcut}</kbd>
  {/if}
</button>
