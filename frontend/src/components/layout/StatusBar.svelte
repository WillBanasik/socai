<script lang="ts">
  import { activeCaseId, activeSessionId } from '../../lib/stores/navigation';
  import { streaming, modelTier } from '../../lib/stores/chat';
</script>

<footer class="h-6 bg-surface-900 border-t border-surface-700 flex items-center px-3 text-[10px] text-gray-500 gap-4 flex-shrink-0">
  <span class="flex items-center gap-1.5">
    <span class="w-1.5 h-1.5 rounded-full {$streaming ? 'bg-yellow-400 pulse-amber' : 'bg-green-500'}"></span>
    {$streaming ? 'streaming' : 'connected'}
  </span>

  {#if $activeCaseId}
    <span>case: {$activeCaseId}</span>
  {:else if $activeSessionId}
    <span>session: {$activeSessionId.slice(0, 12)}</span>
  {/if}

  <div class="flex-1"></div>

  <span>model: {$modelTier}</span>
</footer>
