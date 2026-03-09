<script lang="ts">
  import { activeCaseId, activeSessionId } from '../../lib/stores/navigation';
  import { streaming, sessionTokens } from '../../lib/stores/chat';

  function formatTokens(n: number): string {
    if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
    return String(n);
  }

  const totalTokens = $derived($sessionTokens.input + $sessionTokens.output);
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

  {#if totalTokens > 0}
    <span class="flex items-center gap-1" title="Tokens this session: {$sessionTokens.input} in / {$sessionTokens.output} out">
      <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
      {formatTokens(totalTokens)}
    </span>
  {/if}


</footer>
