<script lang="ts">
  import { navigate } from '../../lib/router';

  let { caseId, title, severity }: { caseId: string; title?: string; severity?: string } = $props();
</script>

<div class="mx-4 mb-3 p-3 rounded-lg bg-green-500/10 border border-green-500/30 flex items-center gap-3 fade-in">
  <span class="w-2 h-2 rounded-full bg-green-500 flex-shrink-0"></span>
  <div class="flex-1 min-w-0">
    <p class="text-sm text-green-300 font-medium">Case created: {caseId}</p>
    {#if title}
      <p class="text-xs text-green-400/70 truncate">{title}</p>
    {/if}
  </div>
  <button
    class="text-xs px-3 py-1.5 bg-green-500/20 hover:bg-green-500/30 border border-green-500/40
      rounded-lg text-green-300 transition-colors flex-shrink-0"
    onclick={() => navigate(`/chat/${caseId}`)}
  >
    Open case
  </button>
</div>
