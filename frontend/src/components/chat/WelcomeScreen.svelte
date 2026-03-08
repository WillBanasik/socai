<script lang="ts">
  let { onsend }: { onsend: (text: string) => void } = $props();

  const chips = [
    'Investigate a suspicious URL',
    'Analyse a phishing email',
    'Enrich these IOCs',
    'Generate an MDR report',
    'Triage an alert',
    'Check for similar campaigns',
  ];
</script>

<div class="flex flex-col items-center justify-center h-full px-4">
  <div class="max-w-lg text-center">
    <h2 class="text-2xl font-bold text-gray-200 mb-2">socai</h2>
    <p class="text-gray-400 text-sm mb-8">
      Security Operations Centre AI assistant. Start a conversation, investigate threats, or manage cases.
    </p>

    <div class="grid grid-cols-2 gap-2">
      {#each chips as chip}
        <button
          class="text-left px-4 py-3 rounded-xl bg-surface-700 border border-surface-600
            hover:border-accent-500/50 hover:bg-surface-600 transition-colors text-sm text-gray-300"
          onclick={() => onsend(chip)}
        >
          {chip}
        </button>
      {/each}
    </div>
  </div>
</div>
