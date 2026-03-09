<script lang="ts">
  import SuggestionChips from './SuggestionChips.svelte';

  let { onsend = (_text: string) => {} }: { onsend?: (text: string) => void } = $props();
</script>

<div class="flex flex-col items-center justify-center h-full px-4">
  <div class="max-w-lg text-center">
    <h2 class="text-2xl font-bold mb-2"><span class="text-accent-400">soc</span><span class="text-white italic">ai</span></h2>
    <p class="text-gray-400 text-sm">
      Security Operations Centre AI assistant. Start a conversation, investigate threats, or manage cases.
    </p>
    <p class="text-gray-500 text-xs mt-3">
      Type <code class="px-1.5 py-0.5 rounded bg-surface-700 text-gray-400">/help</code> for commands or
      <code class="px-1.5 py-0.5 rounded bg-surface-700 text-gray-400">/prompts</code> for examples
    </p>
    <SuggestionChips {onsend} />
  </div>
</div>
