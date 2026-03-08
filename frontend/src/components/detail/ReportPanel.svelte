<script lang="ts">
  import MarkdownBlock from '../shared/MarkdownBlock.svelte';

  let { content }: { content: string } = $props();
</script>

<div class="space-y-3">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Report</h3>
  {#if content}
    <div class="bg-surface-700 rounded-lg p-4 max-h-[500px] overflow-y-auto">
      <MarkdownBlock {content} />
    </div>
  {:else}
    <p class="text-xs text-gray-500">No report generated yet</p>
  {/if}
</div>
