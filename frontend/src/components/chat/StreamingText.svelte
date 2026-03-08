<script lang="ts">
  import { renderMarkdown } from '../../lib/utils/markdown';

  let { text }: { text: string } = $props();

  const html = $derived(renderMarkdown(text));
</script>

<div class="markdown-content text-sm text-gray-200">
  {@html html}<span class="inline-block w-2 h-4 bg-accent-400 animate-pulse ml-0.5 align-text-bottom"></span>
</div>
