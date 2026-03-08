<script lang="ts">
  import { renderMarkdown } from '../../lib/utils/markdown';

  let { content }: { content: string } = $props();

  const html = $derived(renderMarkdown(content));
</script>

<div class="markdown-content text-sm text-gray-200">
  {@html html}
</div>
