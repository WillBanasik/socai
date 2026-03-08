<script lang="ts">
  import type { ChatMessage } from '../../lib/types';
  import MarkdownBlock from '../shared/MarkdownBlock.svelte';
  import ToolCard from './ToolCard.svelte';

  let { message }: { message: ChatMessage } = $props();

  const isUser = $derived(message.role === 'user');
</script>

<div class="fade-in flex {isUser ? 'justify-end' : 'justify-start'} mb-3">
  <div class="max-w-[85%] {isUser ? 'order-2' : ''}">
    {#if isUser}
      <div class="bg-accent-500/20 border border-accent-500/30 rounded-2xl rounded-br-md px-4 py-2.5">
        <p class="text-sm text-gray-100 whitespace-pre-wrap">{message.content}</p>
        {#if message.files && message.files.length > 0}
          <div class="mt-2 flex flex-wrap gap-1">
            {#each message.files as file}
              <span class="text-[10px] bg-accent-500/20 text-accent-300 px-2 py-0.5 rounded-full">{file}</span>
            {/each}
          </div>
        {/if}
      </div>
    {:else}
      <div class="bg-surface-700 border border-surface-600 rounded-2xl rounded-bl-md px-4 py-2.5">
        {#if message.tool_calls && message.tool_calls.length > 0}
          {#each message.tool_calls as tool}
            <ToolCard {tool} />
          {/each}
        {/if}
        <MarkdownBlock content={message.content} />
      </div>
    {/if}
  </div>
</div>
