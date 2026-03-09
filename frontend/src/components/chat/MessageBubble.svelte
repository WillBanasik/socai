<script lang="ts">
  import type { ChatMessage } from '../../lib/types';
  import MarkdownBlock from '../shared/MarkdownBlock.svelte';
  import ToolCard from './ToolCard.svelte';

  let { message, isLast = false, onregenerate, onedit }:
    { message: ChatMessage; isLast?: boolean; onregenerate?: () => void; onedit?: (content: string) => void } = $props();

  const isUser = $derived(message.role === 'user');

  let editing = $state(false);
  let editText = $state('');
  let showActions = $state(false);

  function startEdit() {
    editText = message.content;
    editing = true;
  }

  function submitEdit() {
    if (editText.trim() && onedit) {
      onedit(editText.trim());
    }
    editing = false;
  }

  function cancelEdit() {
    editing = false;
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="fade-in flex {isUser ? 'justify-end' : 'justify-start'} mb-3 group"
  onmouseenter={() => showActions = true}
  onmouseleave={() => showActions = false}
>
  <div class="max-w-[85%] {isUser ? 'order-2' : ''}">
    {#if isUser}
      {#if editing}
        <div class="bg-accent-500/20 border border-accent-500/30 rounded-2xl rounded-br-md px-4 py-2.5">
          <textarea
            bind:value={editText}
            rows="3"
            class="w-full bg-transparent text-sm text-gray-100 focus:outline-none resize-y min-w-[300px]"
          ></textarea>
          <div class="flex gap-2 mt-2">
            <button
              onclick={submitEdit}
              class="text-xs px-3 py-1 bg-accent-500 text-white rounded-lg hover:bg-accent-600"
            >Send</button>
            <button
              onclick={cancelEdit}
              class="text-xs px-3 py-1 text-gray-400 hover:text-gray-200"
            >Cancel</button>
          </div>
        </div>
      {:else}
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
        {#if showActions && onedit}
          <div class="flex justify-end mt-0.5">
            <button
              onclick={startEdit}
              class="text-[10px] text-gray-500 hover:text-gray-300 px-1.5 py-0.5 transition-colors"
              title="Edit and resend"
            >edit</button>
          </div>
        {/if}
      {/if}
    {:else}
      <div class="bg-surface-700 border border-surface-600 rounded-2xl rounded-bl-md px-4 py-2.5">
        {#if message.tool_calls && message.tool_calls.length > 0}
          {#each message.tool_calls as tool}
            <ToolCard {tool} />
          {/each}
        {/if}
        <MarkdownBlock content={message.content} />
      </div>
      {#if showActions && isLast && onregenerate}
        <div class="flex mt-0.5">
          <button
            onclick={onregenerate}
            class="text-[10px] text-gray-500 hover:text-gray-300 px-1.5 py-0.5 transition-colors flex items-center gap-1"
            title="Regenerate response"
          >
            <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            regenerate
          </button>
        </div>
      {/if}
    {/if}
  </div>
</div>
