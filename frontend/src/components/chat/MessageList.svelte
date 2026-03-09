<script lang="ts">
  import { messages, streaming, streamText, activity } from '../../lib/stores/chat';
  import MessageBubble from './MessageBubble.svelte';
  import StreamingText from './StreamingText.svelte';
  import ActivityFeed from './ActivityFeed.svelte';
  import ScrollToBottom from './ScrollToBottom.svelte';
  import { onMount, tick } from 'svelte';

  let { onregenerate, onedit }:
    { onregenerate?: () => void; onedit?: (content: string, index: number) => void } = $props();

  let container: HTMLDivElement;
  let atBottom = $state(true);

  function checkScroll() {
    if (!container) return;
    const threshold = 80;
    atBottom = container.scrollHeight - container.scrollTop - container.clientHeight < threshold;
  }

  async function scrollToBottom() {
    await tick();
    if (container) {
      container.scrollTo({ top: container.scrollHeight, behavior: 'smooth' });
    }
  }

  // Auto-scroll when new content arrives and user is at bottom
  $effect(() => {
    // depend on these
    $messages;
    $streamText;
    if (atBottom) scrollToBottom();
  });

  onMount(() => {
    scrollToBottom();
  });

  // Find the last assistant message index
  const lastAssistantIdx = $derived(
    (() => {
      for (let i = $messages.length - 1; i >= 0; i--) {
        if ($messages[i].role === 'assistant') return i;
      }
      return -1;
    })()
  );
</script>

<div
  bind:this={container}
  onscroll={checkScroll}
  class="flex-1 overflow-y-auto px-4 py-4"
>
  {#each $messages as msg, i (i)}
    <MessageBubble
      message={msg}
      isLast={i === lastAssistantIdx}
      onregenerate={i === lastAssistantIdx ? onregenerate : undefined}
      onedit={msg.role === 'user' ? (content) => onedit?.(content, i) : undefined}
    />
  {/each}

  {#if $streaming}
    {#if $activity.length > 0}
      <ActivityFeed items={$activity} />
    {/if}
    {#if $streamText}
      <div class="flex justify-start mb-3">
        <div class="max-w-[85%] bg-surface-700 border border-surface-600 rounded-2xl rounded-bl-md px-4 py-2.5">
          <StreamingText text={$streamText} />
        </div>
      </div>
    {/if}
  {/if}
</div>

{#if !atBottom}
  <ScrollToBottom onclick={scrollToBottom} />
{/if}
