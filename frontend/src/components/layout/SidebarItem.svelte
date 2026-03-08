<script lang="ts">
  let { label, sublabel = '', active = false, italic = false, href, onclick }:
    { label: string; sublabel?: string; active?: boolean; italic?: boolean; href?: string; onclick?: () => void } = $props();
</script>

{#if href}
  <a
    {href}
    class="flex flex-col px-3 py-2 rounded-md text-sm transition-colors truncate
      {active ? 'bg-accent-500/15 text-accent-400' : 'text-gray-300 hover:bg-surface-600 hover:text-gray-100'}"
  >
    <span class="truncate" class:italic>{label}</span>
    {#if sublabel}
      <span class="text-[10px] text-gray-500 truncate">{sublabel}</span>
    {/if}
  </a>
{:else}
  <button
    {onclick}
    class="w-full text-left flex flex-col px-3 py-2 rounded-md text-sm transition-colors truncate
      {active ? 'bg-accent-500/15 text-accent-400' : 'text-gray-300 hover:bg-surface-600 hover:text-gray-100'}"
  >
    <span class="truncate" class:italic>{label}</span>
    {#if sublabel}
      <span class="text-[10px] text-gray-500 truncate">{sublabel}</span>
    {/if}
  </button>
{/if}
