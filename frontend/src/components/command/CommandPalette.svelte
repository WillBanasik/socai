<script lang="ts">
  import { paletteOpen, paletteQuery, filteredActions } from '../../lib/stores/commandPalette';
  import CommandItem from './CommandItem.svelte';

  let activeIdx = $state(0);
  let input = $state<HTMLInputElement>(null!);

  $effect(() => {
    if ($paletteOpen) {
      activeIdx = 0;
      paletteQuery.set('');
      // focus input after render
      setTimeout(() => input?.focus(), 50);
    }
  });

  $effect(() => {
    // reset active index when query changes
    $paletteQuery;
    activeIdx = 0;
  });

  function handleKey(e: KeyboardEvent) {
    const items = $filteredActions;
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      activeIdx = Math.min(activeIdx + 1, items.length - 1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      activeIdx = Math.max(activeIdx - 1, 0);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (items[activeIdx]) {
        items[activeIdx].action();
        paletteOpen.set(false);
      }
    } else if (e.key === 'Escape') {
      paletteOpen.set(false);
    }
  }

  function handleBackdrop(e: MouseEvent) {
    if (e.target === e.currentTarget) paletteOpen.set(false);
  }

  // Group by section
  const grouped = $derived.by(() => {
    const groups: Record<string, typeof $filteredActions> = {};
    for (const a of $filteredActions) {
      (groups[a.section] ??= []).push(a);
    }
    return groups;
  });
</script>

{#if $paletteOpen}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <!-- svelte-ignore a11y_interactive_supports_focus -->
  <div
    class="fixed inset-0 z-[60] flex items-start justify-center pt-[15vh] bg-black/50 backdrop-blur-sm"
    onclick={handleBackdrop}
    onkeydown={handleKey}
    role="dialog"
    aria-modal="true"
  >
    <div class="w-full max-w-lg bg-surface-800 border border-surface-600 rounded-xl shadow-2xl overflow-hidden fade-in">
      <div class="px-4 py-3 border-b border-surface-600">
        <input
          bind:this={input}
          bind:value={$paletteQuery}
          placeholder="Type a command..."
          class="w-full bg-transparent text-sm text-gray-200 placeholder-gray-500 focus:outline-none"
        />
      </div>

      <div class="max-h-80 overflow-y-auto">
        {#each Object.entries(grouped) as [section, actions]}
          <div class="px-4 pt-2 pb-1">
            <span class="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">{section}</span>
          </div>
          {#each actions as action, i}
            {@const globalIdx = $filteredActions.indexOf(action)}
            <CommandItem {action} active={globalIdx === activeIdx} />
          {/each}
        {/each}
        {#if $filteredActions.length === 0}
          <p class="text-sm text-gray-500 text-center py-6">No matching commands</p>
        {/if}
      </div>
    </div>
  </div>
{/if}
