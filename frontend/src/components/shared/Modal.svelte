<script lang="ts">
  import type { Snippet } from 'svelte';

  let { open = false, onclose, children }: { open: boolean; onclose: () => void; children: Snippet } = $props();

  function handleBackdrop(e: MouseEvent) {
    if (e.target === e.currentTarget) onclose();
  }

  function handleKey(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose();
  }
</script>

{#if open}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
    onclick={handleBackdrop}
    onkeydown={handleKey}
    role="dialog"
    aria-modal="true"
  >
    <div class="fade-in">
      {@render children()}
    </div>
  </div>
{/if}
