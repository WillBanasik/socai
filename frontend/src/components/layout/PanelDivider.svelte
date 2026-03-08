<script lang="ts">
  let { onresize, direction = 'horizontal' }: { onresize: (delta: number) => void; direction?: 'horizontal' | 'vertical' } = $props();

  let dragging = $state(false);

  function onPointerDown(e: PointerEvent) {
    dragging = true;
    const target = e.currentTarget as HTMLElement;
    target.setPointerCapture(e.pointerId);
    const start = direction === 'horizontal' ? e.clientX : e.clientY;

    function onPointerMove(e: PointerEvent) {
      const current = direction === 'horizontal' ? e.clientX : e.clientY;
      onresize(current - start);
    }

    function onPointerUp() {
      dragging = false;
      target.removeEventListener('pointermove', onPointerMove);
      target.removeEventListener('pointerup', onPointerUp);
    }

    target.addEventListener('pointermove', onPointerMove);
    target.addEventListener('pointerup', onPointerUp);
  }
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
  class="flex-shrink-0 {direction === 'horizontal' ? 'w-1 cursor-col-resize hover:bg-accent-500/40' : 'h-1 cursor-row-resize hover:bg-accent-500/40'} bg-surface-600 transition-colors {dragging ? 'bg-accent-500/60' : ''}"
  onpointerdown={onPointerDown}
></div>
