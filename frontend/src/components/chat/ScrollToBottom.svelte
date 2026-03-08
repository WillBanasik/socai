<script lang="ts">
  let { onclick }: { onclick: () => void } = $props();
</script>

<button
  {onclick}
  class="absolute bottom-20 right-6 w-8 h-8 rounded-full bg-surface-600 border border-surface-500
    flex items-center justify-center text-gray-300 hover:bg-surface-500 transition-colors shadow-lg z-10"
  title="Scroll to bottom"
>
  <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 14l-7 7m0 0l-7-7m7 7V3" />
  </svg>
</button>
