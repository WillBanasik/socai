<script lang="ts">
  let { filename, onremove }: { filename: string; onremove: () => void } = $props();
</script>

<span class="inline-flex items-center gap-1 px-2 py-1 rounded-full bg-surface-600 text-xs text-gray-300 border border-surface-500">
  <svg class="w-3 h-3 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
  </svg>
  <span class="truncate max-w-[120px]">{filename}</span>
  <button class="text-gray-400 hover:text-gray-200" onclick={onremove}>&times;</button>
</span>
