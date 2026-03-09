<script lang="ts">
  const shortcuts = [
    { keys: 'Ctrl + K', action: 'Open command palette' },
    { keys: 'Ctrl + B', action: 'Toggle sidebar' },
    { keys: 'Ctrl + \\', action: 'Toggle context panel' },
    { keys: 'Ctrl + N', action: 'New session' },
    { keys: 'Ctrl + Shift + E', action: 'Export current session' },
    { keys: 'Ctrl + ,', action: 'Open settings' },
    { keys: 'Ctrl + /', action: 'Show keyboard shortcuts' },
    { keys: 'Enter', action: 'Send message' },
    { keys: 'Shift + Enter', action: 'New line in message' },
    { keys: '/', action: 'Slash command (in empty input)' },
  ];
</script>

<div class="bg-surface-800 border border-surface-600 rounded-xl p-4">
  <div class="grid grid-cols-2 gap-2">
    {#each shortcuts as s}
      <div class="flex items-center justify-between py-1.5 border-b border-surface-700 last:border-0">
        <span class="text-xs text-gray-400">{s.action}</span>
        <kbd class="text-[10px] bg-surface-700 text-gray-300 px-2 py-0.5 rounded border border-surface-600 font-mono">
          {s.keys}
        </kbd>
      </div>
    {/each}
  </div>
</div>
