<script lang="ts">
  import type { Toast } from '../../lib/types';
  import { removeToast } from '../../lib/stores/toasts';

  let { toast }: { toast: Toast } = $props();

  const colours: Record<string, string> = {
    success: 'border-green-500/40 bg-green-950/80 text-green-200',
    error: 'border-red-500/40 bg-red-950/80 text-red-200',
    warning: 'border-yellow-500/40 bg-yellow-950/80 text-yellow-200',
    info: 'border-gray-500/30 bg-surface-800/90 text-gray-300',
  };

  const icons: Record<string, string> = {
    success: '\u2713',
    error: '\u2717',
    warning: '\u26A0',
    info: '\u2139',
  };
</script>

<div class="fly-in-bottom flex items-center gap-3 px-4 py-3 rounded-lg border backdrop-blur-sm {colours[toast.type]} shadow-lg max-w-sm">
  <span class="text-lg">{icons[toast.type]}</span>
  <span class="text-sm flex-1">{toast.message}</span>
  <button class="text-gray-400 hover:text-gray-200 text-sm" onclick={() => removeToast(toast.id)}>
    &times;
  </button>
</div>
