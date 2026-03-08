<script lang="ts">
  import type { Toast } from '../../lib/types';
  import { removeToast } from '../../lib/stores/toasts';

  let { toast }: { toast: Toast } = $props();

  const colours: Record<string, string> = {
    success: 'border-green-500 bg-green-500/10 text-green-300',
    error: 'border-red-500 bg-red-500/10 text-red-300',
    warning: 'border-yellow-500 bg-yellow-500/10 text-yellow-300',
    info: 'border-blue-500 bg-blue-500/10 text-blue-300',
  };

  const icons: Record<string, string> = {
    success: '\u2713',
    error: '\u2717',
    warning: '\u26A0',
    info: '\u2139',
  };
</script>

<div class="fly-in-bottom flex items-center gap-3 px-4 py-3 rounded-lg border {colours[toast.type]} shadow-lg max-w-md">
  <span class="text-lg">{icons[toast.type]}</span>
  <span class="text-sm flex-1">{toast.message}</span>
  <button class="text-gray-400 hover:text-gray-200 text-sm" onclick={() => removeToast(toast.id)}>
    &times;
  </button>
</div>
