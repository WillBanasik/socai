<script lang="ts">
  import { toasts } from '../../lib/stores/toasts';
  import Toast from './Toast.svelte';
</script>

<div class="fixed bottom-16 right-8 z-[100] flex flex-col gap-2">
  {#each $toasts as toast (toast.id)}
    <Toast {toast} />
  {/each}
</div>
