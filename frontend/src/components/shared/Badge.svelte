<script lang="ts">
  import { getBadgeClass } from '../../lib/utils/badges';

  let { type, value }: { type: 'severity' | 'status' | 'disposition'; value: string } = $props();
</script>

<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border {getBadgeClass(type, value)}">
  {value?.replace(/_/g, ' ')}
</span>
