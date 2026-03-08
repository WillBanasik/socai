<script lang="ts">
  import type { ParsedInput } from '../../lib/types';
  import Badge from '../shared/Badge.svelte';

  let { parsed }: { parsed: ParsedInput | null } = $props();

  const sections = $derived(
    parsed
      ? [
          { label: 'URLs', items: parsed.urls || [] },
          { label: 'IPs', items: parsed.ips || [] },
          { label: 'Hashes', items: parsed.hashes || [] },
          { label: 'Emails', items: parsed.emails || [] },
          { label: 'CVEs', items: parsed.cves || [] },
        ].filter((s) => s.items.length > 0)
      : []
  );
</script>

<div class="bg-surface-700 border border-surface-600 rounded-xl p-4 space-y-3 sticky top-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">IOC Preview</h3>

  {#if parsed?.severity}
    <div class="flex items-center gap-2">
      <span class="text-xs text-gray-400">Severity:</span>
      <Badge type="severity" value={parsed.severity} />
    </div>
  {/if}

  {#if parsed?.title}
    <div>
      <span class="text-xs text-gray-400">Title:</span>
      <p class="text-sm text-gray-200">{parsed.title}</p>
    </div>
  {/if}

  {#each sections as section}
    <div>
      <span class="text-[10px] font-semibold text-gray-500 uppercase">{section.label} ({section.items.length})</span>
      <div class="mt-1 space-y-0.5">
        {#each section.items.slice(0, 10) as item}
          <div class="text-xs font-mono text-gray-300 bg-surface-800 px-2 py-1 rounded truncate">{item}</div>
        {/each}
        {#if section.items.length > 10}
          <span class="text-[10px] text-gray-500">+{section.items.length - 10} more</span>
        {/if}
      </div>
    </div>
  {/each}

  {#if sections.length === 0 && !parsed?.severity}
    <p class="text-xs text-gray-500">Start typing to see parsed IOCs</p>
  {/if}
</div>
