<script lang="ts">
  import type { LogEntry } from '../../lib/types';
  import { relativeTime, formatDateTime } from '../../lib/utils/time';

  let { entries }: { entries: LogEntry[] } = $props();
  let expandedGroups: Record<number, boolean> = $state({});
</script>

<div class="space-y-2">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Investigation Log</h3>
  {#if entries.length === 0}
    <p class="text-xs text-gray-500">No log entries</p>
  {:else}
    {#each entries as entry, i}
      <div class="border-l-2 border-surface-600 pl-3">
        {#if entry.entries && entry.entries.length > 0}
          <button
            class="flex items-center gap-2 text-xs text-gray-300 hover:text-gray-100 w-full text-left"
            onclick={() => expandedGroups[i] = !expandedGroups[i]}
          >
            <svg class="w-3 h-3 transition-transform {expandedGroups[i] ? 'rotate-90' : ''}" fill="currentColor" viewBox="0 0 20 20">
              <path d="M6 6l8 4-8 4V6z" />
            </svg>
            <span class="font-medium">{entry.action}</span>
            <span class="text-gray-500">({entry.entries.length})</span>
            {#if entry.ts}
              <span class="text-gray-500 ml-auto">{relativeTime(entry.ts)}</span>
            {/if}
          </button>
          {#if expandedGroups[i]}
            <div class="mt-1 ml-5 space-y-1">
              {#each entry.entries as sub}
                <div class="text-xs text-gray-400">
                  <span class="text-gray-500">{sub.ts ? formatDateTime(sub.ts) : ''}</span>
                  {sub.action}
                  {#if sub.detail}
                    <span class="text-gray-500">- {sub.detail}</span>
                  {/if}
                </div>
              {/each}
            </div>
          {/if}
        {:else}
          <div class="flex items-center gap-2 text-xs">
            <span class="w-1.5 h-1.5 rounded-full bg-surface-500 flex-shrink-0"></span>
            <span class="text-gray-300">{entry.action}</span>
            {#if entry.detail}
              <span class="text-gray-500">- {entry.detail}</span>
            {/if}
            {#if entry.ts}
              <span class="text-gray-500 ml-auto">{relativeTime(entry.ts)}</span>
            {/if}
          </div>
        {/if}
      </div>
    {/each}
  {/if}
</div>
