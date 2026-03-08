<script lang="ts">
  import { activeCaseId, activeSessionId } from '../../lib/stores/navigation';
  import { getCaseIOCs, getCaseVerdicts } from '../../lib/api/cases';
  import { getSessionContext } from '../../lib/api/sessions';
  import Badge from '../shared/Badge.svelte';
  import { onMount } from 'svelte';
  import type { IOCSet, Finding } from '../../lib/types';

  let iocs = $state<IOCSet>({});
  let verdicts = $state<any>(null);
  let findings = $state<Finding[]>([]);
  let loading = $state(false);

  async function loadContext() {
    loading = true;
    try {
      if ($activeCaseId) {
        const [i, v] = await Promise.all([
          getCaseIOCs($activeCaseId),
          getCaseVerdicts($activeCaseId).catch(() => null),
        ]);
        iocs = i;
        verdicts = v;
      } else if ($activeSessionId) {
        const ctx = await getSessionContext($activeSessionId);
        iocs = ctx.iocs || {};
        findings = ctx.findings || [];
      }
    } catch {}
    loading = false;
  }

  onMount(loadContext);

  // Reload when context changes
  $effect(() => {
    if ($activeCaseId || $activeSessionId) loadContext();
  });

  const iocTypes = $derived(
    Object.entries(iocs).filter(([_, v]) => v && v.length > 0)
  );
</script>

<aside class="h-full bg-surface-800 border-l border-surface-600 overflow-y-auto p-4 space-y-4">
  <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider">Context</h3>

  {#if loading}
    <p class="text-xs text-gray-500">Loading...</p>
  {:else}
    <!-- IOCs -->
    {#if iocTypes.length > 0}
      <div class="space-y-3">
        <h4 class="text-xs font-medium text-gray-300">IOCs</h4>
        {#each iocTypes as [type, items]}
          <div>
            <span class="text-[10px] font-semibold text-gray-500 uppercase">{type}</span>
            <div class="mt-1 space-y-0.5">
              {#each (items || []).slice(0, 10) as ioc}
                <div class="text-xs text-gray-300 font-mono truncate bg-surface-700 px-2 py-1 rounded">{ioc}</div>
              {/each}
              {#if (items || []).length > 10}
                <span class="text-[10px] text-gray-500">+{(items || []).length - 10} more</span>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}

    <!-- Verdicts -->
    {#if verdicts}
      <div class="space-y-2">
        <h4 class="text-xs font-medium text-gray-300">Verdicts</h4>
        {#if verdicts.high?.length}
          <div>
            <Badge type="severity" value="high" />
            {#each verdicts.high.slice(0, 5) as v}
              <p class="text-xs text-gray-300 mt-1 pl-2">{v}</p>
            {/each}
          </div>
        {/if}
        {#if verdicts.medium?.length}
          <div>
            <Badge type="severity" value="medium" />
            {#each verdicts.medium.slice(0, 5) as v}
              <p class="text-xs text-gray-300 mt-1 pl-2">{v}</p>
            {/each}
          </div>
        {/if}
      </div>
    {/if}

    <!-- Findings (session mode) -->
    {#if findings.length > 0}
      <div class="space-y-2">
        <h4 class="text-xs font-medium text-gray-300">Findings</h4>
        {#each findings.slice(0, 8) as f}
          <div class="text-xs bg-surface-700 rounded p-2">
            <span class="text-gray-400">{f.type}:</span>
            <span class="text-gray-200">{f.summary}</span>
          </div>
        {/each}
      </div>
    {/if}

    {#if iocTypes.length === 0 && !verdicts && findings.length === 0}
      <p class="text-xs text-gray-500">No context data yet. Start chatting to build context.</p>
    {/if}
  {/if}
</aside>
