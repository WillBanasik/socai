<script lang="ts">
  import { getCTIFeed, getTrending, getAttackHeatmap, getWatchlist, getIOCDecay, getIOCXRef } from '../../lib/api/cti';
  import CTIFeed from './CTIFeed.svelte';
  import TrendingIndicators from './TrendingIndicators.svelte';
  import AttackHeatmap from './AttackHeatmap.svelte';
  import Watchlist from './Watchlist.svelte';
  import IOCDecay from './IOCDecay.svelte';
  import IOCXRef from './IOCXRef.svelte';
  import InternalIntel from './InternalIntel.svelte';
  import Spinner from '../shared/Spinner.svelte';
  import { onMount } from 'svelte';

  let loading = $state(true);
  let feed = $state<any[]>([]);
  let trending = $state<any[]>([]);
  let heatmap = $state<any>(null);
  let watchlist = $state<any[]>([]);
  let decay = $state<any>(null);
  let xref = $state<any[]>([]);
  let xrefLoading = $state(true);

  async function loadFast() {
    // Load the fast endpoints first — render immediately when done
    loading = true;
    const results = await Promise.allSettled([
      getCTIFeed(),
      getTrending(),
      getAttackHeatmap(),
      getWatchlist(),
      getIOCDecay(),
    ]);

    if (results[0].status === 'fulfilled') {
      const v = results[0].value as any;
      feed = Array.isArray(v) ? v : (v.feed || []);
    }
    if (results[1].status === 'fulfilled') trending = results[1].value as any;
    if (results[2].status === 'fulfilled') heatmap = results[2].value;
    if (results[3].status === 'fulfilled') watchlist = (results[3].value as any).watchlist || [];
    if (results[4].status === 'fulfilled') decay = results[4].value;

    loading = false;
  }

  async function loadSlow() {
    // xref is slow (~8s) — load in background, don't block the page
    xrefLoading = true;
    try {
      const data = await getIOCXRef();
      xref = Array.isArray(data) ? data : [];
    } catch {}
    xrefLoading = false;
  }

  async function refreshWatchlist() {
    try {
      const data = await getWatchlist();
      watchlist = data.watchlist || [];
    } catch {}
  }

  onMount(() => {
    loadFast();
    loadSlow();
  });
</script>

<div class="h-full overflow-y-auto p-4 space-y-4">
  <h2 class="text-sm font-semibold text-gray-300">Threat Intelligence</h2>

  {#if loading}
    <div class="flex items-center justify-center h-64">
      <Spinner size="lg" />
    </div>
  {:else}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <!-- Left column -->
      <div class="space-y-4">
        <InternalIntel />
        <CTIFeed items={feed} />
        <TrendingIndicators items={trending} />
      </div>
      <!-- Right column -->
      <div class="space-y-4">
        {#if xrefLoading}
          <div class="bg-surface-700 border border-surface-600 rounded-xl p-4">
            <h3 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">IOC Cross-Reference</h3>
            <div class="flex items-center gap-2 py-4 justify-center">
              <Spinner size="sm" />
              <span class="text-xs text-gray-500">Querying OpenCTI...</span>
            </div>
          </div>
        {:else}
          <IOCXRef data={xref} />
        {/if}
        <Watchlist items={watchlist} onrefresh={refreshWatchlist} />
        <AttackHeatmap data={heatmap} />
        <IOCDecay data={decay} />
      </div>
    </div>
  {/if}
</div>
