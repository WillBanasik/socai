<script lang="ts">
  import { route, navigate } from '../../lib/router';
  import { activeCaseId } from '../../lib/stores/navigation';
  import { contextPanelOpen } from '../../lib/stores/layout';
  import { getCaseDetail, getCaseReport, getCaseIOCs, getCaseVerdicts, getCaseTimeline } from '../../lib/api/cases';
  import Badge from '../shared/Badge.svelte';
  import Spinner from '../shared/Spinner.svelte';
  import IOCPanel from './IOCPanel.svelte';
  import VerdictPanel from './VerdictPanel.svelte';
  import FindingsPanel from './FindingsPanel.svelte';
  import KQLPanel from './KQLPanel.svelte';
  import InvestigationLog from './InvestigationLog.svelte';
  import ReportPanel from './ReportPanel.svelte';
  import { formatDateTime } from '../../lib/utils/time';
  import { onMount } from 'svelte';
  import type { CaseDetail as CaseDetailType, IOCSet, LogEntry, KQLQuery, Finding } from '../../lib/types';

  let loading = $state(true);
  let detail = $state<CaseDetailType | null>(null);
  let report = $state('');
  let iocs = $state<IOCSet>({});
  let verdicts = $state<any>(null);
  let timeline = $state<LogEntry[]>([]);

  const caseId = $derived($route.params.caseId);

  $effect(() => {
    if (caseId) {
      activeCaseId.set(caseId);
      contextPanelOpen.set(true);
      load(caseId);
    }
  });

  async function load(id: string) {
    loading = true;
    try {
      const [d, r, i, v, t] = await Promise.all([
        getCaseDetail(id),
        getCaseReport(id).catch(() => ''),
        getCaseIOCs(id).catch(() => ({})),
        getCaseVerdicts(id).catch(() => null),
        getCaseTimeline(id).catch(() => []),
      ]);
      detail = d;
      report = r;
      iocs = i;
      verdicts = v;
      timeline = t;
    } catch {}
    loading = false;
  }
</script>

<div class="h-full overflow-y-auto p-4">
  {#if loading}
    <div class="flex items-center justify-center h-64">
      <Spinner size="lg" />
    </div>
  {:else if detail}
    <!-- Header -->
    <div class="mb-6">
      <div class="flex items-center gap-3 mb-2">
        <span class="text-lg font-mono text-accent-400 font-bold">{detail.case_id}</span>
        <Badge type="severity" value={detail.severity} />
        {#if detail.status}
          <Badge type="status" value={detail.status} />
        {/if}
        {#if detail.disposition}
          <Badge type="disposition" value={detail.disposition} />
        {/if}
      </div>
      <h1 class="text-xl font-semibold text-gray-100 mb-2">{detail.title}</h1>
      <div class="flex items-center gap-4 text-xs text-gray-500">
        {#if detail.analyst}
          <span>Analyst: {detail.analyst}</span>
        {/if}
        {#if detail.created}
          <span>Created: {formatDateTime(detail.created)}</span>
        {/if}
      </div>
      <button
        class="mt-3 text-xs px-3 py-1.5 bg-accent-500/20 hover:bg-accent-500/30 border border-accent-500/40
          rounded-lg text-accent-300 transition-colors"
        onclick={() => navigate(`/chat/${detail?.case_id}`)}
      >
        Open in Chat
      </button>
    </div>

    <!-- Two-column detail grid -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="space-y-6">
        <IOCPanel {iocs} />
        <VerdictPanel {verdicts} />
        <FindingsPanel findings={detail.findings || []} />
      </div>
      <div class="space-y-6">
        <ReportPanel content={report} />
        <KQLPanel queries={detail.kql_queries || []} />
        <InvestigationLog entries={timeline} />
      </div>
    </div>
  {:else}
    <p class="text-gray-500">Case not found</p>
  {/if}
</div>
