<script lang="ts">
  import { activeSessionId } from '../../lib/stores/navigation';
  import { getSessionContext } from '../../lib/api/sessions';
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';

  let { onsend }: { onsend: (text: string) => void } = $props();
  let suggestions = $state<{ label: string; prompt: string }[]>([]);

  onMount(async () => {
    const sid = get(activeSessionId);
    if (!sid) {
      // No session yet — show starter suggestions
      suggestions = [
        { label: 'Investigate phishing email', prompt: 'I have a suspicious email to investigate. Let me paste the alert details.' },
        { label: 'Enrich IOCs', prompt: 'Enrich these IOCs and tell me which are malicious:' },
        { label: 'Hunt for IOCs in Sentinel', prompt: 'Hunt for these indicators across our Sentinel workspace:' },
        { label: 'Analyse uploaded file', prompt: 'Analyse the uploaded telemetry file and extract key findings.' },
      ];
      return;
    }

    try {
      const ctx = await getSessionContext(sid);
      const iocs = ctx.iocs || {};
      const iocCount = Object.values(iocs).reduce((n: number, arr: any) => n + (arr || []).length, 0);
      const findings = ctx.findings || [];
      const telemetry = ctx.telemetry_summaries || [];

      const s: { label: string; prompt: string }[] = [];

      // Context-aware suggestions
      if (iocCount === 0 && telemetry.length === 0) {
        s.push(
          { label: 'Upload telemetry', prompt: 'I have telemetry to upload for analysis.' },
          { label: 'Paste alert JSON', prompt: 'Here is the alert JSON for investigation:' },
          { label: 'Search prior cases', prompt: 'Search prior cases for any related intelligence.' },
        );
      }
      if (iocCount > 0 && findings.length === 0) {
        s.push({ label: 'Enrich IOCs', prompt: 'Enrich the collected IOCs against threat intelligence.' });
        s.push({ label: 'Hunt in Sentinel', prompt: 'Hunt for these IOCs across our Sentinel workspace.' });
      }
      if (findings.length > 0 && !ctx.disposition) {
        s.push({ label: 'Generate FP comment', prompt: 'Based on the investigation, generate a false positive closure comment.' });
        s.push({ label: 'Generate MDR report', prompt: 'Generate an MDR incident report from the investigation findings.' });
      }
      if (telemetry.length > 0 && iocCount === 0) {
        s.push({ label: 'Extract IOCs', prompt: 'Extract all IOCs from the analysed telemetry.' });
      }
      if (s.length < 3) {
        s.push({ label: 'Summarise investigation', prompt: 'Summarise the current investigation status and key findings.' });
      }

      suggestions = s.slice(0, 4);
    } catch {
      suggestions = [
        { label: 'Start investigating', prompt: 'Paste IOCs, alerts, or upload a file to begin.' },
      ];
    }
  });
</script>

{#if suggestions.length > 0}
  <div class="flex flex-wrap gap-2 justify-center mt-4">
    {#each suggestions as s}
      <button
        onclick={() => onsend(s.prompt)}
        class="px-3 py-1.5 text-xs text-gray-300 bg-surface-700 border border-surface-600
          rounded-full hover:bg-surface-600 hover:text-accent-400 hover:border-accent-500/30
          transition-colors"
      >
        {s.label}
      </button>
    {/each}
  </div>
{/if}
