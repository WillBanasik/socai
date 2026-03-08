<script lang="ts">
  import { apiPost, apiFetch } from '../../lib/api/client';
  import { addToast } from '../../lib/stores/toasts';
  import { navigate } from '../../lib/router';
  import IOCPreview from './IOCPreview.svelte';
  import FileDropZone from './FileDropZone.svelte';
  import Spinner from '../shared/Spinner.svelte';
  import type { ParsedInput } from '../../lib/types';

  let text = $state('');
  let severity = $state('medium');
  let zipPass = $state('');
  let files = $state<File[]>([]);
  let parsed = $state<ParsedInput | null>(null);
  let submitting = $state(false);
  let parseTimer: ReturnType<typeof setTimeout>;

  function handleInput() {
    clearTimeout(parseTimer);
    if (!text.trim()) {
      parsed = null;
      return;
    }
    parseTimer = setTimeout(async () => {
      try {
        const fd = new FormData();
        fd.append('text', text);
        const resp = await apiFetch('/api/parse', { method: 'POST', body: fd });
        parsed = await resp.json();
      } catch {}
    }, 400);
  }

  async function submit() {
    if (!text.trim()) return;
    submitting = true;
    try {
      const fd = new FormData();
      fd.append('text', text);
      fd.append('severity', severity);
      if (zipPass) fd.append('zip_pass', zipPass);
      for (const f of files) {
        if (f.name.endsWith('.zip')) {
          fd.append('zip_file', f);
        } else if (f.name.endsWith('.eml')) {
          fd.append('eml_files', f);
        } else {
          fd.append('zip_file', f);
        }
      }

      const resp = await apiFetch('/api/cases', { method: 'POST', body: fd });
      const data = await resp.json();
      addToast('success', `Case ${data.case_id} created`);
      navigate(`/chat/${data.case_id}`);
    } catch (e: any) {
      addToast('error', `Failed: ${e.message}`);
    }
    submitting = false;
  }
</script>

<div class="h-full overflow-y-auto p-4">
  <div class="grid grid-cols-1 lg:grid-cols-5 gap-6 max-w-6xl mx-auto">
    <!-- Left: Form -->
    <div class="lg:col-span-3 space-y-4">
      <h2 class="text-sm font-semibold text-gray-300">New Investigation</h2>

      <div>
        <label for="text" class="block text-xs text-gray-400 mb-1">Evidence / Observables</label>
        <textarea
          id="text"
          bind:value={text}
          oninput={handleInput}
          rows="8"
          placeholder="Paste URLs, IPs, hashes, email headers, alert JSON, or describe the incident..."
          class="w-full px-4 py-3 bg-surface-700 border border-surface-600 rounded-xl text-sm text-gray-200
            placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-accent-500/50 resize-y"
        ></textarea>
      </div>

      <FileDropZone {files} onfileschange={(f) => files = f} />

      <div class="grid grid-cols-2 gap-4">
        <div>
          <label for="severity" class="block text-xs text-gray-400 mb-1">Severity</label>
          <select
            id="severity"
            bind:value={severity}
            class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-sm text-gray-300
              focus:outline-none focus:ring-2 focus:ring-accent-500/50"
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div>
          <label for="zippass" class="block text-xs text-gray-400 mb-1">ZIP Password (if applicable)</label>
          <input
            id="zippass"
            type="text"
            bind:value={zipPass}
            placeholder="e.g. infected"
            class="w-full px-3 py-2 bg-surface-700 border border-surface-600 rounded-lg text-sm text-gray-200
              placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-accent-500/50"
          />
        </div>
      </div>

      <button
        onclick={submit}
        disabled={!text.trim() || submitting}
        class="w-full py-3 bg-accent-500 hover:bg-accent-600 disabled:opacity-40 disabled:cursor-not-allowed
          text-white rounded-xl text-sm font-medium transition-colors flex items-center justify-center gap-2"
      >
        {#if submitting}
          <Spinner size="sm" />
        {/if}
        Create Case
      </button>
    </div>

    <!-- Right: Preview -->
    <div class="lg:col-span-2">
      <IOCPreview {parsed} />
    </div>
  </div>
</div>
