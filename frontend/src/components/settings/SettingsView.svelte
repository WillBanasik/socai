<script lang="ts">
  import { onMount } from 'svelte';
  import { user } from '../../lib/stores/auth';
  import { userPreferences } from '../../lib/stores/preferences';
  import { addToast } from '../../lib/stores/toasts';
  import { getPreferences, updatePreferences } from '../../lib/api/preferences';
  import KeyboardShortcuts from './KeyboardShortcuts.svelte';

  let customInstructions = $state('');
  let defaultModelTier = $state('standard');
  let responseStyle = $state('concise');
  let saving = $state(false);
  let loaded = $state(false);
  let showShortcuts = $state(false);

  onMount(async () => {
    try {
      const prefs = await getPreferences();
      userPreferences.set(prefs);
      customInstructions = prefs.custom_instructions || '';
      defaultModelTier = prefs.default_model_tier || 'standard';
      responseStyle = prefs.response_style || 'concise';
      loaded = true;
    } catch {
      addToast('error', 'Failed to load preferences');
    }
  });

  async function save() {
    saving = true;
    try {
      const prefs = await updatePreferences({
        custom_instructions: customInstructions,
        default_model_tier: defaultModelTier,
        response_style: responseStyle,
      });
      userPreferences.set(prefs);
      addToast('success', 'Preferences saved');
    } catch {
      addToast('error', 'Failed to save preferences');
    }
    saving = false;
  }

  const styleDescriptions: Record<string, string> = {
    concise: 'Short, direct responses. Bullet points and findings first.',
    detailed: 'Thorough analysis with reasoning, evidence, and step-by-step walkthrough.',
    formal: 'Professional, report-style language suitable for client-facing documents.',
  };
</script>

<div class="h-full overflow-y-auto">
  <div class="max-w-2xl mx-auto px-6 py-8">
    <h1 class="text-xl font-bold text-gray-100 mb-6">Settings</h1>

    {#if !loaded}
      <div class="text-gray-400 text-sm">Loading preferences...</div>
    {:else}
      <!-- Profile -->
      <section class="mb-8">
        <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Profile</h2>
        <div class="bg-surface-800 border border-surface-600 rounded-xl p-4">
          <div class="flex items-center gap-3">
            <div class="w-10 h-10 rounded-full bg-accent-500/20 flex items-center justify-center text-accent-400 font-bold text-sm">
              {($user?.email || '?')[0].toUpperCase()}
            </div>
            <div>
              <div class="text-sm text-gray-200">{$user?.email}</div>
              <div class="text-xs text-gray-500">{$user?.role || 'analyst'}</div>
            </div>
          </div>
        </div>
      </section>

      <!-- Response Style -->
      <section class="mb-8">
        <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Response Style</h2>
        <div class="bg-surface-800 border border-surface-600 rounded-xl p-4 space-y-3">
          {#each ['concise', 'detailed', 'formal'] as style}
            <label class="flex items-start gap-3 cursor-pointer group">
              <input
                type="radio"
                name="response_style"
                value={style}
                bind:group={responseStyle}
                class="mt-1 accent-accent-500"
              />
              <div>
                <div class="text-sm text-gray-200 capitalize group-hover:text-accent-400 transition-colors">{style}</div>
                <div class="text-xs text-gray-500">{styleDescriptions[style]}</div>
              </div>
            </label>
          {/each}
        </div>
      </section>

      <!-- Default Model Tier -->
      <section class="mb-8">
        <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Default Model Tier</h2>
        <div class="bg-surface-800 border border-surface-600 rounded-xl p-4">
          <select
            bind:value={defaultModelTier}
            class="w-full bg-surface-700 border border-surface-600 rounded-lg px-3 py-2 text-sm text-gray-200
              focus:outline-none focus:ring-2 focus:ring-accent-500/50"
          >
            <option value="fast">Fast — quick responses, lower cost</option>
            <option value="standard">Standard — balanced quality and speed</option>
            <option value="heavy">Heavy — maximum quality, higher cost</option>
          </select>
          <p class="text-xs text-gray-500 mt-2">Applied to new sessions. Override per-message with the input selector.</p>
        </div>
      </section>

      <!-- Custom Instructions -->
      <section class="mb-8">
        <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Custom Instructions</h2>
        <div class="bg-surface-800 border border-surface-600 rounded-xl p-4">
          <textarea
            bind:value={customInstructions}
            placeholder="E.g., 'I investigate financial services clients. Always check for lateral movement after credential phishing. Prefer tables over prose.'"
            rows="5"
            maxlength="2000"
            class="w-full bg-surface-700 border border-surface-600 rounded-lg px-3 py-2 text-sm text-gray-200
              placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-accent-500/50 resize-y"
          ></textarea>
          <div class="flex justify-between mt-2">
            <p class="text-xs text-gray-500">Injected into every system prompt. Personalises Chief's responses.</p>
            <span class="text-xs text-gray-500">{customInstructions.length}/2000</span>
          </div>
        </div>
      </section>

      <!-- Save -->
      <div class="flex items-center gap-3">
        <button
          onclick={save}
          disabled={saving}
          class="px-4 py-2 bg-accent-500 hover:bg-accent-600 disabled:opacity-50 text-white text-sm rounded-lg transition-colors"
        >
          {saving ? 'Saving...' : 'Save preferences'}
        </button>
      </div>

      <!-- Keyboard Shortcuts -->
      <section class="mt-10 mb-8">
        <button
          onclick={() => showShortcuts = !showShortcuts}
          class="text-sm font-semibold text-gray-400 uppercase tracking-wider hover:text-gray-300 transition-colors flex items-center gap-2"
        >
          Keyboard Shortcuts
          <span class="text-xs">{showShortcuts ? '▾' : '▸'}</span>
        </button>
        {#if showShortcuts}
          <div class="mt-3">
            <KeyboardShortcuts />
          </div>
        {/if}
      </section>

      <!-- API Integrations status -->
      <section class="mb-8">
        <h2 class="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Integration Status</h2>
        <div class="bg-surface-800 border border-surface-600 rounded-xl p-4">
          <p class="text-xs text-gray-500">
            API key status and integration configuration are managed server-side.
            Contact your admin to enable or update integrations.
          </p>
        </div>
      </section>
    {/if}
  </div>
</div>
