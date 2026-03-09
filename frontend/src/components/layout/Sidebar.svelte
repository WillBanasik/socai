<script lang="ts">
  import { route, navigate } from '../../lib/router';
  import { sessionList } from '../../lib/stores/sessions';
  import { activeSessionId, activeCaseId } from '../../lib/stores/navigation';
  import { allCases } from '../../lib/stores/cases';
  import { userPreferences } from '../../lib/stores/preferences';
  import { listSessions, deleteSession, deleteAllSessions } from '../../lib/api/sessions';
  import { browseCases } from '../../lib/api/cases';
  import { getPreferences, pinSession, unpinSession, searchSessions as apiSearch } from '../../lib/api/preferences';
  import { addToast } from '../../lib/stores/toasts';
  import { resetChat } from '../../lib/stores/chat';
  import SidebarItem from './SidebarItem.svelte';
  import { relativeTime } from '../../lib/utils/time';
  import { onMount } from 'svelte';

  const navItems = [
    { label: 'Dashboard', hash: '#/dashboard', icon: 'D' },
    { label: 'Cases', hash: '#/cases', icon: 'C' },
    { label: 'Investigate', hash: '#/investigate', icon: 'I' },
    { label: 'Settings', hash: '#/settings', icon: 'S' },
  ];

  let searchQuery = $state('');
  let searchResults = $state<any[]>([]);
  let searching = $state(false);
  let searchTimeout: ReturnType<typeof setTimeout>;

  function newInvestigation() {
    resetChat();
    activeSessionId.set(null);
    activeCaseId.set(null);
    navigate('/');
  }

  async function killSession(e: MouseEvent, sessionId: string) {
    e.preventDefault();
    e.stopPropagation();
    try {
      await deleteSession(sessionId);
      sessionList.update((s) => s.filter((x) => x.session_id !== sessionId));
      if ($activeSessionId === sessionId) {
        activeSessionId.set(null);
        resetChat();
        navigate('/');
      }
      addToast('info', 'Session deleted');
    } catch (err: any) {
      addToast('error', `Failed to delete session: ${err.message}`);
    }
  }

  async function killAllSessions() {
    try {
      await deleteAllSessions();
      sessionList.set([]);
      if ($activeSessionId) {
        activeSessionId.set(null);
        resetChat();
        navigate('/');
      }
      addToast('info', 'All sessions deleted');
    } catch (err: any) {
      addToast('error', `Failed: ${err.message}`);
    }
  }

  async function togglePin(e: MouseEvent, sessionId: string) {
    e.preventDefault();
    e.stopPropagation();
    const pinned = $userPreferences.pinned_sessions || [];
    try {
      if (pinned.includes(sessionId)) {
        const result = await unpinSession(sessionId);
        userPreferences.update((p) => ({ ...p, pinned_sessions: result.pinned_sessions }));
      } else {
        const result = await pinSession(sessionId);
        userPreferences.update((p) => ({ ...p, pinned_sessions: result.pinned_sessions }));
      }
    } catch {
      addToast('error', 'Failed to update pin');
    }
  }

  function handleSearchInput() {
    clearTimeout(searchTimeout);
    if (!searchQuery.trim()) {
      searchResults = [];
      return;
    }
    searching = true;
    searchTimeout = setTimeout(async () => {
      try {
        searchResults = await apiSearch(searchQuery.trim());
      } catch {
        searchResults = [];
      }
      searching = false;
    }, 300);
  }

  async function loadSidebar() {
    try {
      const [sessions, cases, prefs] = await Promise.all([
        listSessions(),
        browseCases(),
        getPreferences(),
      ]);
      sessionList.set(sessions);
      allCases.set(cases);
      userPreferences.set(prefs);
    } catch {}
  }

  onMount(loadSidebar);

  const pinnedIds = $derived(new Set($userPreferences.pinned_sessions || []));

  const pinnedSessions = $derived(
    $sessionList.filter((s) => pinnedIds.has(s.session_id))
  );

  const unpinnedSessions = $derived(
    $sessionList.filter((s) => !pinnedIds.has(s.session_id))
  );

  const recentCases = $derived(
    [...$allCases].sort((a, b) => (b.created || '').localeCompare(a.created || '')).slice(0, 8)
  );
</script>

<nav class="h-full flex flex-col bg-surface-900 overflow-hidden">
  <!-- Brand -->
  <div class="px-4 py-3 border-b border-surface-700 text-center">
    <a href="#/" class="text-lg font-bold tracking-tight"><span class="text-accent-400">soc</span><span class="text-white italic">ai</span></a>
  </div>

  <!-- Search -->
  <div class="px-3 pt-3 pb-1">
    <div class="relative">
      <input
        type="text"
        placeholder="Search sessions..."
        bind:value={searchQuery}
        oninput={handleSearchInput}
        class="w-full bg-surface-800 border border-surface-600 rounded-lg px-3 py-1.5 text-xs text-gray-300
          placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-accent-500/50 focus:border-accent-500/50"
      />
      {#if searching}
        <span class="absolute right-2 top-1.5 text-[10px] text-gray-500">...</span>
      {/if}
    </div>
    {#if searchResults.length > 0}
      <div class="mt-1 bg-surface-800 border border-surface-600 rounded-lg overflow-hidden max-h-40 overflow-y-auto">
        {#each searchResults as r}
          <a
            href="#/session/{r.session_id}"
            class="block px-3 py-2 text-xs hover:bg-surface-700 border-b border-surface-700 last:border-0"
            onclick={() => { searchQuery = ''; searchResults = []; }}
          >
            <div class="text-gray-300 truncate">{r.title || 'untitled'}</div>
            <div class="text-[10px] text-gray-500">
              {r.match_fields?.join(', ')} — {relativeTime(r.created)}
            </div>
          </a>
        {/each}
      </div>
    {/if}
  </div>

  <!-- Navigation -->
  <div class="px-2 py-2 space-y-0.5">
    {#each navItems as item}
      <SidebarItem
        label={item.label}
        href={item.hash}
        active={$route.hash === item.hash.slice(1)}
      />
    {/each}
  </div>

  <!-- Pinned Sessions -->
  {#if pinnedSessions.length > 0}
    <div class="px-3 pt-3 pb-1">
      <span class="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Pinned</span>
    </div>
    <div class="px-2 space-y-0.5">
      {#each pinnedSessions as session (session.session_id)}
        <div class="group flex items-center">
          <div class="flex-1 min-w-0">
            <SidebarItem
              label={session.title || 'new investigation'}
              italic={!session.title}
              sublabel={relativeTime(session.created)}
              href="#/session/{session.session_id}"
              active={$activeSessionId === session.session_id}
            />
          </div>
          <button
            class="flex-shrink-0 text-accent-400 hover:text-accent-300 px-1.5 py-1 text-[10px] transition-colors"
            onclick={(e) => togglePin(e, session.session_id)}
            title="Unpin"
          >★</button>
        </div>
      {/each}
    </div>
  {/if}

  <!-- Sessions -->
  <div class="px-3 pt-3 pb-1 flex items-center justify-between">
    <span class="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Sessions</span>
    <div class="flex items-center gap-1">
      {#if $sessionList.length > 1}
        <button
          class="text-[10px] text-red-400/60 hover:text-red-400 px-1 py-0.5 rounded hover:bg-surface-700"
          onclick={killAllSessions}
          title="Delete all sessions"
        >Clear all</button>
      {/if}
    </div>
  </div>
  <div class="px-2 space-y-0.5 overflow-y-auto flex-shrink min-h-0 max-h-48">
    {#each unpinnedSessions as session (session.session_id)}
      <div class="group flex items-center">
        <div class="flex-1 min-w-0">
          <SidebarItem
            label={session.title || 'new investigation'}
            italic={!session.title}
            sublabel={relativeTime(session.created)}
            href="#/session/{session.session_id}"
            active={$activeSessionId === session.session_id}
          />
        </div>
        <button
          class="flex-shrink-0 text-gray-600 hover:text-accent-400
            px-1.5 py-1 text-[10px] opacity-0 group-hover:opacity-100 transition-all"
          onclick={(e) => togglePin(e, session.session_id)}
          title="Pin session"
        >☆</button>
        <button
          class="flex-shrink-0 text-gray-600 hover:text-red-400
            px-1.5 py-1 text-xs transition-colors"
          onclick={(e) => killSession(e, session.session_id)}
          title="Delete session"
        >&times;</button>
      </div>
    {/each}
    {#if $sessionList.length === 0}
      <p class="text-xs text-gray-600 px-3 py-2">No active sessions</p>
    {/if}
  </div>

  <!-- Recent Cases -->
  <div class="px-3 pt-3 pb-1">
    <span class="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Recent Cases</span>
  </div>
  <div class="px-2 space-y-0.5 overflow-y-auto flex-1 min-h-0">
    {#each recentCases as c (c.case_id)}
      <SidebarItem
        label="{c.case_id} {c.title}"
        sublabel={c.severity}
        href="#/chat/{c.case_id}"
        active={$activeCaseId === c.case_id}
      />
    {/each}
  </div>

  <!-- Bottom padding -->
  <div class="flex-shrink-0 h-2"></div>
</nav>
