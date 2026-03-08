<script lang="ts">
  import { route, navigate } from '../../lib/router';
  import { sessionList } from '../../lib/stores/sessions';
  import { activeSessionId, activeCaseId } from '../../lib/stores/navigation';
  import { allCases } from '../../lib/stores/cases';
  import { listSessions, deleteSession, deleteAllSessions } from '../../lib/api/sessions';
  import { browseCases } from '../../lib/api/cases';
  import { addToast } from '../../lib/stores/toasts';
  import { resetChat } from '../../lib/stores/chat';
  import SidebarItem from './SidebarItem.svelte';
  import { relativeTime } from '../../lib/utils/time';
  import { onMount } from 'svelte';

  const navItems = [
    { label: 'Dashboard', hash: '#/dashboard', icon: 'D' },
    { label: 'Cases', hash: '#/cases', icon: 'C' },
    { label: 'Investigate', hash: '#/investigate', icon: 'I' },
  ];

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

  async function loadSidebar() {
    try {
      const [sessions, cases] = await Promise.all([listSessions(), browseCases()]);
      sessionList.set(sessions);
      allCases.set(cases);
    } catch {}
  }

  onMount(loadSidebar);

  const recentCases = $derived(
    [...$allCases].sort((a, b) => (b.created || '').localeCompare(a.created || '')).slice(0, 8)
  );
</script>

<nav class="h-full flex flex-col bg-surface-900 overflow-hidden">
  <!-- Brand -->
  <div class="px-4 py-3 border-b border-surface-700 text-center">
    <a href="#/" class="text-lg font-bold tracking-tight"><span class="text-accent-400">soc</span><span class="text-white italic">ai</span></a>
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
    {#each $sessionList as session (session.session_id)}
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
