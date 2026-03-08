<script lang="ts">
  import { route } from '../../lib/router';
  import { activeCaseId, activeSessionId } from '../../lib/stores/navigation';
  import { user, token } from '../../lib/stores/auth';
  import { sidebarCollapsed } from '../../lib/stores/layout';
  import { navigate } from '../../lib/router';
  import { cleanupSessions } from '../../lib/api/sessions';
  import { sessionList } from '../../lib/stores/sessions';
  import { resetChat } from '../../lib/stores/chat';

  const contextLabel = $derived.by(() => {
    if ($activeCaseId) return $activeCaseId;
    if ($activeSessionId) return '';
    const names: Record<string, string> = {
      cases: 'Cases',
      dashboard: 'Threat Intelligence',
      investigate: 'New Investigation',
    };
    return names[$route.name] || '';
  });

  const isCase = $derived(!!$activeCaseId);

  async function logout() {
    // Clean up all non-materialised sessions before logging out
    try {
      await cleanupSessions();
    } catch {}
    sessionList.set([]);
    activeSessionId.set(null);
    activeCaseId.set(null);
    resetChat();
    token.set(null);
    user.set(null);
    navigate('/login');
  }
</script>

<header class="h-12 bg-surface-800 border-b border-surface-600 flex items-center px-4 gap-3 flex-shrink-0">
  <button
    class="text-gray-400 hover:text-gray-200 p-1"
    onclick={() => sidebarCollapsed.update((v) => !v)}
    title="Toggle sidebar (Ctrl+B)"
  >
    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
    </svg>
  </button>

  {#if contextLabel}
    <span class="text-sm font-medium truncate {isCase ? 'text-accent-400' : 'text-gray-400'}">{contextLabel}</span>
  {/if}

  <div class="flex-1"></div>

  {#if $user}
    <span class="text-xs text-gray-400">{$user.email}</span>
    <button
      class="text-xs text-gray-400 hover:text-gray-200 px-2 py-1 rounded hover:bg-surface-600"
      onclick={logout}
    >
      Logout
    </button>
  {/if}
</header>
