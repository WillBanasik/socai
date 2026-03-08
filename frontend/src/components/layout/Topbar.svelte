<script lang="ts">
  import { route } from '../../lib/router';
  import { activeCaseId, activeSessionId } from '../../lib/stores/navigation';
  import { user, token } from '../../lib/stores/auth';
  import { sidebarCollapsed } from '../../lib/stores/layout';
  import { navigate } from '../../lib/router';

  const contextLabel = $derived.by(() => {
    if ($activeCaseId) return `Case ${$activeCaseId}`;
    if ($activeSessionId) return `Session ${$activeSessionId.slice(0, 12)}...`;
    const names: Record<string, string> = {
      cases: 'Cases',
      dashboard: 'Threat Intelligence',
      investigate: 'New Investigation',
      chat: 'Chat',
    };
    return names[$route.name] || 'socai';
  });

  function logout() {
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

  <span class="text-sm font-medium text-gray-200 truncate">{contextLabel}</span>

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
