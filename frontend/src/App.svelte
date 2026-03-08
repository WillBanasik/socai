<script lang="ts">
  import { route, navigate } from './lib/router';
  import { token, user, isAuthenticated } from './lib/stores/auth';
  import { getMe } from './lib/api/auth';
  import { paletteOpen, paletteActions } from './lib/stores/commandPalette';
  import { sidebarCollapsed, contextPanelOpen } from './lib/stores/layout';
  import { restoreContext } from './lib/stores/navigation';
  import { initShortcuts, registerShortcut } from './lib/utils/shortcuts';
  import { onMount } from 'svelte';

  import AppShell from './components/layout/AppShell.svelte';
  import LoginPage from './components/auth/LoginPage.svelte';
  import ChatView from './components/chat/ChatView.svelte';
  import CasesBrowse from './components/cases/CasesBrowse.svelte';
  import CaseDetail from './components/detail/CaseDetail.svelte';
  import DashboardView from './components/dashboard/DashboardView.svelte';
  import InvestigateView from './components/investigate/InvestigateView.svelte';
  import CommandPalette from './components/command/CommandPalette.svelte';
  import ToastContainer from './components/shared/ToastContainer.svelte';

  let ready = $state(false);

  onMount(async () => {
    initShortcuts();

    // Register global shortcuts
    registerShortcut({ key: 'k', ctrl: true, handler: () => paletteOpen.update((v) => !v) });
    registerShortcut({ key: 'b', ctrl: true, handler: () => sidebarCollapsed.update((v) => !v) });
    registerShortcut({ key: '\\', ctrl: true, handler: () => contextPanelOpen.update((v) => !v) });

    // Register command palette actions
    paletteActions.set([
      { id: 'nav-chat', label: 'Go to Chat', shortcut: '', section: 'Navigation', action: () => navigate('/') },
      { id: 'nav-cases', label: 'Go to Cases', shortcut: '', section: 'Navigation', action: () => navigate('/cases') },
      { id: 'nav-dashboard', label: 'Go to Dashboard', shortcut: '', section: 'Navigation', action: () => navigate('/dashboard') },
      { id: 'nav-investigate', label: 'New Investigation', shortcut: '', section: 'Navigation', action: () => navigate('/investigate') },
      { id: 'toggle-sidebar', label: 'Toggle Sidebar', shortcut: 'Ctrl+B', section: 'View', action: () => sidebarCollapsed.update((v) => !v) },
      { id: 'toggle-context', label: 'Toggle Context Panel', shortcut: 'Ctrl+\\', section: 'View', action: () => contextPanelOpen.update((v) => !v) },
    ]);

    // Auth check
    if ($token) {
      try {
        const me = await getMe();
        user.set(me);
        restoreContext(me.email);
        if ($route.name === 'login') navigate('/');
      } catch {
        token.set(null);
        navigate('/login');
      }
    } else if ($route.name !== 'login') {
      navigate('/login');
    }

    ready = true;
  });

  // Auth guard
  $effect(() => {
    if (ready && !$isAuthenticated && $route.name !== 'login') {
      navigate('/login');
    }
  });
</script>

{#if !ready}
  <div class="h-screen flex items-center justify-center bg-surface-950">
    <div class="text-accent-400 text-lg font-bold animate-pulse">socai</div>
  </div>
{:else if $route.name === 'login'}
  <LoginPage />
{:else}
  <AppShell>
    {#if $route.name === 'chat'}
      <ChatView />
    {:else if $route.name === 'cases'}
      <CasesBrowse />
    {:else if $route.name === 'case-detail'}
      <CaseDetail />
    {:else if $route.name === 'dashboard'}
      <DashboardView />
    {:else if $route.name === 'investigate'}
      <InvestigateView />
    {:else}
      <ChatView />
    {/if}
  </AppShell>
{/if}

<CommandPalette />
<ToastContainer />
