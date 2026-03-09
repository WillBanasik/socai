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
  import SettingsView from './components/settings/SettingsView.svelte';
  import CommandPalette from './components/command/CommandPalette.svelte';
  import ToastContainer from './components/shared/ToastContainer.svelte';

  let ready = $state(false);
  let showShortcutOverlay = $state(false);

  onMount(async () => {
    initShortcuts();

    // Register global shortcuts
    registerShortcut({ key: 'k', ctrl: true, handler: () => paletteOpen.update((v) => !v) });
    registerShortcut({ key: 'b', ctrl: true, handler: () => sidebarCollapsed.update((v) => !v) });
    registerShortcut({ key: '\\', ctrl: true, handler: () => contextPanelOpen.update((v) => !v) });
    registerShortcut({ key: ',', ctrl: true, handler: () => navigate('/settings') });
    registerShortcut({ key: '/', ctrl: true, handler: () => showShortcutOverlay = !showShortcutOverlay });

    // Register command palette actions
    paletteActions.set([
      { id: 'nav-chat', label: 'Go to Chat', shortcut: '', section: 'Navigation', action: () => navigate('/') },
      { id: 'nav-cases', label: 'Go to Cases', shortcut: '', section: 'Navigation', action: () => navigate('/cases') },
      { id: 'nav-dashboard', label: 'Go to Dashboard', shortcut: '', section: 'Navigation', action: () => navigate('/dashboard') },
      { id: 'nav-investigate', label: 'New Investigation', shortcut: '', section: 'Navigation', action: () => navigate('/investigate') },
      { id: 'nav-settings', label: 'Open Settings', shortcut: 'Ctrl+,', section: 'Navigation', action: () => navigate('/settings') },
      { id: 'toggle-sidebar', label: 'Toggle Sidebar', shortcut: 'Ctrl+B', section: 'View', action: () => sidebarCollapsed.update((v) => !v) },
      { id: 'toggle-context', label: 'Toggle Context Panel', shortcut: 'Ctrl+\\', section: 'View', action: () => contextPanelOpen.update((v) => !v) },
      { id: 'show-shortcuts', label: 'Keyboard Shortcuts', shortcut: 'Ctrl+/', section: 'View', action: () => showShortcutOverlay = !showShortcutOverlay },
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

  const shortcuts = [
    { keys: 'Ctrl+K', action: 'Command palette' },
    { keys: 'Ctrl+B', action: 'Toggle sidebar' },
    { keys: 'Ctrl+\\', action: 'Toggle context panel' },
    { keys: 'Ctrl+,', action: 'Settings' },
    { keys: 'Ctrl+/', action: 'Show shortcuts' },
    { keys: 'Enter', action: 'Send message' },
    { keys: 'Shift+Enter', action: 'New line' },
  ];
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
    {:else if $route.name === 'settings'}
      <SettingsView />
    {:else}
      <ChatView />
    {/if}
  </AppShell>
{/if}

<CommandPalette />
<ToastContainer />

<!-- Keyboard shortcuts overlay -->
{#if showShortcutOverlay}
  <!-- svelte-ignore a11y_no_static_element_interactions -->
  <!-- svelte-ignore a11y_interactive_supports_focus -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
    onclick={() => showShortcutOverlay = false}
    onkeydown={(e) => { if (e.key === 'Escape') showShortcutOverlay = false; }}
    role="dialog"
    aria-modal="true"
  >
    <div class="bg-surface-800 border border-surface-600 rounded-xl shadow-2xl p-6 max-w-md w-full fade-in">
      <h3 class="text-sm font-semibold text-gray-300 mb-4">Keyboard Shortcuts</h3>
      <div class="space-y-2">
        {#each shortcuts as s}
          <div class="flex items-center justify-between">
            <span class="text-xs text-gray-400">{s.action}</span>
            <kbd class="text-[10px] bg-surface-700 text-gray-300 px-2 py-0.5 rounded border border-surface-600 font-mono">
              {s.keys}
            </kbd>
          </div>
        {/each}
      </div>
      <p class="text-[10px] text-gray-500 mt-4">Press Esc or click outside to close</p>
    </div>
  </div>
{/if}
