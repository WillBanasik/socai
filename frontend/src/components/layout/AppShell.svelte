<script lang="ts">
  import type { Snippet } from 'svelte';
  import Sidebar from './Sidebar.svelte';
  import Topbar from './Topbar.svelte';
  import StatusBar from './StatusBar.svelte';
  import ContextPanel from './ContextPanel.svelte';
  import PanelDivider from './PanelDivider.svelte';
  import { sidebarWidth, sidebarCollapsed, contextPanelOpen, contextPanelWidth } from '../../lib/stores/layout';
  import { route } from '../../lib/router';

  let { children }: { children: Snippet } = $props();

  let baseSidebarWidth = $state(0);
  let baseContextWidth = $state(0);

  // Show context panel only on chat and case-detail views
  const showContext = $derived(
    $contextPanelOpen && ($route.name === 'chat' || $route.name === 'case-detail')
  );

  function startSidebarResize() {
    baseSidebarWidth = $sidebarWidth;
  }

  function handleSidebarResize(delta: number) {
    const newWidth = Math.max(180, Math.min(400, baseSidebarWidth + delta));
    sidebarWidth.set(newWidth);
  }

  function startContextResize() {
    baseContextWidth = $contextPanelWidth;
  }

  function handleContextResize(delta: number) {
    const newWidth = Math.max(250, Math.min(600, baseContextWidth - delta));
    contextPanelWidth.set(newWidth);
  }

  // Track drag start via pointerdown on divider
  let sidebarDragStart = $state(0);
  let contextDragStart = $state(0);
</script>

<div class="h-screen flex flex-col overflow-hidden bg-surface-950">
  <div class="flex flex-1 min-h-0">
    <!-- Sidebar -->
    {#if !$sidebarCollapsed}
      <div style="width: {$sidebarWidth}px" class="flex-shrink-0 overflow-hidden">
        <Sidebar />
      </div>
      <PanelDivider
        onresize={(delta) => {
          sidebarWidth.set(Math.max(180, Math.min(400, $sidebarWidth + delta)));
        }}
      />
    {/if}

    <!-- Main Area -->
    <div class="flex-1 flex flex-col min-w-0 min-h-0">
      <Topbar />
      <main class="flex-1 overflow-hidden">
        {@render children()}
      </main>
      <StatusBar />
    </div>

    <!-- Context Panel -->
    {#if showContext}
      <PanelDivider
        onresize={(delta) => {
          contextPanelWidth.set(Math.max(250, Math.min(600, $contextPanelWidth - delta)));
        }}
      />
      <div style="width: {$contextPanelWidth}px" class="flex-shrink-0 overflow-hidden">
        <ContextPanel />
      </div>
    {/if}
  </div>
</div>
