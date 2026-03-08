<script lang="ts">
  import { messages, streaming, streamText, activity, pendingFiles, modelTier, resetChat } from '../../lib/stores/chat';
  import { activeCaseId, activeSessionId } from '../../lib/stores/navigation';
  import { contextPanelOpen } from '../../lib/stores/layout';
  import { route } from '../../lib/router';
  import { streamChat } from '../../lib/api/chat';
  import { getChatHistory } from '../../lib/api/cases';
  import { getSessionHistory } from '../../lib/api/sessions';
  import { parseSSE } from '../../lib/utils/sse';
  import { addToast } from '../../lib/stores/toasts';
  import MessageList from './MessageList.svelte';
  import ChatInput from './ChatInput.svelte';
  import WelcomeScreen from './WelcomeScreen.svelte';
  import MaterialiseBanner from './MaterialiseBanner.svelte';
  import type { ChatMessage, ToolCall } from '../../lib/types';
  import { onMount } from 'svelte';
  import { get } from 'svelte/store';

  let materialisedCase = $state<{ caseId: string; title?: string; severity?: string } | null>(null);

  // Update context based on route
  $effect(() => {
    const r = $route;
    if (r.name === 'chat' && r.params.caseId) {
      activeCaseId.set(r.params.caseId);
      activeSessionId.set(null);
      contextPanelOpen.set(true);
    } else if (r.name === 'chat' && r.params.sessionId) {
      activeSessionId.set(r.params.sessionId);
      activeCaseId.set(null);
      contextPanelOpen.set(true);
    } else {
      // No specific context
      contextPanelOpen.set(false);
    }
  });

  // Load history when context changes
  $effect(() => {
    const cid = $activeCaseId;
    const sid = $activeSessionId;
    loadHistory(cid, sid);
  });

  async function loadHistory(caseId: string | null, sessionId: string | null) {
    resetChat();
    materialisedCase = null;
    try {
      let history: any[] = [];
      if (caseId) {
        history = await getChatHistory(caseId);
      } else if (sessionId) {
        history = await getSessionHistory(sessionId);
      }
      if (history.length > 0) {
        messages.set(
          history.map((m: any) => ({
            role: m.role,
            content: m.content || (typeof m === 'string' ? m : ''),
            ts: m.ts,
            tool_calls: m.tool_calls,
          }))
        );
      }
    } catch {}
  }

  async function handleSend(text: string) {
    const files = get(pendingFiles);
    const tier = get(modelTier);
    const caseId = get(activeCaseId);
    const sessionId = get(activeSessionId);

    // Add user message optimistically
    const userMsg: ChatMessage = {
      role: 'user',
      content: text,
      ts: new Date().toISOString(),
      files: files.map((f) => f.name),
    };
    messages.update((m) => [...m, userMsg]);
    pendingFiles.set([]);

    streaming.set(true);
    streamText.set('');
    activity.set([]);

    let fullReply = '';
    const toolCalls: ToolCall[] = [];

    try {
      const response = await streamChat({
        caseId: caseId || undefined,
        sessionId: sessionId || undefined,
        message: text,
        modelTier: tier,
        files: files.length > 0 ? files : undefined,
      });

      for await (const evt of parseSSE(response)) {
        switch (evt.type) {
          case 'text_delta':
            fullReply += evt.text || '';
            streamText.set(fullReply);
            break;

          case 'tool_start':
            activity.update((a) => [
              ...a,
              { name: evt.name || '', status: 'running', input: evt.input },
            ]);
            toolCalls.push({ name: evt.name || '', input: evt.input });
            break;

          case 'tool_result':
            activity.update((a) =>
              a.map((item) =>
                item.name === evt.name && item.status === 'running'
                  ? { ...item, status: 'done', result: evt.result }
                  : item
              )
            );
            const tc = toolCalls.find((t) => t.name === evt.name && !t.result);
            if (tc) tc.result = evt.result;
            break;

          case 'case_context_loaded':
            materialisedCase = {
              caseId: evt.case_id || '',
              title: evt.title,
              severity: evt.severity,
            };
            break;

          case 'done':
            fullReply = evt.reply || fullReply;
            break;

          case 'error':
            addToast('error', evt.message || 'Stream error');
            break;
        }
      }
    } catch (e: any) {
      addToast('error', `Chat error: ${e.message}`);
    }

    // Finalise assistant message
    const assistantMsg: ChatMessage = {
      role: 'assistant',
      content: fullReply,
      ts: new Date().toISOString(),
      tool_calls: toolCalls.length > 0 ? toolCalls : undefined,
    };
    messages.update((m) => [...m, assistantMsg]);
    streaming.set(false);
    streamText.set('');
    activity.set([]);
  }

  const isEmpty = $derived($messages.length === 0 && !$streaming);
</script>

<div class="h-full flex flex-col relative">
  {#if materialisedCase}
    <MaterialiseBanner {...materialisedCase} />
  {/if}

  {#if isEmpty}
    <WelcomeScreen onsend={handleSend} />
  {:else}
    <MessageList />
  {/if}

  <ChatInput onsend={handleSend} />
</div>
