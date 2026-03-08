<script lang="ts">
  import { messages, streaming, streamText, activity, pendingFiles, modelTier, resetChat } from '../../lib/stores/chat';
  import { activeCaseId, activeSessionId } from '../../lib/stores/navigation';
  import { sessionList } from '../../lib/stores/sessions';
  import { contextPanelOpen } from '../../lib/stores/layout';
  import { route, navigate } from '../../lib/router';
  import { streamChat } from '../../lib/api/chat';
  import { getChatHistory } from '../../lib/api/cases';
  import { getSessionHistory, getSessionContext, getSession, createSession } from '../../lib/api/sessions';
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

  // ---- Slash commands (client-side, never hit the API) ----
  function addLocalMessage(content: string) {
    const msg: ChatMessage = { role: 'assistant', content, ts: new Date().toISOString() };
    messages.update((m) => [...m, msg]);
  }

  function handleSlashCommand(text: string): boolean {
    const trimmed = text.trim();
    if (!trimmed.startsWith('/')) return false;
    const parts = trimmed.split(/\s+/);
    const cmd = parts[0].toLowerCase();

    switch (cmd) {
      case '/help':
        addLocalMessage(
          '**Available commands:**\n' +
          '| Command | Description |\n' +
          '|---------|-------------|\n' +
          '| `/help` | Show this help |\n' +
          '| `/clear` | Clear chat display (context preserved) |\n' +
          '| `/new` | Start a fresh session |\n' +
          '| `/context` | Show accumulated investigation context |\n' +
          '| `/uploads` | List uploaded files |\n' +
          '| `/status` | Show current session/case info |\n' +
          '| `/prompts` | Show example prompts by complexity |\n' +
          '| `/model [fast\\|standard\\|heavy]` | Switch model tier |'
        );
        return true;

      case '/clear':
        messages.set([]);
        addLocalMessage('Chat display cleared. Session context is preserved.');
        return true;

      case '/new':
        (async () => {
          resetChat();
          activeCaseId.set(null);
          try {
            const session = await createSession();
            activeSessionId.set(session.session_id);
            sessionList.update((s) => [session, ...s]);
            navigate(`/session/${session.session_id}`);
          } catch (e: any) {
            activeSessionId.set(null);
            navigate('/');
            addToast('error', `Failed to create session: ${e.message}`);
          }
        })();
        return true;

      case '/context':
        (async () => {
          const sid = get(activeSessionId);
          if (!sid) { addLocalMessage('No active session.'); return; }
          try {
            const ctx = await getSessionContext(sid);
            const iocs = ctx.iocs || {};
            const findings = ctx.findings || [];
            const tel = ctx.telemetry_summaries || [];
            let md = '**Session Context:**\n';
            const iocCount = Object.values(iocs).reduce((n: number, arr: any) => n + (arr || []).length, 0);
            md += `- **IOCs:** ${iocCount} total`;
            for (const [k, v] of Object.entries(iocs)) { if (v && (v as any[]).length) md += ` (${k}: ${(v as any[]).length})`; }
            md += `\n- **Findings:** ${findings.length}\n- **Telemetry summaries:** ${tel.length}`;
            if (ctx.disposition) md += `\n- **Disposition:** ${ctx.disposition}`;
            if (findings.length) {
              md += '\n\n**Findings:**\n';
              findings.forEach((f: any, i: number) => { md += `${i + 1}. [${f.type}] ${f.summary}\n`; });
            }
            addLocalMessage(md);
          } catch { addLocalMessage('Failed to load context.'); }
        })();
        return true;

      case '/uploads':
        (async () => {
          const sid = get(activeSessionId);
          if (!sid) { addLocalMessage('No active session.'); return; }
          try {
            const meta = await getSession(sid);
            const files = meta.uploads || [];
            if (!files.length) { addLocalMessage('No files uploaded yet.'); return; }
            addLocalMessage('**Uploaded files:**\n' + files.map((f: string) => '- `' + f + '`').join('\n'));
          } catch { addLocalMessage('Failed to load session.'); }
        })();
        return true;

      case '/status': {
        const sid = get(activeSessionId);
        const cid = get(activeCaseId);
        const tier = get(modelTier);
        let md = '**Status:**\n';
        md += sid ? `- Session: \`${sid}\`\n` : '- No active session\n';
        md += cid ? `- Case: \`${cid}\`\n` : '- No case (session mode)\n';
        md += `- Model tier: ${tier}`;
        addLocalMessage(md);
        return true;
      }

      case '/model': {
        const tier = (parts[1] || '').toLowerCase();
        if (['fast', 'standard', 'heavy'].includes(tier)) {
          modelTier.set(tier);
          addLocalMessage(`Model tier set to **${tier}**.`);
        } else {
          addLocalMessage('Usage: `/model fast|standard|heavy`');
        }
        return true;
      }

      case '/prompts':
        addLocalMessage(
          '**Quick wins**\n' +
          '- `Run a WHOIS lookup on evil-domain.com and summarise the registrant info`\n' +
          '- `Enrich these IOCs and tell me which ones are malicious: 1.2.3.4, bad.com`\n\n' +
          '**Automated investigation**\n' +
          '- `Capture and analyse https://suspicious-login.com for phishing indicators`\n' +
          '- `Analyse this alert JSON, extract IOCs, enrich, and generate a verdict`\n\n' +
          '**Deep analysis**\n' +
          '- `I have a memory dump from a compromised host — analyse it for injected code`\n' +
          '- `Run full investigation: ingest the attached telemetry, enrich, and report`'
        );
        return true;

      default:
        addLocalMessage(`Unknown command: \`${cmd}\`. Type \`/help\` for available commands.`);
        return true;
    }
  }

  const COMMAND_WORDS = new Set(['help', 'clear', 'new', 'context', 'uploads', 'status', 'model', 'prompts']);

  async function handleSend(text: string) {
    // Intercept slash commands client-side
    if (text.trim().startsWith('/') && get(pendingFiles).length === 0) {
      if (handleSlashCommand(text)) return;
    }

    // Catch bare command words without the / prefix
    const bare = text.trim().toLowerCase();
    if (get(pendingFiles).length === 0 && COMMAND_WORDS.has(bare)) {
      addToast('info', `Did you mean /${bare}? Commands start with /`);
      return;
    }

    const files = get(pendingFiles);
    const tier = get(modelTier);
    const caseId = get(activeCaseId);
    let sessionId = get(activeSessionId);

    // Lazy session creation — only when sending a real message with no case/session
    if (!caseId && !sessionId) {
      try {
        const session = await createSession();
        sessionId = session.session_id;
        activeSessionId.set(sessionId);
        sessionList.update((s) => [session, ...s]);
      } catch (e: any) {
        addToast('error', `Failed to create session: ${e.message}`);
        return;
      }
    }

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
            // If materialisation happened, switch to case mode
            if (evt.case_id) {
              activeCaseId.set(evt.case_id);
              activeSessionId.set(null);
              // Update session in sidebar to show materialised state
              sessionList.update((s) =>
                s.map((sess) =>
                  sess.session_id === sessionId
                    ? { ...sess, status: 'materialised', case_id: evt.case_id }
                    : sess
                )
              );
              navigate(`/chat/${evt.case_id}`);
            }
            break;

          case 'error':
            addToast('error', evt.message || 'Stream error');
            break;
        }
      }
    } catch (e: any) {
      // If session is materialised, redirect to the linked case
      if (e.message?.includes('materialised') && get(activeSessionId)) {
        try {
          const meta = await getSession(get(activeSessionId)!);
          if (meta.case_id) {
            addLocalMessage(`This session has been materialised into **${meta.case_id}**. Switching to case chat.`);
            navigate(`/chat/${meta.case_id}`);
            return;
          }
        } catch {}
      }
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
    <WelcomeScreen />
  {:else}
    <MessageList />
  {/if}

  <ChatInput onsend={handleSend} />
</div>
