import { writable, derived } from 'svelte/store';

export type View = 'login' | 'chat' | 'cases' | 'case-detail' | 'dashboard' | 'investigate' | 'settings';

export const activeView = writable<View>('chat');
export const activeCaseId = writable<string | null>(null);
export const activeSessionId = writable<string | null>(null);

export const activeContext = derived(
  [activeCaseId, activeSessionId],
  ([$caseId, $sessionId]) => {
    if ($caseId) return { type: 'case' as const, id: $caseId };
    if ($sessionId) return { type: 'session' as const, id: $sessionId };
    return null;
  }
);

export function persistContext(email: string) {
  const key = `socai_active_context_${email}`;
  let caseId: string | null = null;
  let sessionId: string | null = null;

  activeCaseId.subscribe((v) => (caseId = v))();
  activeSessionId.subscribe((v) => (sessionId = v))();

  localStorage.setItem(key, JSON.stringify({ caseId, sessionId, ts: new Date().toISOString() }));
}

export function restoreContext(email: string) {
  const key = `socai_active_context_${email}`;
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return;
    const { caseId, sessionId } = JSON.parse(raw);
    if (caseId) activeCaseId.set(caseId);
    if (sessionId) activeSessionId.set(sessionId);
  } catch {}
}
