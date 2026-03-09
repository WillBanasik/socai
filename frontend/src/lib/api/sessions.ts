import { apiJson, apiPost, apiFetch } from './client';
import type { SessionMeta, SessionContext, ThreadSummary } from '../types';

export async function listSessions(): Promise<SessionMeta[]> {
  return apiJson<SessionMeta[]>('/api/sessions');
}

export async function createSession(): Promise<SessionMeta> {
  const resp = await apiFetch('/api/sessions', { method: 'POST' });
  return resp.json();
}

export async function getSession(sessionId: string): Promise<SessionMeta> {
  return apiJson<SessionMeta>(`/api/sessions/${sessionId}`);
}

export async function renameSession(sessionId: string, title: string): Promise<void> {
  await apiFetch(`/api/sessions/${sessionId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title }),
  });
}

export async function deleteSession(sessionId: string): Promise<void> {
  await apiFetch(`/api/sessions/${sessionId}`, { method: 'DELETE' });
}

export async function deleteAllSessions(): Promise<void> {
  await apiFetch('/api/sessions', { method: 'DELETE' });
}

export async function cleanupSessions(): Promise<void> {
  await apiFetch('/api/sessions/cleanup', { method: 'POST' });
}

export async function uploadToSession(sessionId: string, file: File): Promise<any> {
  const fd = new FormData();
  fd.append('file', file);
  const resp = await apiFetch(`/api/sessions/${sessionId}/upload`, {
    method: 'POST',
    body: fd,
  });
  return resp.json();
}

export async function getSessionHistory(sessionId: string, threadId?: string): Promise<any[]> {
  const params = threadId ? `?thread=${threadId}` : '';
  return apiJson<any[]>(`/api/sessions/${sessionId}/history${params}`);
}

export async function getSessionContext(sessionId: string): Promise<SessionContext> {
  return apiJson<SessionContext>(`/api/sessions/${sessionId}/context`);
}

export async function listThreads(sessionId: string): Promise<ThreadSummary[]> {
  return apiJson<ThreadSummary[]>(`/api/sessions/${sessionId}/threads`);
}

export async function pivotThread(sessionId: string, label?: string): Promise<ThreadSummary> {
  const fd = new FormData();
  fd.append('label', label || '');
  const resp = await apiFetch(`/api/sessions/${sessionId}/pivot-with-label`, {
    method: 'POST',
    body: fd,
  });
  return resp.json();
}

export async function activateThread(sessionId: string, threadId: string): Promise<ThreadSummary> {
  const resp = await apiFetch(`/api/sessions/${sessionId}/threads/${threadId}/activate`, {
    method: 'POST',
  });
  return resp.json();
}

export async function materialiseSession(sessionId: string, data: {
  case_id?: string;
  title?: string;
  severity?: string;
  disposition?: string;
}): Promise<any> {
  return apiPost(`/api/sessions/${sessionId}/materialise`, data);
}
