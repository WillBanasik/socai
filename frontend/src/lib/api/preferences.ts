import { apiJson, apiFetch } from './client';
import type { UserPreferences, SessionMeta } from '../types';

export async function getPreferences(): Promise<UserPreferences> {
  return apiJson<UserPreferences>('/api/preferences');
}

export async function updatePreferences(updates: Partial<UserPreferences>): Promise<UserPreferences> {
  const resp = await apiFetch('/api/preferences', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
  return resp.json();
}

export async function pinSession(sessionId: string): Promise<{ pinned_sessions: string[] }> {
  const resp = await apiFetch(`/api/preferences/pin/${sessionId}`, { method: 'POST' });
  return resp.json();
}

export async function unpinSession(sessionId: string): Promise<{ pinned_sessions: string[] }> {
  const resp = await apiFetch(`/api/preferences/pin/${sessionId}`, { method: 'DELETE' });
  return resp.json();
}

export async function tagSession(sessionId: string, tags: string[]): Promise<any> {
  const resp = await apiFetch(`/api/preferences/tags/${sessionId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ tags }),
  });
  return resp.json();
}

export async function searchSessions(query: string): Promise<(SessionMeta & { score: number; match_fields: string[] })[]> {
  return apiJson(`/api/sessions/search?q=${encodeURIComponent(query)}`);
}

export async function exportSession(sessionId: string): Promise<string> {
  const resp = await apiFetch(`/api/sessions/${sessionId}/export`);
  return resp.text();
}
