import { token } from '../stores/auth';
import { get } from 'svelte/store';

const API_BASE = '';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const t = get(token);
  const headers = new Headers(options.headers);
  if (t) {
    headers.set('Authorization', `Bearer ${t}`);
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    token.set(null);
    localStorage.removeItem('socai_token');
    window.location.hash = '#/login';
    throw new ApiError(401, 'Unauthorized');
  }

  if (!response.ok && response.headers.get('content-type')?.includes('text/event-stream') === false) {
    const text = await response.text();
    throw new ApiError(response.status, text);
  }

  return response;
}

export async function apiJson<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await apiFetch(path, options);
  return response.json();
}

export async function apiPost<T>(path: string, body: Record<string, any>): Promise<T> {
  const fd = new FormData();
  for (const [key, value] of Object.entries(body)) {
    if (value !== undefined && value !== null) {
      if (value instanceof File) {
        fd.append(key, value);
      } else if (Array.isArray(value) && value[0] instanceof File) {
        for (const f of value) fd.append(key, f);
      } else {
        fd.append(key, String(value));
      }
    }
  }
  const response = await apiFetch(path, { method: 'POST', body: fd });
  return response.json();
}
