import { apiFetch } from './client';
import type { LandscapeData } from '../types';

export async function getLandscape(): Promise<LandscapeData> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const resp = await apiFetch('/api/landscape', { signal: controller.signal });
    return resp.json();
  } finally {
    clearTimeout(timeout);
  }
}
