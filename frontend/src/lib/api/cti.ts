import { apiJson, apiFetch } from './client';
import type { CTIFeedItem, TrendingIndicator, WatchlistEntry, HeatmapCell, IOCDecayEntry } from '../types';

export async function getCTIFeed(): Promise<{ feed: CTIFeedItem[]; summary: any }> {
  return apiJson('/api/cti/feed');
}

export async function getTrending(): Promise<TrendingIndicator[]> {
  return apiJson('/api/cti/trending');
}

export async function getAttackHeatmap(): Promise<HeatmapCell[]> {
  return apiJson('/api/cti/attack-heatmap');
}

export async function getWatchlist(): Promise<{ watchlist: WatchlistEntry[] }> {
  return apiJson('/api/cti/watchlist');
}

export async function addToWatchlist(name: string, description: string): Promise<void> {
  const fd = new FormData();
  fd.append('name', name);
  fd.append('description', description);
  await apiFetch('/api/cti/watchlist', { method: 'POST', body: fd });
}

export async function removeFromWatchlist(name: string): Promise<void> {
  await apiFetch(`/api/cti/watchlist?name=${encodeURIComponent(name)}`, { method: 'DELETE' });
}

export async function getIOCDecay(): Promise<IOCDecayEntry[]> {
  return apiJson('/api/cti/ioc-decay');
}

export async function getIOCXRef(): Promise<any> {
  return apiJson('/api/cti/ioc-xref');
}
