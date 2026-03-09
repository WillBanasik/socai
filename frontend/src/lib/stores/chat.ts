import { writable } from 'svelte/store';
import type { ChatMessage, ActivityItem, TokenUsage } from '../types';

export const messages = writable<ChatMessage[]>([]);
export const streaming = writable(false);
export const streamText = writable('');
export const activity = writable<ActivityItem[]>([]);
export const pendingFiles = writable<File[]>([]);
export const lastUsage = writable<TokenUsage | null>(null);
export const sessionTokens = writable<{ input: number; output: number }>({ input: 0, output: 0 });

export function resetChat() {
  messages.set([]);
  streaming.set(false);
  streamText.set('');
  activity.set([]);
  pendingFiles.set([]);
  lastUsage.set(null);
  sessionTokens.set({ input: 0, output: 0 });
}
