import { writable } from 'svelte/store';
import type { ChatMessage, ActivityItem } from '../types';

export const messages = writable<ChatMessage[]>([]);
export const streaming = writable(false);
export const streamText = writable('');
export const activity = writable<ActivityItem[]>([]);
export const pendingFiles = writable<File[]>([]);
export const modelTier = writable<string>('standard');

export function resetChat() {
  messages.set([]);
  streaming.set(false);
  streamText.set('');
  activity.set([]);
  pendingFiles.set([]);
}
