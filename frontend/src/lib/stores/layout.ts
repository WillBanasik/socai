import { writable } from 'svelte/store';

function persistedWritable<T>(key: string, initial: T) {
  const stored = localStorage.getItem(key);
  const value = stored ? JSON.parse(stored) : initial;
  const store = writable<T>(value);
  store.subscribe((v) => localStorage.setItem(key, JSON.stringify(v)));
  return store;
}

export const sidebarWidth = persistedWritable('socai_sidebar_w', 260);
export const sidebarCollapsed = persistedWritable('socai_sidebar_collapsed', false);
export const contextPanelOpen = writable(false);
export const contextPanelWidth = persistedWritable('socai_context_w', 380);
