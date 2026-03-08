import { writable } from 'svelte/store';
import type { Toast } from '../types';

export const toasts = writable<Toast[]>([]);

let counter = 0;

export function addToast(type: Toast['type'], message: string, duration = 4000) {
  const id = `toast-${++counter}`;
  toasts.update((t) => [...t, { id, type, message, duration }]);
  if (duration > 0) {
    setTimeout(() => removeToast(id), duration);
  }
  return id;
}

export function removeToast(id: string) {
  toasts.update((t) => t.filter((x) => x.id !== id));
}
