import { writable, derived } from 'svelte/store';
import type { User } from '../types';

export const token = writable<string | null>(localStorage.getItem('socai_token'));
export const user = writable<User | null>(null);

export const isAuthenticated = derived(token, ($token) => !!$token);
export const isAdmin = derived(user, ($user) => $user?.permissions?.includes('admin') ?? false);

token.subscribe((value) => {
  if (value) {
    localStorage.setItem('socai_token', value);
  } else {
    localStorage.removeItem('socai_token');
  }
});
