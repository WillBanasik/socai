import { writable } from 'svelte/store';
import type { SessionMeta } from '../types';

export const sessionList = writable<SessionMeta[]>([]);
