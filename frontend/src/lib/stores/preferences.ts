import { writable } from 'svelte/store';
import type { UserPreferences } from '../types';

const defaults: UserPreferences = {
  custom_instructions: '',
  response_style: 'concise',
  pinned_sessions: [],
  session_tags: {},
};

export const userPreferences = writable<UserPreferences>({ ...defaults });
