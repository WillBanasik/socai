import { writable, derived } from 'svelte/store';
import type { CommandAction } from '../types';
import { fuzzyScore } from '../utils/fuzzy';

export const paletteOpen = writable(false);
export const paletteQuery = writable('');
export const paletteActions = writable<CommandAction[]>([]);

export const filteredActions = derived(
  [paletteActions, paletteQuery],
  ([$actions, $query]) => {
    if (!$query) return $actions;
    return $actions
      .map((a) => ({ action: a, score: fuzzyScore($query, a.label) }))
      .filter((x) => x.score > 0)
      .sort((a, b) => b.score - a.score)
      .map((x) => x.action);
  }
);
