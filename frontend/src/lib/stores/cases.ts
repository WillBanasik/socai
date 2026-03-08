import { writable, derived } from 'svelte/store';
import type { CaseBrowseItem, Severity } from '../types';

export const allCases = writable<CaseBrowseItem[]>([]);

export const filters = writable({
  severity: '' as Severity | '',
  status: '',
  disposition: '',
  search: '',
});

export const filteredCases = derived([allCases, filters], ([$cases, $filters]) => {
  return $cases.filter((c) => {
    if ($filters.severity && c.severity !== $filters.severity) return false;
    if ($filters.status && c.status !== $filters.status) return false;
    if ($filters.disposition && c.disposition !== $filters.disposition) return false;
    if ($filters.search) {
      const q = $filters.search.toLowerCase();
      const match =
        c.case_id.toLowerCase().includes(q) ||
        c.title.toLowerCase().includes(q) ||
        (c.analyst?.toLowerCase().includes(q) ?? false);
      if (!match) return false;
    }
    return true;
  });
});
