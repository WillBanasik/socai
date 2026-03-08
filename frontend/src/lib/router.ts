import { writable, derived } from 'svelte/store';

export interface Route {
  path: string;
  params: Record<string, string>;
}

function parseHash(): Route {
  const hash = window.location.hash.slice(1) || '/';
  const routes: [RegExp, string[]][] = [
    [/^\/login$/, []],
    [/^\/chat\/([^/]+)$/, ['caseId']],
    [/^\/session\/([^/]+)$/, ['sessionId']],
    [/^\/cases\/([^/]+)$/, ['caseId']],
    [/^\/cases$/, []],
    [/^\/dashboard$/, []],
    [/^\/investigate$/, []],
    [/^\/$/, []],
  ];

  for (const [re, paramNames] of routes) {
    const match = hash.match(re);
    if (match) {
      const params: Record<string, string> = {};
      paramNames.forEach((name, i) => {
        params[name] = match[i + 1];
      });
      return { path: hash.replace(/\/[^/]+$/, paramNames.length ? hash.match(re)![0].replace(match[1] || '', ':id') : hash), params };
    }
  }

  return { path: hash, params: {} };
}

function getRouteName(hash: string): string {
  if (hash === '/login') return 'login';
  if (hash === '/' || hash === '') return 'chat';
  if (/^\/chat\//.test(hash)) return 'chat';
  if (/^\/session\//.test(hash)) return 'chat';
  if (/^\/cases\/[^/]+$/.test(hash)) return 'case-detail';
  if (hash === '/cases') return 'cases';
  if (hash === '/dashboard') return 'dashboard';
  if (hash === '/investigate') return 'investigate';
  return 'chat';
}

export const currentHash = writable(window.location.hash.slice(1) || '/');

export const route = derived(currentHash, ($hash) => {
  const routes: [RegExp, string[]][] = [
    [/^\/chat\/(.+)$/, ['caseId']],
    [/^\/session\/(.+)$/, ['sessionId']],
    [/^\/cases\/(.+)$/, ['caseId']],
  ];

  const params: Record<string, string> = {};
  for (const [re, names] of routes) {
    const m = $hash.match(re);
    if (m) {
      names.forEach((n, i) => (params[n] = m[i + 1]));
      break;
    }
  }

  return {
    name: getRouteName($hash),
    hash: $hash,
    params,
  };
});

export function navigate(hash: string) {
  window.location.hash = hash;
}

// Listen for hash changes
window.addEventListener('hashchange', () => {
  currentHash.set(window.location.hash.slice(1) || '/');
});
