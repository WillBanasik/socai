type ShortcutHandler = (e: KeyboardEvent) => void;

interface Shortcut {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  handler: ShortcutHandler;
}

const shortcuts: Shortcut[] = [];

export function registerShortcut(shortcut: Shortcut) {
  shortcuts.push(shortcut);
  return () => {
    const idx = shortcuts.indexOf(shortcut);
    if (idx >= 0) shortcuts.splice(idx, 1);
  };
}

export function initShortcuts() {
  window.addEventListener('keydown', (e) => {
    for (const s of shortcuts) {
      if (
        e.key.toLowerCase() === s.key.toLowerCase() &&
        !!e.ctrlKey === !!s.ctrl &&
        !!e.shiftKey === !!s.shift &&
        !!e.altKey === !!s.alt
      ) {
        e.preventDefault();
        s.handler(e);
        return;
      }
    }
  });
}
