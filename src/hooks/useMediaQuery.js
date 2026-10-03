import { useCallback, useEffect, useState, useSyncExternalStore } from 'react';

export function useMediaQuery(query) {
  return useSyncExternalStore(
    (notify) => {
      const media = window.matchMedia(query);
      media.addEventListener('change', notify);
      return () => media.removeEventListener('change', notify);
    },
    () => window.matchMedia(query).matches,
    () => false,
  );
}

/** 'wide' >= 1280px, 'medium' >= 768px, otherwise 'compact'. */
export function useLayoutMode() {
  const wide = useMediaQuery('(min-width: 1280px)');
  const medium = useMediaQuery('(min-width: 768px)');
  if (wide) return 'wide';
  if (medium) return 'medium';
  return 'compact';
}

const THEME_KEY = 'threat-globe:theme';

const readStoredTheme = () => {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    return stored === 'light' || stored === 'dark' ? stored : null;
  } catch {
    return null;
  }
};

/** Follows the system scheme until the viewer picks one; the pick is remembered per browser. */
export function useTheme() {
  const [chosen, setChosen] = useState(readStoredTheme);
  const systemDark = useMediaQuery('(prefers-color-scheme: dark)');
  const theme = chosen || (systemDark ? 'dark' : 'light');

  useEffect(() => {
    if (chosen) document.documentElement.dataset.theme = chosen;
    else delete document.documentElement.dataset.theme;
  }, [chosen]);

  const toggle = useCallback(() => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setChosen(next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch {
      // storage unavailable (private mode); the choice lasts for this visit only
    }
  }, [theme]);

  return [theme, toggle];
}
