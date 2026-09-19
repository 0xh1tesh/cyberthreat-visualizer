import { useSyncExternalStore } from 'react';

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
