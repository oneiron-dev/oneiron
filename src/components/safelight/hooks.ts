import * as React from 'react'

declare global {
  interface Window {
    cuelume?: {
      play: (name: string) => void
      setEnabled: (on: boolean) => void
    }
  }
}

/* ── cuelume · the house sound. every call is guarded: the library may be
   muted, blocked before the first gesture, or absent. ── */
export function cue(name: string) {
  try {
    window.cuelume?.play(name)
  } catch {
    /* silence is fine */
  }
}

export function setCueEnabled(on: boolean) {
  try {
    window.cuelume?.setEnabled(on)
  } catch {
    /* no library, no sound */
  }
}

/* ── a boolean that lives as a class on <html> and remembers itself.
   the class is already right at first paint (public/prepaint.js), so the
   hook reads the DOM on mount rather than the store — no flash, no
   localStorage during SSR. ── */
export function useLocalStorageClass(
  className: string,
  storageKey: string,
  onValue: string,
  offValue: string,
): [boolean, (next: boolean) => void] {
  const [on, setOnState] = React.useState(false)

  React.useEffect(() => {
    setOnState(document.documentElement.classList.contains(className))
  }, [className])

  const setOn = React.useCallback(
    (next: boolean) => {
      document.documentElement.classList.toggle(className, next)
      try {
        localStorage.setItem(storageKey, next ? onValue : offValue)
      } catch {
        /* private mode · the class still holds for this session */
      }
      setOnState(next)
    },
    [className, storageKey, onValue, offValue],
  )

  return [on, setOn]
}

/* ── the rail fold: [ or the mark. the labels swap out first (130ms),
   then the width animates, then the labels come back — otherwise the
   text reflows mid-slide. reduced motion skips the dance. ── */
export function useRailFold(railRef: React.RefObject<HTMLElement | null>) {
  const [folded, applyFold] = useLocalStorageClass(
    'rail-folded',
    'oneiron-mock-rail',
    'folded',
    'open',
  )
  const foldTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null)

  const toggleFold = React.useCallback(() => {
    const next = !document.documentElement.classList.contains('rail-folded')
    cue('toggle')
    if (matchMedia('(prefers-reduced-motion: reduce)').matches) {
      applyFold(next)
      return
    }
    if (foldTimer.current) clearTimeout(foldTimer.current)
    const rail = railRef.current
    rail?.classList.add('swap')
    foldTimer.current = setTimeout(() => {
      applyFold(next)
      requestAnimationFrame(() =>
        requestAnimationFrame(() => rail?.classList.remove('swap')),
      )
    }, 130)
  }, [applyFold, railRef])

  React.useEffect(
    () => () => {
      if (foldTimer.current) clearTimeout(foldTimer.current)
    },
    [],
  )

  return { folded, toggleFold }
}

export const PACKS = ['crm', 'office', 'channels', 'lenses'] as const
export type PackName = (typeof PACKS)[number]

/* ── pack-group disclosure (owner 07-07): default expanded · sticky
   manual fold · per-group. state lives on <html> as rg-* classes (set
   pre-paint) + localStorage 'oneiron-rail-groups' JSON. ── */
export function usePackFolds() {
  const [folded, setFolded] = React.useState<Record<string, boolean>>({})

  const read = React.useCallback(() => {
    const root = document.documentElement
    const next: Record<string, boolean> = {}
    for (const p of PACKS) next[p] = root.classList.contains(`rg-${p}`)
    return next
  }, [])

  React.useEffect(() => {
    setFolded(read())
  }, [read])

  const toggle = React.useCallback(
    (name: PackName) => {
      const root = document.documentElement
      root.classList.toggle(`rg-${name}`)
      const next = read()
      const state: Record<string, string> = {}
      for (const p of PACKS) state[p] = next[p] ? 'folded' : 'open'
      try {
        localStorage.setItem('oneiron-rail-groups', JSON.stringify(state))
      } catch {
        /* private mode */
      }
      setFolded(next)
      cue('toggle')
    },
    [read],
  )

  return { folded, toggle }
}

/* ── t / m: theme + sound. their real homes are the settings page; the
   keys stay so the exemplars can be flipped while annotating. the theme
   is three-state — system → light → dark → system — held as a class on
   <html> (public/prepaint.js restores it before first paint); no class
   = follow the system (color-scheme: light dark in safelight.css). ── */
export type Theme = 'system' | 'light' | 'dark'
const THEME_ORDER: Theme[] = ['system', 'light', 'dark']

export function readTheme(): Theme {
  const c = document.documentElement.classList
  return c.contains('light') ? 'light' : c.contains('dark') ? 'dark' : 'system'
}

export function applyTheme(next: Theme) {
  const c = document.documentElement.classList
  c.toggle('light', next === 'light')
  c.toggle('dark', next === 'dark')
  try {
    if (next === 'system') localStorage.removeItem('oneiron-theme')
    else localStorage.setItem('oneiron-theme', next)
  } catch {
    /* private mode · the class still holds for this session */
  }
}

export function useTheme() {
  return React.useCallback(() => {
    const cur = readTheme()
    applyTheme(THEME_ORDER[(THEME_ORDER.indexOf(cur) + 1) % THEME_ORDER.length])
    cue('toggle')
  }, [])
}

export function useSound() {
  const sound = React.useRef(true)

  React.useEffect(() => {
    let on = true
    try {
      on = localStorage.getItem('oneiron-mock-sound') !== 'off'
    } catch {
      /* private mode · sound on */
    }
    sound.current = on
    setCueEnabled(on)
  }, [])

  return React.useCallback(() => {
    const next = !sound.current
    sound.current = next
    try {
      localStorage.setItem('oneiron-mock-sound', next ? 'on' : 'off')
    } catch {
      /* private mode */
    }
    setCueEnabled(next)
    if (next) cue('toggle')
  }, [])
}

/* ── global keys · keystrokes never fire while you are typing ── */
export function useGlobalKeys(handlers: Record<string, () => void>) {
  const ref = React.useRef(handlers)
  React.useEffect(() => {
    ref.current = handlers
  })
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null
      if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return
      ref.current[e.key]?.()
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  }, [])
}

/* Escape carries no typing guard in the mocks: it closes from anywhere,
   including a focused input. */
export function useEscape(handler: () => void) {
  const ref = React.useRef(handler)
  React.useEffect(() => {
    ref.current = handler
  })
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') ref.current()
    }
    addEventListener('keydown', onKey)
    return () => removeEventListener('keydown', onKey)
  }, [])
}

export function useDocumentEvent<K extends keyof DocumentEventMap>(
  type: K,
  handler: (e: DocumentEventMap[K]) => void,
) {
  const ref = React.useRef(handler)
  React.useEffect(() => {
    ref.current = handler
  })
  React.useEffect(() => {
    const fn = (e: Event) => ref.current(e as DocumentEventMap[K])
    document.addEventListener(type, fn)
    return () => document.removeEventListener(type, fn)
  }, [type])
}

/* ── the braille throbber — terminal heritage, never a spinner. ONE
   interval drives every span on the page; reduced motion holds the
   first frame. null until the first tick so SSR and hydration agree. ── */
const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
let frame: string | null = null
let frameIndex = 0
let throbTimer: ReturnType<typeof setInterval> | null = null
const throbListeners = new Set<() => void>()

function subscribeThrob(listener: () => void) {
  throbListeners.add(listener)
  if (!throbTimer && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
    throbTimer = setInterval(() => {
      frameIndex = (frameIndex + 1) % FRAMES.length
      frame = FRAMES[frameIndex]
      throbListeners.forEach((l) => l())
    }, 120)
  }
  return () => {
    throbListeners.delete(listener)
    if (throbListeners.size === 0 && throbTimer) {
      clearInterval(throbTimer)
      throbTimer = null
    }
  }
}

export function useThrobber(): string | null {
  return React.useSyncExternalStore(
    subscribeThrob,
    () => frame,
    () => null,
  )
}

type CuedEvent = Event & { __cued?: boolean }

/* A handler that rings its own cue marks the native event so the
   document-level press does not double up. The mocks stopped propagation
   to get this; React delegates its listeners, so stopPropagation there no
   longer reaches a listener bound on the document itself. */
export function markCued(e: { nativeEvent: Event }) {
  ;(e.nativeEvent as CuedEvent).__cued = true
}

/* every bare act presses */
export function useCuePress() {
  useDocumentEvent('click', (e) => {
    if ((e as CuedEvent).__cued) return
    if ((e.target as HTMLElement | null)?.closest?.('.act')) cue('press')
  })
}
