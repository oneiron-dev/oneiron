/* Ordered dither and the develop timeline shared by every painted surface
   (the field, the island grain, seals, portraits). Pure functions only; the
   develop loop takes its clock and frame scheduler from the caller's
   environment. */

/* The 8x8 Bayer index matrix, row-major. */
export const BAYER_8X8: readonly number[] = [
  0, 32, 8, 40, 2, 34, 10, 42,
  48, 16, 56, 24, 50, 18, 58, 26,
  12, 44, 4, 36, 14, 46, 6, 38,
  60, 28, 52, 20, 62, 30, 54, 22,
  3, 35, 11, 43, 1, 33, 9, 41,
  51, 19, 59, 27, 49, 17, 57, 25,
  15, 47, 7, 39, 13, 45, 5, 37,
  63, 31, 55, 23, 61, 29, 53, 21,
]

/* The threshold for cell (x, y), in (0, 1). A cell prints when its coverage
   exceeds the threshold. Negative coordinates wrap like positive ones. */
export function bayerThreshold(x: number, y: number): number {
  return (BAYER_8X8[(y & 7) * 8 + (x & 7)] + 0.5) / 64
}

/* The develop curve: a quartic ease-out, fast exposure that settles. */
export function easeOutQuart(t: number): number {
  const c = Math.min(1, Math.max(0, t))
  return 1 - Math.pow(1 - c, 4)
}

export const DEVELOP_MS = 1000

/* Runs render(exposure) from 0 to 1 over `duration` ms on animation frames.
   With `reduced` set it renders the full exposure at once. Returns a cancel
   function; a cancelled develop renders nothing further. */
export function develop(
  render: (exposure: number) => void,
  options: { duration?: number; reduced?: boolean } = {},
): () => void {
  const duration = options.duration ?? DEVELOP_MS
  if (options.reduced) {
    render(1)
    return () => {}
  }
  let cancelled = false
  let frame = 0
  render(0)
  const start = performance.now()
  const step = (now: number) => {
    if (cancelled) return
    const t = Math.min(1, Math.max(0, (now - start) / duration))
    render(easeOutQuart(t))
    if (t < 1) frame = requestAnimationFrame(step)
  }
  frame = requestAnimationFrame(step)
  return () => {
    cancelled = true
    cancelAnimationFrame(frame)
  }
}

/* Luminance of an sRGB pixel turned into print coverage for the night field:
   bright cloud prints, the dark sky stays bare (the 0.12 floor drops the
   sky's noise). */
export function luminanceCoverage(r: number, g: number, b: number): number {
  return Math.max(0, (r * 0.3 + g * 0.59 + b * 0.11) / 255 - 0.12)
}

export function prefersReducedMotion(): boolean {
  return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches
}
