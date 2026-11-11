/* The soft magnet of a split edge. Within `pullPx` of a magnet the edge
   eases toward it: the pull grows with the square of closeness and is
   continuous at the edge of the radius, so the edge never jumps. */

export const SPLIT_MAGNETS: readonly number[] = [0.25, 0.5, 0.75]
export const SPLIT_MAGNET_PULL_PX = 30
/* Share of the remaining distance covered when the edge sits on a magnet. */
const PULL_STRENGTH = 0.72

export interface MagnetSnap {
  /* The eased position, a fraction of the width. */
  fraction: number
  /* The magnet in reach, or null. */
  magnet: number | null
}

export function snapToMagnet(
  fraction: number,
  widthPx: number,
  magnets: readonly number[] = SPLIT_MAGNETS,
  pullPx: number = SPLIT_MAGNET_PULL_PX,
): MagnetSnap {
  if (!(widthPx > 0) || !(pullPx > 0)) return { fraction, magnet: null }
  const raw = fraction * widthPx
  let out = raw
  let magnet: number | null = null
  let nearest = Infinity
  for (const m of magnets) {
    const stop = m * widthPx
    const d = Math.abs(raw - stop)
    if (d < pullPx && d < nearest) {
      nearest = d
      const k = Math.pow(1 - d / pullPx, 2) * PULL_STRENGTH
      out = raw + (stop - raw) * k
      magnet = m
    }
  }
  return { fraction: out / widthPx, magnet }
}
