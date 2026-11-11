/* The progress donut as data: one arc per task (or per step of one task),
   read clockwise from twelve o'clock with a small gap between arcs, and
   what sits in the middle. Pure, so it is tested without a DOM. */

export type DonutArc = 'done' | 'working' | 'ahead' | 'failed'
export type DonutSize = 14 | 18

/* Past this many arcs the gaps would eat the ring: the donut draws one
   smooth arc of the done share over the empty ring instead. */
export const DONUT_MAX_ARCS = 12

export interface DonutSegment {
  /* What the arc shows: an entry's state, or `track` for the empty ring
     under a smooth arc. */
  state: DonutArc | 'track'
  /* Degrees clockwise from twelve o'clock. */
  start: number
  end: number
  /* SVG path data for the arc in a size x size box. */
  d: string
}

export interface DonutGeometry {
  size: DonutSize
  /* `arcs`: one arc per entry. `smooth`: the done share as one arc.
     `empty`: no entries, the empty ring alone. */
  layout: 'arcs' | 'smooth' | 'empty'
  radius: number
  stroke: number
  segments: DonutSegment[]
  /* The middle: the waiting dot's radius, the check's path and stroke. */
  dot: number
  check: string
  checkStroke: number
}

interface DonutScale {
  radius: number
  stroke: number
  /* The gap between two arcs, measured along the ring in CSS pixels. */
  gap: number
  dot: number
  check: string
  checkStroke: number
}

const SCALE: Record<DonutSize, DonutScale> = {
  18: { radius: 6, stroke: 2.5, gap: 1.6, dot: 2.4, check: 'M6.8 9.2 8.4 10.8 11.3 7.6', checkStroke: 1.4 },
  14: { radius: 4.75, stroke: 2, gap: 1.3, dot: 1.9, check: 'M5.3 7.15 6.55 8.4 8.8 5.9', checkStroke: 1.2 },
}

const round = (n: number) => Math.round(n * 100) / 100

/* A point on the ring at `angle` degrees clockwise from twelve o'clock. */
function point(centre: number, radius: number, angle: number): [number, number] {
  const a = (angle * Math.PI) / 180
  return [round(centre + radius * Math.sin(a)), round(centre - radius * Math.cos(a))]
}

/* Path data for a clockwise arc. A whole turn is drawn as two halves: one
   arc command cannot start and end on the same point. */
export function arcPath(centre: number, radius: number, start: number, end: number): string {
  const sweep = end - start
  const r = round(radius)
  if (sweep >= 360 - 1e-6) {
    const [x0, y0] = point(centre, radius, start)
    const [x1, y1] = point(centre, radius, start + 180)
    return `M${x0} ${y0}A${r} ${r} 0 1 1 ${x1} ${y1}A${r} ${r} 0 1 1 ${x0} ${y0}`
  }
  const [x0, y0] = point(centre, radius, start)
  const [x1, y1] = point(centre, radius, end)
  return `M${x0} ${y0}A${r} ${r} 0 ${sweep > 180 ? 1 : 0} 1 ${x1} ${y1}`
}

/* The arcs of a donut `size` pixels square for these entries. */
export function donutSegments(arcs: readonly DonutArc[], size: DonutSize = 18): DonutGeometry {
  const scale = SCALE[size]
  const centre = size / 2
  const { radius } = scale
  const base = { size, radius, stroke: scale.stroke, dot: scale.dot, check: scale.check, checkStroke: scale.checkStroke }
  const segment = (state: DonutSegment['state'], start: number, end: number): DonutSegment => ({
    state,
    start: round(start),
    end: round(end),
    d: arcPath(centre, radius, start, end),
  })

  const n = arcs.length
  if (n === 0) return { ...base, layout: 'empty', segments: [segment('track', 0, 360)] }

  if (n > DONUT_MAX_ARCS) {
    const share = arcs.filter((a) => a === 'done').length / n
    const segments: DonutSegment[] = []
    if (share < 1) segments.push(segment('track', 0, 360))
    if (share > 0) segments.push(segment('done', 0, share * 360))
    return { ...base, layout: 'smooth', segments }
  }

  if (n === 1) return { ...base, layout: 'arcs', segments: [segment(arcs[0], 0, 360)] }

  const span = 360 / n
  const gap = (scale.gap / (2 * Math.PI * radius)) * 360
  return {
    ...base,
    layout: 'arcs',
    segments: arcs.map((state, i) => segment(state, i * span + gap / 2, (i + 1) * span - gap / 2)),
  }
}

/* What sits in the middle: a dot while something waits on the person, a
   check once every entry is done and nothing waits; never both. */
export function donutCentre(arcs: readonly DonutArc[], needsYou: boolean): 'dot' | 'check' | 'none' {
  if (needsYou) return 'dot'
  if (arcs.length > 0 && arcs.every((a) => a === 'done')) return 'check'
  return 'none'
}

/* The donut in words, for its tooltip and accessible name:
   `1 of 3 done, waits on you`. */
export function donutLabel(arcs: readonly DonutArc[], needsYou: boolean): string {
  const waits = needsYou ? ', waits on you' : ''
  if (arcs.length === 0) return `nothing yet${waits}`
  const done = arcs.filter((a) => a === 'done').length
  const failed = arcs.filter((a) => a === 'failed').length
  return `${done} of ${arcs.length} done${failed ? `, ${failed} failed` : ''}${waits}`
}
