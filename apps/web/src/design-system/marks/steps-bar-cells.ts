/* The steps bar's geometry as data: a run's own plan, never a percentage.
   Pure, so it is tested without a DOM. */

export type StepState = 'done' | 'working' | 'ahead' | 'failed'

export interface Step {
  state: StepState
  /* How far a working step is, 0 to 1, from its own sub-steps. */
  progress?: number
}

export interface StepsBarCell {
  state: StepState
  /* Share of the cell filled with solid ink, 0 to 1, from the left. */
  solid: number
  /* Share of the cell screened with the half-tone, 0 to 1, from the left. */
  halftone: number
}

export interface StepsBarLayout {
  /* `per-step`: one cell per step. `fixed`: twelve cells filled by
     done over total. */
  layout: 'per-step' | 'fixed'
  cells: StepsBarCell[]
}

/* A flat plan longer than this falls back to fixed cells. */
export const STEPS_BAR_MAX_SEGMENTS = 8
export const STEPS_BAR_FIXED_CELLS = 12

const unit = (value: number | undefined) => {
  const v = value ?? 0
  return Number.isFinite(v) ? Math.min(1, Math.max(0, v)) : 0
}

/* Per step: done is solid; working is half-tone with its progress laid in
   solid over it; ahead is empty track; failed is empty track that the bar
   outlines with a dashed line. Past eight steps: twelve cells, the first
   floor(done / total * 12) solid, and the next cell screened part-way by
   the working step's progress, or marked failed when a step failed and
   none is working. */
export function stepsBarCells(steps: readonly Step[]): StepsBarLayout {
  if (steps.length <= STEPS_BAR_MAX_SEGMENTS) {
    return {
      layout: 'per-step',
      cells: steps.map((step) =>
        step.state === 'done'
          ? { state: 'done', solid: 1, halftone: 0 }
          : step.state === 'working'
            ? { state: 'working', solid: unit(step.progress), halftone: 1 }
            : { state: step.state === 'failed' ? 'failed' : 'ahead', solid: 0, halftone: 0 },
      ),
    }
  }

  const done = steps.filter((s) => s.state === 'done').length
  const full = Math.floor((done / steps.length) * STEPS_BAR_FIXED_CELLS)
  const working = steps.find((s) => s.state === 'working')
  const part = working ? unit(working.progress) : 0
  const failed = !working && steps.some((s) => s.state === 'failed')
  const cells: StepsBarCell[] = []
  for (let c = 0; c < STEPS_BAR_FIXED_CELLS; c++) {
    if (c < full) cells.push({ state: 'done', solid: 1, halftone: 0 })
    else if (c === full && part > 0) cells.push({ state: 'working', solid: 0, halftone: part })
    else if (c === full && failed) cells.push({ state: 'failed', solid: 0, halftone: 0 })
    else cells.push({ state: 'ahead', solid: 0, halftone: 0 })
  }
  return { layout: 'fixed', cells }
}

/* The sentence a screen reader hears for a bar. */
export function stepsBarLabel(steps: readonly Step[]): string {
  const done = steps.filter((s) => s.state === 'done').length
  const base = `${done} of ${steps.length} steps done`
  const i = steps.findIndex((s) => s.state === 'working')
  if (i >= 0) return `${base}, step ${i + 1} of ${steps.length} working`
  const f = steps.findIndex((s) => s.state === 'failed')
  return f >= 0 ? `${base}, step ${f + 1} of ${steps.length} failed` : base
}
