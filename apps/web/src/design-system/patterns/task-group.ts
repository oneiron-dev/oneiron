import type { DonutArc } from '../marks/donut-segments'

/* Which of the three heads a task sits under in a grouped task list, as
   data. Pure, so it is tested without a DOM. */

export type TaskGroup = 'needs-you' | 'working' | 'done'

/* The heads in the order they show, with their words. */
export const TASK_GROUPS: ReadonlyArray<{ group: TaskGroup; head: string }> = [
  { group: 'needs-you', head: 'needs you' },
  { group: 'working', head: 'working' },
  { group: 'done', head: 'done' },
]

/* The done group folds to its count when it holds more than this. */
export const TASK_DONE_FOLD_AFTER = 3

/* Waiting on the person comes first; a task whose every step is done is
   done; anything else (working, ahead, failed) is still working. */
export function taskGroup(arcs: readonly DonutArc[], needsYou: boolean): TaskGroup {
  if (needsYou) return 'needs-you'
  if (arcs.length > 0 && arcs.every((a) => a === 'done')) return 'done'
  return 'working'
}

/* Splits tasks into the three groups, keeping their order inside each. */
export function groupTasks<T extends { id: string; arcs: readonly DonutArc[]; needsYou?: boolean }>(
  tasks: readonly T[],
): Record<TaskGroup, T[]> {
  const out: Record<TaskGroup, T[]> = { 'needs-you': [], working: [], done: [] }
  for (const task of tasks) out[taskGroup(task.arcs, !!task.needsYou)].push(task)
  return out
}

/* A count of tasks said in words: `1 task`, `3 tasks`. */
export function taskCountWords(count: number): string {
  return `${count} ${count === 1 ? 'task' : 'tasks'}`
}
