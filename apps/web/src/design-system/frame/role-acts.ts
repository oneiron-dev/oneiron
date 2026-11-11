/* The acts a role checks in about, as data. Pure, so it is tested without
   a DOM. */

/* How a role checks in before an act: always ask, ask when unsure, just go. */
export type ActMode = 'always-ask' | 'ask-when-unsure' | 'just-go'

export interface RoleAct {
  name: string
  mode: ActMode
}

export const ACT_MODES: ReadonlyArray<{ value: ActMode; label: string }> = [
  { value: 'always-ask', label: 'always ask' },
  { value: 'ask-when-unsure', label: 'ask when unsure' },
  { value: 'just-go', label: 'just go' },
]

/* The acts with one act's mode changed. Pure. */
export function setActMode(acts: readonly RoleAct[], name: string, mode: ActMode): RoleAct[] {
  return acts.map((act) => (act.name === name ? { ...act, mode } : act))
}
