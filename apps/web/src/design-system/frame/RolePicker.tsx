import * as React from 'react'
import { PickDiamond } from '../marks/PickDiamond'
import { SETTLE_OPEN, settleReducer, type SettleState } from '../patterns/settle-reducer'
import { NEEDS_YOU_UNDO_MS } from '../patterns/NeedsYou'
import { Unfold } from '../primitives/Unfold'
import { Verb } from '../primitives/Verb'
import { pushPendingUndo } from '../lib/pending-undo'
import { soundPress } from '../lib/press'
import { cx, useControllableState } from '../lib/react-utils'
import { ACT_MODES, setActMode, type RoleAct } from './role-acts'

export interface RoleOption {
  id: string
  name: string
  /* What the role does, in one line. */
  job: string
  /* A quieter note: `usually an agent`. */
  hint?: string
}

export interface RolePickerProps extends Omit<React.ComponentPropsWithRef<'div'>, 'defaultValue' | 'onChange'> {
  roles: RoleOption[]
  /* The chosen role's id. */
  value?: string
  defaultValue?: string
  onValueChange?: (id: string) => void
  /* What the chosen role asks first: one mode per act. */
  acts?: RoleAct[]
  defaultActs?: RoleAct[]
  onActsChange?: (acts: RoleAct[]) => void
  /* Off: the picks and modes show, read-only. */
  canChange?: boolean
  undoWindowMs?: number
}

/* The roles as diamond picks, each with its one-line job and a quieter
   hint. A pick applies at once and shows `undo` for the same window as an
   answer (Escape undoes too). Under the picks, an unfold lists the acts the
   role asks about first, each with its mode as three picks. */
export function RolePicker({
  roles,
  value: valueProp,
  defaultValue,
  onValueChange,
  acts: actsProp,
  defaultActs,
  onActsChange,
  canChange = true,
  undoWindowMs = NEEDS_YOU_UNDO_MS,
  className,
  ...props
}: RolePickerProps) {
  const [value, setValue] = useControllableState(valueProp, defaultValue ?? roles[0]?.id ?? '', onValueChange)
  const [acts, setActs] = useControllableState<RoleAct[]>(actsProp, defaultActs ?? [], onActsChange)
  const [settle, setSettle] = React.useState<SettleState>(SETTLE_OPEN)
  /* The role before the newest pick: where `undo` goes back to. */
  const undoTo = React.useRef<string | null>(null)

  const choose = (id: string) => {
    if (!canChange || id === value) return
    undoTo.current = value
    setValue(id)
    /* A second pick inside the window starts a fresh window. */
    setSettle((s) => settleReducer(s.status === 'pending' ? SETTLE_OPEN : s, { type: 'pick', value: id }))
  }

  const undo = React.useCallback(() => {
    setSettle((s) => settleReducer(s, { type: 'undo' }))
    if (undoTo.current !== null) setValue(undoTo.current)
    undoTo.current = null
  }, [setValue])

  React.useEffect(() => {
    if (settle.status !== 'pending') return
    const release = pushPendingUndo(undo)
    const timer = setTimeout(() => setSettle((s) => settleReducer(s, { type: 'commit' })), undoWindowMs)
    return () => {
      clearTimeout(timer)
      release()
    }
  }, [settle, undo, undoWindowMs])

  /* Once the window ends the pick stands and the picker is open again. */
  React.useEffect(() => {
    if (settle.status !== 'settled') return
    undoTo.current = null
    setSettle(SETTLE_OPEN)
  }, [settle])

  const chosen = roles.find((r) => r.id === value)

  return (
    <div className={cx('sl-role-picker', className)} data-can-change={canChange ? '' : undefined} {...props}>
      <div role="group" aria-label="role" className="sl-role-picks">
        {roles.map((role) => {
          const on = role.id === value
          return (
            <button
              key={role.id}
              type="button"
              className="sl-role-pick"
              aria-pressed={on}
              disabled={!canChange}
              data-role={role.id}
              onClick={(event) => {
                if (on) return
                soundPress(event)
                choose(role.id)
              }}
            >
              <PickDiamond />
              <span className="sl-role-pick-name">{role.name}</span>
              <span className="sl-role-pick-job">{role.job}</span>
              {role.hint ? <span className="sl-role-pick-hint">{role.hint}</span> : null}
            </button>
          )
        })}
      </div>
      {settle.status === 'pending' ? (
        <p className="sl-role-receipt" role="status">
          now {chosen?.name}
          <span aria-hidden="true"> · </span>
          <Verb onClick={undo}>undo</Verb>
        </p>
      ) : null}
      {acts.length ? (
        <Unfold className="sl-role-acts">
          <Unfold.Trigger asChild>
            <Verb className="sl-role-acts-trigger">what this role asks first</Verb>
          </Unfold.Trigger>
          <Unfold.Content>
            <ul className="sl-role-act-list">
              {acts.map((act) => (
                <li key={act.name} className="sl-role-act">
                  <span className="sl-role-act-name">{act.name}</span>
                  <span role="group" aria-label={act.name} className="sl-role-act-modes">
                    {ACT_MODES.map((mode) => (
                      <button
                        key={mode.value}
                        type="button"
                        className="sl-role-act-mode"
                        aria-pressed={act.mode === mode.value}
                        disabled={!canChange}
                        onClick={(event) => {
                          if (act.mode === mode.value) return
                          soundPress(event)
                          setActs(setActMode(acts, act.name, mode.value))
                        }}
                      >
                        <PickDiamond />
                        {mode.label}
                      </button>
                    ))}
                  </span>
                </li>
              ))}
            </ul>
          </Unfold.Content>
        </Unfold>
      ) : null}
    </div>
  )
}
