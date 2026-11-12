import * as React from 'react'
import { Figure } from '../primitives/Figure'
import { Icon } from '../primitives/Icon'
import { Unfold } from '../primitives/Unfold'
import { Verb } from '../primitives/Verb'
import { cx } from '../lib/react-utils'
import { formatElapsed } from './run-elapsed'

/* What the process is doing, as a real state, never a spinner label. */
export type RunSubState = 'thinking' | 'calling a tool' | 'writing' | 'waiting on you'

interface RunFootBase extends Omit<React.ComponentPropsWithRef<'div'>, 'onChange'> {
  /* The resident at work: a Glyph. */
  who?: React.ReactNode
}

export type RunFootProps = RunFootBase &
  (
    | {
        status: 'working'
        subState: RunSubState
        /* Seconds since the run started, from the run itself; the component keeps no clock. */
        elapsed: number
        toolCalls: number
        onInterrupt?: () => void
        summary?: React.ReactNode
      }
    | {
        status: 'done'
        /* The receipt, one small line: `thought for 54s, 3 tool calls`. */
        summary: React.ReactNode
        subState?: RunSubState
        elapsed?: number
        toolCalls?: number
        onInterrupt?: never
      }
  )

/* The foot of a running thread. While the run works: the sub-state as a
   word, elapsed and the tool-call count as figures, and `interrupt`. When
   it ends, the working line folds once into a receipt that unfolds the
   calls (the children). */
function RunFootRoot({
  status,
  who,
  subState,
  elapsed = 0,
  toolCalls = 0,
  onInterrupt,
  summary,
  className,
  children,
  ...props
}: RunFootProps) {
  /* The fold plays only when the status changes while mounted. */
  const first = React.useRef(status)
  const animate = first.current !== status
  const working = status === 'working'
  return (
    <div className={cx('sl-run-foot', className)} data-status={status} data-animate={animate ? '' : undefined} {...props}>
      <div className="sl-run-foot-slot" data-slot="working" inert={!working} aria-hidden={!working}>
        <div className="sl-run-foot-slot-inner">
          <div className="sl-run-working">
            {who}
            <span className="sl-run-substate">{subState}</span>
            <Figure className="sl-run-elapsed">{formatElapsed(elapsed)}</Figure>
            <span className="sl-run-calls" aria-label={`${toolCalls} tool ${toolCalls === 1 ? 'call' : 'calls'}`}>
              <Icon name="tool" size={13} />
              <Figure aria-hidden="true">{toolCalls}</Figure>
            </span>
            {onInterrupt ? (
              <Verb tone="consent" className="sl-run-interrupt" onClick={onInterrupt}>
                interrupt
              </Verb>
            ) : null}
          </div>
        </div>
      </div>
      <div className="sl-run-foot-slot" data-slot="done" inert={working} aria-hidden={working}>
        <div className="sl-run-foot-slot-inner">
          <Unfold className="sl-run-receipt">
            <Unfold.Trigger className="sl-fold-line sl-run-receipt-line">
              <Icon name="chevron" size={12} className="sl-fold-chevron" />
              <span>{summary}</span>
            </Unfold.Trigger>
            <Unfold.Content>
              <div className="sl-run-calls-list">{children}</div>
            </Unfold.Content>
          </Unfold>
        </div>
      </div>
    </div>
  )
}

export interface RunFootCallProps extends React.ComponentPropsWithRef<'div'> {
  /* The tool's name, an id. */
  name: string
  /* Who made the call. */
  by?: React.ReactNode
  /* Seconds the call took. */
  duration?: number
}

/* One tool call in the receipt: a check, the tool, who, how long. */
function RunFootCall({ name, by, duration, className, ...props }: RunFootCallProps) {
  return (
    <div className={cx('sl-run-call', className)} {...props}>
      <Icon name="check" size={13} className="sl-run-call-mark" />
      <span className="sl-run-call-name">{name}</span>
      <span className="sl-run-call-by">{by}</span>
      {duration !== undefined ? <Figure className="sl-run-call-duration">{formatElapsed(duration)}</Figure> : <span />}
    </div>
  )
}

/* Compound parts: RunFoot, RunFoot.Call. */
export const RunFoot = Object.assign(RunFootRoot, { Call: RunFootCall })
