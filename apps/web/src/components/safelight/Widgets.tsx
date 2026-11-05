import * as React from 'react'
import { useThrobber } from './hooks'

/* the braille throbber · every span on the page shares one interval */
export function Throbber({ initial = '⠋' }: { initial?: string }) {
  const frame = useThrobber()
  return <span className="throbber">{frame ?? initial}</span>
}

/* a GenUI block the agent sends into the chat thread: a small object with
   the same widget grammar as the draft card in the inbox rows */
export function Cwidget({
  title,
  line,
  children,
}: {
  title: string
  line: string
  children: React.ReactNode
}) {
  return (
    <div className="cwidget">
      <span className="cw-title">{title}</span>
      <span className="cw-line">{line}</span>
      <span className="cw-foot">{children}</span>
    </div>
  )
}

/* the draft is a WIDGET in the mini-thread (owner 08-14 night): the name
   small inside, the editable text, send on the card's foot. */
export function DraftCard({
  agent,
  name,
  nameTitle,
  lang,
  rows,
  defaultValue,
  ariaLabel,
  sendTitle,
  onSend,
  envelope,
}: {
  agent: string
  name: string
  nameTitle: string
  lang?: string
  rows: number
  defaultValue: string
  ariaLabel: string
  sendTitle: string
  onSend: (e: React.MouseEvent) => void
  envelope?: string
}) {
  return (
    <div className="draft-card">
      <span className="cw-head">
        <span className="aname" data-agent={agent} title={nameTitle}>
          {name}
        </span>
        {envelope ? (
          <span className="meta-line" title="the envelope: who receives it · sent as which identity">
            {envelope}
          </span>
        ) : null}
      </span>
      <textarea
        className="draft-edit"
        lang={lang}
        rows={rows}
        aria-label={ariaLabel}
        defaultValue={defaultValue}
      />
      <div className="cw-foot">
        <a className="act" href="#" title={sendTitle} onClick={onSend}>
          send
        </a>
      </div>
    </div>
  )
}
