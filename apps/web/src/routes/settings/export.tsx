import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { Throbber } from '~/components/safelight/Widgets'
import { cue, markCued } from '~/components/safelight/hooks'
import { CLOCK, HASH_SHORT, PaneHead, Sheet, TODAY } from './-shared'

export const Route = createFileRoute('/settings/export')({
  component: ExportPage,
})

/* ── export with provenance: one row that settles; the past exports under it ── */
type Past = { when: string; file: string; tip: string }
const PAST: Past[] = [
  { when: '08-06 09:02', file: 'antevon-ops-20260806.tar.zst', tip: `antevon-ops-20260806.tar.zst · 798 MB · stamped ${HASH_SHORT}` },
]

function ExportPage() {
  const [exp, setExp] = React.useState<'idle' | 'sealing' | 'sealed'>('idle')
  const [past, setPast] = React.useState<Past[]>(PAST)
  const [landed, setLanded] = React.useState(false)
  const timer = React.useRef<ReturnType<typeof setTimeout> | null>(null)
  React.useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current)
    },
    [],
  )
  const file = `antevon-ops-${TODAY.replace(/-/g, '')}.tar.zst`
  const requestExport = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    setExp('sealing')
    cue('press')
    const wait = matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 1400
    timer.current = setTimeout(() => {
      setExp('sealed')
      setPast((p) => [{ when: `${TODAY.slice(5)} ${CLOCK}`, file, tip: `${file} · 812 MB · stamped ${HASH_SHORT}` }, ...p])
      setLanded(true)
      cue('success')
    }, wait)
  }

  return (
    <Sheet page="export">
      <PaneHead title="export" hint="Take the whole vault with you. Every claim leaves with its sources and receipts." />
      <div className="exp">
        {exp === 'idle' && (
          <>
            <a
              className="act"
              href="#"
              title="verb: request_export · worlds base, clients and internal, with every source and receipt"
              onClick={requestExport}
            >
              export with provenance
            </a>
            <span className="meta-line" title="the last export left on 08-06 09:02">
              base · clients · internal
            </span>
          </>
        )}
        {exp === 'sealing' && (
          <>
            <span className="settled">requested · {CLOCK}</span>
            <Throbber />
          </>
        )}
        {exp === 'sealed' && (
          <>
            <span className="settled">sealed · 12,408 claims · 812 MB</span>
            <a className="act" href="#" title={`${file} · 812 MB · stamped with the genesis seal`} onClick={(e) => e.preventDefault()}>
              download
            </a>
          </>
        )}
      </div>

      <div className="ledger-wrap">
        <table className="ledger x-ledger" aria-label="past exports">
          <thead>
            <tr>
              <th className="c-when">when</th>
              <th>file</th>
            </tr>
          </thead>
          <tbody>
            {past.map((p, i) => (
              <tr className={landed && i === 0 ? 'row landed' : 'row'} key={p.file}>
                <td>
                  <span className="clk">{p.when}</span>
                </td>
                <td>
                  <a className="file" href="#" title={p.tip} onClick={(e) => e.preventDefault()}>
                    {p.file}
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Sheet>
  )
}
