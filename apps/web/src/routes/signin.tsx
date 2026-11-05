import * as React from 'react'
import { Link, createFileRoute, useNavigate } from '@tanstack/react-router'
import { LogoMark } from '~/components/safelight/icons'
import { Throbber } from '~/components/safelight/Widgets'
import { cue, useEscape } from '~/components/safelight/hooks'
import signinCss from '~/styles/signin.css?url'

export const Route = createFileRoute('/signin')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: signinCss }],
  }),
  component: SignIn,
})

/* ── the gate (outside the chassis) ──
   one field, one verb; the plate does the talking. Phases:
     ask      · the field is live, [continue] waits for an address
     mailed   · the verb settled; a receipt lands under the field
     passkey  · this device is asked for its key (throbber), then the door
     opened   · the key was accepted; the vault opens                       ── */
type Phase = 'ask' | 'mailed' | 'passkey' | 'opened'
const PASSKEY_MS = 900
const OPEN_MS = 520
const looksLikeMail = (s: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s.trim())

function SignIn() {
  const navigate = useNavigate()
  const [phase, setPhase] = React.useState<Phase>('ask')
  const [mail, setMail] = React.useState('')
  const timers = React.useRef<ReturnType<typeof setTimeout>[]>([])
  const later = (fn: () => void, ms: number) => {
    timers.current.push(setTimeout(fn, ms))
  }
  React.useEffect(() => () => timers.current.forEach(clearTimeout), [])

  /* the room lives on the settings page; this page only has to read in
     both, which the tokens do. No local theme key here. */

  /* esc reopens the field after a settle, and the cursor goes back in */
  const field = React.useRef<HTMLInputElement>(null)
  useEscape(() => {
    if (phase !== 'mailed') return
    setPhase('ask')
    later(() => field.current?.focus(), 0)
  })

  const ready = looksLikeMail(mail)

  const send = (e: React.FormEvent) => {
    e.preventDefault()
    if (!ready || phase !== 'ask') return
    cue('press')
    setPhase('mailed')
    later(() => cue('success'), 160)
  }

  const passkey = () => {
    if (phase === 'passkey' || phase === 'opened') return
    cue('press')
    setPhase('passkey')
    later(() => {
      setPhase('opened')
      cue('success')
      later(() => navigate({ to: '/app/inbox' }), OPEN_MS)
    }, PASSKEY_MS)
  }

  const busy = phase === 'passkey' || phase === 'opened'
  const fieldOff = phase !== 'ask'

  return (
    <>
      <div className="grain" aria-hidden="true"></div>
      <div className="gate">
        <main className="gate-card" aria-label="sign in">
          <Link to="/" className="gate-brand" title="oneiron">
            <LogoMark />
            <span className="word">oneiron</span>
          </Link>

          <span className="label">sign in</span>
          <p className="gate-line">Your vault, your file. Sign in to open it.</p>

          <form className="gate-form" onSubmit={send}>
            <div className="gate-row">
              <input
                ref={field}
                className="gate-field"
                type="email"
                inputMode="email"
                autoComplete="email"
                spellCheck={false}
                placeholder="you@example.com"
                aria-label="email"
                value={mail}
                onChange={(e) => setMail(e.target.value)}
                disabled={fieldOff}
                autoFocus
              />
              {phase === 'ask' && (
                <button
                  className="act lead"
                  type="submit"
                  disabled={!ready}
                  title="verb: sign_in · a link goes to this address"
                >
                  continue
                </button>
              )}
            </div>
            {/* one standing live region: a span that appears inside an
                already-mounted region is what screen readers announce */}
            <div className="gate-out" aria-live="polite">
              {phase === 'mailed' && (
                <span className="gate-receipt" title="esc · another address">
                  Check your mail. A link is on its way.
                </span>
              )}
              {phase === 'passkey' && (
                <span className="gate-receipt">
                  <Throbber />
                  <span>Asking this device for its key.</span>
                </span>
              )}
              {phase === 'opened' && (
                <span className="gate-receipt">Key accepted. Opening the vault.</span>
              )}
            </div>
          </form>

          <div className="gate-alt">
            <button
              type="button"
              className="act"
              onClick={passkey}
              disabled={busy}
              title="verb: sign_in · this device's key, no mail"
            >
              passkey
            </button>
            <span className="sep" aria-hidden="true">
              ·
            </span>
            <Link to="/mint" className="act" title="mint a vault · one file, yours">
              mint a new vault
            </Link>
          </div>

          <span className="gate-foot">Nothing leaves your machine without a receipt.</span>
        </main>
      </div>
    </>
  )
}
