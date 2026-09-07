import * as React from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { cue, markCued } from '~/components/safelight/hooks'
import { GenesisSeal, HASH_FULL, HASH_GROUPS, HASH_SHORT, PaneHead, Sec, Sheet, useEscLayer } from './-shared'

export const Route = createFileRoute('/settings/vault')({
  component: VaultPage,
})

/* ── vault: this vault's identity, and the policy it lives under. the
   genesis seal is THE one resting red of the whole area. ── */
const POLICY: [string, string][] = [
  ['retention', 'nothing pretends to forget; forget is explicit'],
  ['worlds', 'base · clients · internal'],
  ['agents never', 'send without your click · write a claim without review'],
]

function VaultPage() {
  /* the vault fingerprint: copy settles to "copied" */
  const [copied, setCopied] = React.useState(false)
  const copyHash = (e: React.MouseEvent) => {
    e.preventDefault()
    markCued(e)
    try {
      void navigator.clipboard?.writeText(HASH_FULL)
    } catch {
      /* no clipboard · the hash is on the screen */
    }
    setCopied(true)
    cue('success')
  }

  /* policy: read it unfolds three kv lines under the row */
  const [policyOpen, setPolicyOpen] = React.useState(false)
  useEscLayer(policyOpen, () => setPolicyOpen(false))

  return (
    <Sheet page="vault">
      <PaneHead title="vault" hint="This vault's identity, and the policy it lives under." />

      <Sec label="vault fingerprint" title="Vault">
        <div className="fp">
          <GenesisSeal />
          <span className="gh" title={`genesis hash · sha256 of the first block · ${HASH_GROUPS.join(' ')}`}>
            {HASH_SHORT}
          </span>
          <span className="acts">
            {copied ? (
              <span className="settled">copied</span>
            ) : (
              <a className="act" href="#" title="verb: copy_genesis_hash · the full hash goes to the clipboard" onClick={copyHash}>
                copy
              </a>
            )}
          </span>
        </div>
        <div className="fp-path">
          <span className="meta-line" title="one file, yours · minted 2026-03-02 09:14">
            ~/vaults/antevon-ops.oneiron
          </span>
        </div>
        <div className="crea">
          <span
            className="face vault"
            data-agent="antevon"
            role="img"
            aria-label="the antevon moth"
            title="the moth · the face this vault wears wherever it appears"
            style={{ width: 40, height: 40 }}
          />
          <span className="c-col">
            <span className="nm">antevon · ops</span>
            <span className="sub">the mascot is the address</span>
          </span>
        </div>
        <div className="srow worlds">
          <span className="key">worlds</span>
          <span className="meta-line" title="three worlds · a member's reach is a set of them">
            base · clients · internal
          </span>
        </div>
      </Sec>

      <Sec label="policy" title="Policy">
        <div className="srow policy">
          <span className="key">policy</span>
          <span className="acts tail">
            <button
              className="act"
              aria-expanded={policyOpen}
              aria-controls="policy-fold"
              title="verb: open_policy · the policy, as the engine reads it"
              onClick={(e) => {
                markCued(e)
                setPolicyOpen((o) => !o)
                cue('toggle')
              }}
            >
              {policyOpen ? 'fold it' : 'read it'}
            </button>
          </span>
        </div>
        <div className={policyOpen ? 'fold on' : 'fold'} id="policy-fold" aria-hidden={!policyOpen}>
          <div className="fold-in">
            <div className="fold-body kvs">
              {POLICY.map(([k, v]) => (
                <div className="kv" key={k}>
                  <span className="k">{k}</span>
                  <span className="v">{v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Sec>
    </Sheet>
  )
}
