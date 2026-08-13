import { createFileRoute } from '@tanstack/react-router'
import vaultCss from '~/styles/vault.css?url'

export const Route = createFileRoute('/app/vault')({
  head: () => ({
    links: [{ rel: 'stylesheet', href: vaultCss }],
  }),
  component: Vault,
})

/* ══ pane · ONE sheet: the lens body + the inspector column ══
   Two-tier law: everything OUTSIDE the .instrument region is CHROME
   (hand-built shell). The .instrument region is an agent-rendered lens and
   carries its provenance eyebrow. */
function Vault() {
  return (
    <main className="pane">
      <div className="pane-body">
        <div className="pane-head">
          <h1>Vault</h1>
          <span className="meta-line" title="claims alive · last write 14:07">
            12,408 claims · 214 entities · last write 14:07
          </span>
        </div>

        {/* chrome: world scope + state filters (OF-293 / OF-111) */}
        <div className="filters">
          <span className="set" role="group" aria-label="worlds">
            <span className="label" style={{ marginRight: 6 }}>
              worlds
            </span>
            <button className="chip on" title="base reality · always on">
              base
            </button>
            <button className="chip on" title="world: work · in the allowed-set">
              work
            </button>
            <button className="chip" title="world: health · in the allowed-set, off this view">
              health
            </button>
            <button className="chip" title="world: fiction · archived 2026-05-12">
              fiction
            </button>
          </span>
          <span className="set" role="group" aria-label="state">
            <span className="label" style={{ marginRight: 6 }}>
              show
            </span>
            <button className="chip on">active</button>
            <button className="chip on">superseded</button>
            <button className="chip">retracted</button>
          </span>
        </div>

        {/* chrome: the as-of scrubber — what did the vault believe then (OF-082) */}
        <div className="asof" title="drag to reconstruct the vault as of a past date">
          <span className="label">as of</span>
          <span className="track">
            <span className="handle"></span>
          </span>
          <span className="date">today · 2026-07-07</span>
        </div>

        {/* ══ INSTRUMENT · vault lens (agent-rendered, closed atoms) ══ */}
        <section className="instrument" aria-label="vault lens">
          <div
            className="instrument-eyebrow"
            title="agent-rendered lens · closed atom kit v0.4 · regenerated 2026-07-05 · behavior-diff passed"
          >
            <span>vault lens · instrument</span>
          </div>

          <div className="ledger-wrap">
            <table className="ledger">
              <thead>
                <tr>
                  <th>claim</th>
                  <th className="c-pred">predicate</th>
                  <th className="c-occ">occurred</th>
                  <th className="c-lrn">learned</th>
                  <th className="c-actor">by</th>
                  <th className="c-dot"></th>
                </tr>
              </thead>
              <tbody>
                <tr className="selected">
                  <td>
                    <span className="claim conf-1" title="confidence 0.97">
                      Sasha moved from Berlin to Lisbon
                    </span>
                  </td>
                  <td>
                    <a className="pred" href="#" title="predicate person.location · registry">
                      person.location
                    </a>
                  </td>
                  <td>
                    <span className="clk">2026-05-30</span>
                  </td>
                  <td>
                    <span className="clk hollow">2026-06-24</span>
                  </td>
                  <td className="c-actor">
                    <span className="seal seal-human" title="o · oleksii · owner">
                      o
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className="dot dot-approved" title="approved"></span>
                  </td>
                </tr>
                <tr>
                  <td>
                    <span className="claim conf-1" title="confidence 0.94">
                      Yurii prefers async reviews over live calls
                    </span>
                  </td>
                  <td>
                    <a className="pred" href="#" title="predicate person.preference · registry">
                      person.preference
                    </a>
                  </td>
                  <td>
                    <span className="clk">2026-06-18</span>
                  </td>
                  <td>
                    <span className="clk hollow">2026-06-18</span>
                  </td>
                  <td className="c-actor">
                    <span className="seal seal-agent" title="e · eiri · agent · via kimi-k2.6">
                      e
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className="dot dot-auto" title="auto · trusted, unreviewed"></span>
                  </td>
                </tr>
                <tr>
                  <td>
                    <span className="claim conf-2" title="confidence 0.88">
                      Antevon pilot decision expected by July 18
                    </span>
                  </td>
                  <td>
                    <a className="pred" href="#" title="predicate commitment.deadline · registry">
                      commitment.deadline
                    </a>
                  </td>
                  <td>
                    <span className="clk">2026-07-02</span>
                  </td>
                  <td>
                    <span className="clk hollow">2026-07-03</span>
                  </td>
                  <td className="c-actor">
                    <span className="seal seal-agent" title="e · eiri · agent · via kimi-k2.6">
                      e
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className="dot dot-auto" title="auto · trusted, unreviewed"></span>
                  </td>
                </tr>
                <tr>
                  <td>
                    <span className="claim conf-2" title="confidence 0.79">
                      Prefers briefing digests merged, not one ping per item
                    </span>
                  </td>
                  <td>
                    <a className="pred" href="#" title="predicate person.preference · registry">
                      person.preference
                    </a>
                  </td>
                  <td>
                    <span className="clk">2026-06-29</span>
                  </td>
                  <td>
                    <span className="clk hollow">2026-06-29</span>
                  </td>
                  <td className="c-actor">
                    <span className="seal seal-agent" title="cc · claude code · agent · mcp">
                      cc
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className="dot dot-approved" title="approved"></span>
                  </td>
                </tr>
                <tr>
                  <td>
                    <span
                      className="claim conf-3"
                      title="confidence 0.52 · predicate class: critical · never renders below muted ink"
                    >
                      May be allergic to shellfish
                    </span>
                    <span
                      className="unverified"
                      title="low-confidence critical claim · explicit mark instead of vanishing ink"
                    >
                      unverified
                    </span>
                  </td>
                  <td>
                    <a
                      className="pred"
                      href="#"
                      title="predicate health.allergy · registry · class: critical"
                    >
                      health.allergy
                    </a>
                  </td>
                  <td>
                    <span className="clk">2026-04-11</span>
                  </td>
                  <td>
                    <span className="clk hollow">2026-04-11</span>
                  </td>
                  <td className="c-actor">
                    <span className="seal seal-agent" title="e · eiri · agent · via kimi-k2.6">
                      e
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className="dot dot-proposed" title="proposed · awaiting review"></span>
                  </td>
                </tr>
                <tr className="superseded">
                  <td>
                    <span className="claim conf-2">Office lease renews in March</span>
                    <a className="succ" href="#" title="superseded 2026-06-30">
                      → successor
                    </a>
                  </td>
                  <td>
                    <a className="pred" href="#" title="predicate org.lease · registry">
                      org.lease
                    </a>
                  </td>
                  <td>
                    <span className="clk">2025-03-14</span>
                  </td>
                  <td>
                    <span className="clk hollow">2025-03-14</span>
                  </td>
                  <td className="c-actor">
                    <span className="seal seal-human" title="o · oleksii · owner">
                      o
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className="dot dot-approved" title="approved · superseded"></span>
                  </td>
                </tr>
                <tr>
                  <td>
                    <span
                      className="claim conf-3 retracted"
                      title="retracted 2026-06-02 · confidence at retraction 0.44"
                    >
                      Flight back on the 12th
                    </span>
                  </td>
                  <td>
                    <a className="pred" href="#" title="predicate travel.flight · registry">
                      travel.flight
                    </a>
                  </td>
                  <td>
                    <span className="clk">2026-06-12</span>
                  </td>
                  <td>
                    <span className="clk hollow">2026-05-28</span>
                  </td>
                  <td className="c-actor">
                    <span
                      className="seal seal-system"
                      title="sys · importer · system · calendar connector"
                    >
                      s
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className="dot dot-rejected" title="rejected"></span>
                  </td>
                </tr>
                <tr>
                  <td>
                    <span className="claim conf-1" title="confidence 0.92">
                      Runs the weather book on Polymarket with a hard daily loss cap
                    </span>
                  </td>
                  <td>
                    <a className="pred" href="#" title="predicate project.constraint · registry">
                      project.constraint
                    </a>
                  </td>
                  <td>
                    <span className="clk">2026-06-05</span>
                  </td>
                  <td>
                    <span className="clk hollow">2026-06-05</span>
                  </td>
                  <td className="c-actor">
                    <span className="seal seal-human" title="o · oleksii · owner">
                      o
                    </span>
                  </td>
                  <td className="c-dot">
                    <span className="dot dot-approved" title="approved"></span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          {/* on this day (OF-249) */}
          <div className="otd">
            <span className="label">on this day</span>
            <span className="claim">2025 · first note about the Antevon forecasting pilot.</span>
            <a className="act" href="#">
              open
            </a>
          </div>
        </section>
      </div>

      {/* inspector (OF-235): the selected claim's context — work, so it
          rides inside the sheet as its right column (owner 08-14 eve) */}
      <aside className="inspector" aria-label="inspector">
        <div className="trail">
          <a href="#">vault</a>
          <span className="sep">›</span>
          <a href="#" title="entity en_… · dossier">
            Sasha O.
          </a>
          <span className="sep">›</span>
          <a href="#" style={{ color: 'var(--silver-2)' }} title="claim cl_9f27c3">
            claim
          </a>
        </div>

        <div className="insp-title">Sasha moved from Berlin to Lisbon</div>

        <div className="insp-sec">
          <div className="kv">
            <span className="k">predicate</span>
            <span className="v">
              <a href="#" title="registry">
                person.location
              </a>
            </span>
          </div>
          <div className="kv">
            <span className="k">confidence</span>
            <span className="v">0.97</span>
          </div>
          <div className="kv">
            <span className="k">status</span>
            <span className="v" style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <span className="dot dot-approved"></span> approved · active
            </span>
          </div>
          <div className="kv">
            <span className="k">worlds</span>
            <span className="v">
              <a href="#">base</a>
            </span>
          </div>
        </div>

        <div className="insp-sec">
          <span className="label">two clocks</span>
          <div className="twoclocks">
            <div className="tc-row">
              <span className="tc-dot"></span>
              <span className="when">2026-05-30</span>
              <span className="what">occurred</span>
            </div>
            <div className="tc-gap">
              <span className="meta-line">learned 25 days later, from a June catch-up</span>
            </div>
            <div className="tc-row">
              <span className="tc-dot hollow"></span>
              <span className="when">2026-06-24</span>
              <span className="what">learned</span>
            </div>
          </div>
        </div>

        <div className="insp-sec evidence">
          <span className="label">evidence</span>
          <div className="quote">
            “…by the way, Sasha finally did it. She’s been in Lisbon since the end of May, the Berlin
            flat is gone.”
          </div>
          <span className="meta-line" title="turn tn_58c1 · source: chat · trust: first-party">
            turn 2026-06-24 · chat · first-party
          </span>
          <a
            className="act"
            href="#"
            title="context receipt · persona compile, activated memories, board ref, substrate (OF-369)"
          >
            context receipt
          </a>
        </div>

        <div className="insp-sec">
          <span className="label">notes on record</span>
          <div className="aside-note">
            <span className="claim">likely permanent; she signed a year lease.</span>
            <a
              className="byline"
              data-agent="eiri"
              href="#"
              title="eiri · agent · noted 2026-06-24 · a door: the agent panel"
            >
              eiri · 06-24
            </a>
          </div>
        </div>

        <div className="insp-actions">
          <a className="act" href="#" title="verb: supersede_claim">
            supersede
          </a>
          <a className="act" href="#" title="verb: retract_claim">
            retract
          </a>
          <a className="act" href="#" title="verb: share_snapshot">
            share
          </a>
        </div>
      </aside>
    </main>
  )
}
