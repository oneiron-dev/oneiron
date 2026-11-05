# Scour audit — 2026-08-19

The Prime surface scour (finished 08-14, blind to this lane) audited against the built lane
(oneiron-web as of 08-18, FLOWS rules 1–42, both ADJUDICATE packs). 15 auditors, one per
scour brief, each verdicting every material recommendation against the code. Three headless
Grok legs backfilled the scour's failed X-search lanes.

- Scour root: `~/.prime/agent/sessions/019ffc85-…/oneiron-surface-scour/`
- Full verdict tables: [VERDICTS.md](VERDICTS.md) (231 rows, per surface)
- X backfill: [grok-grokbot.md](grok-grokbot.md) · [grok-toastfree.md](grok-toastfree.md) ·
  [grok-consent.md](grok-consent.md)

**Score: 231 material recommendations → 75 BUILT · 30 RULED · 38 NEW-TAKE · 34 NEW-OPTION ·
30 CONFLICT · 24 REJECT.** 45% of the scour was already landed before it was read — it ran one
day before the 08-15 build and four days before the owner's 08-18 review.

## What the scour validates

1. **Confidence-as-ink (exact four-step + criticality floor): no prior art anywhere** (its
   C08 verdict, the only clean "none"). The silver ladder is an invention, not a convention.
2. **The compound vault workbench is fragmentary in the wild** — pieces exist (Wikidata
   statements, XTDB with no console, Dolt, Datomic proprietary), the compound does not.
3. **Grants registry: nothing praised exists anywhere** (grok consent leg, "nothing found") —
   a second no-prior-art wedge; `/settings/grants` is already ahead of every shipped product.
4. **Toast-free**: practitioners reward exactly the three things the lane built — the object
   settles in place, undo that is not a timed corner, a durable home for the outcome
   (receipts). Things 3's Logbook is the validated adjacent pattern (already the tasks ref).

## Systemic corrections (how to read the scour)

- It was fed the **old fixed direction**: film-black desk (dead → rule 37 two rooms),
  DESIGN-APPS §5 hover-peek/centered-sheet/j-k-dock ladder (superseded → rules 31/39),
  "no Raycast clone" (owner ruled the Raycast-model palette 08-18).
- It treats as unbuilt many things that shipped 08-15/08-18: the palette + ask-AI, the vault
  table + as-of slider, the settings area, the grants registry, briefs with cited spans, the
  agents page, mint. Read its briefs only through VERDICTS.md.
- Its own OF-334 correction stands: `a ` = agent definitions, OF-249 = the vault lens.

## Bugs the audit found (fix without asking)

1. **Criticality floor not enforced** — `confClass()` in vault.tsx ignores `critical`; a
   critical claim under 0.4 renders faint, the one thing the ink rule forbids. The row
   tooltip already promises the floor.
2. **`allow once` tooltip mislabeled** (inbox.tsx:814) — it describes what `allow + grant` does.
3. **Threads copy says `seen`** (threads.tsx:103 "the receipt lands when it is seen") — the
   lane's word per ARCH-0046 O5 is `verified`; one line of copy.
4. **IME guard missing** — Enter during kana→kanji composition fires the palette row /
   submits the ask (Palette.tsx, recall.tsx). JP-first product.
5. **`/` double-handler on /app/recall** — page handler + layout handler both fire; `/`
   focuses the ask AND opens the palette over it.
6. **`data-danger` has no CSS** — six destructive acts set it, no rule styles it; the grants
   registry revoke commits on a single click while FLOWS §3-7 says revoke arms red.
7. **Rule-42 eyebrow kill incomplete** — survivors in recall.tsx, threads.tsx,
   lens/supplier-watch.tsx, mint.tsx, signin.tsx (all files dated 08-15, missed by the 08-18
   pass). The coherent-pass law says these clear in one sweep.
8. **Dead doors** — grant doors `href="#"` ×6 (inbox, threads), two links to retired
   `/app/settings`, vault context receipt, threads "36 older receipts", agents run receipts,
   vault inspector entity crumb: all stubs under "every mono token is a door."
9. **Palette selection is index-based** — reorders under the caret once results are async
   (the kbar bug cmdk fixed); key it to item id.

## Take list (NEW-TAKE: fits lane law, no owner input)

Keyboard / one registry
- One action table (id · title · keys · context) feeding the palette acts, the hold-⌘ sheet,
  and page key handlers — today three hooks + a hardcoded KEYS array drift silently.
- Inbox row cursor: ↑↓ walk, Enter opens under the open law, accept/reject on keys, cursor
  advances after settle. The home screen is the one ledger without the walk it advertises.
- One terminal-status word map (DF01): queued|running|waiting|completed|failed|cancelled →
  one lane word + ink, read by agents, inbox, today, ground line.

Receipts / honesty
- Inline `undo · the receipt` on the settled inbox row (pipeline/supplier-watch already ship
  the shape; persistent, no timer).
- Run states beyond live/stopped: `waits on you` (door to the inbox item) + cap warning.
- Outbound negative space: held / degraded / suppressed / let go beside `verified`.
- Envelope truth on the draft card: the From identity + audience above the send click.
- Absent verbs on connector rows (LINE cannot react/edit/retract) — capability vs permission.
- Connector health on agent channel chips (bound-but-not-connected, revoked-but-lit).
- Agent setup edits leave receipts (a history fold on the sheet, matching the docs model).
- Composer limits / reply-window truth (LinkedIn 1900, LINE batch, replyToken ~1min).
- Halt-on-reply on outreach cards (`outreach stopped · they replied`).
- @-handle + addressed-not-ambient line on the agent sheet (ARCH-0065 §4 made visible).
- "What this would remember" line under `allow + grant` (the narrowest bound, before the tap).
- Grants fold: plain-English charter sentence (connectors already solve it) + minted-at +
  last-used.

Vault / records
- Filters, sort, search, as-of into the URL (unblocks saved views and share without deciding
  either).
- Wire the `on this day` strip to the scrubber (owner's own OF-249 note).
- View-scoped export (JSON/Markdown of the current ledger view).
- Deep-link cited spans to the claim record (today every cite lands on the bare ledger).
- Lifecycle ink on cited spans in documents (a retracted claim currently reads as live
  prose — the forgery ARCH-0032b forbids; tokens already exist).
- Revert-one-block from the notes history fold (the safety valve the Proof model needs).
- Entity dossier route + live entity crumb (orgs already proves the shape; person nodes have
  no landing page).
- `opposes` as a real traversable edge in fixtures (contradiction is prose today).
- Exclusion (NOT) + orphan filters on the vault.

A11y / grammar
- One polite aria-live region on the agent line (no-toast law currently leaves screen
  readers with nothing when outcomes settle).
- aria-live line for board drag (keyboard move exists; announcement doesn't).
- Inline field-error grammar (one quiet line under the field; only the global catch boundary
  exists today).
- Typed empty component (first-use · filtered · no-access · failed).
- Narrow-viewport rule for the notes/briefs provenance gutter (the one pane with no
  max-width behavior).
- Settings into the palette + palette mounted in /settings + ⌘, (settings is chip-menu-only —
  the lockout anti-pattern).
- Match-substring marking in palette rows via ink strength.
- Jump-to-latest in the run-scoped chat panel (auto-follow pauses on scroll-up).
- Custody line in mint ("this file is the vault") — its strongest comprehension gap, one STE
  sentence.

## New owner picks (propose adding to the adjudication table)

1. **Snooze / not-now in the inbox** — (a) none: rows only settle, (b) `not now` with a wake,
   (c) defer + mute-predicate. Genuinely uncovered anywhere in canon or register.
2. **Typed palette prefixes** (`c ` claim, `e ` entity, `w ` world…) — Linear-style prefixes
   vs typing the group name (as now) vs neither.
3. **Two-axis scrubber** — second hairline for occurred vs occurred-as-filter + "as believed"
   label vs a mode flip. (Learned-axis + honest supersession replay is already built.)
4. **Saved views home** (OF-403) — rail lenses group vs vault head vs palette.
5. **Graph** — nothing graph-shaped is built yet; the ≤30-dot neighborhood law is canon.
   If and where a first constellation lands (claim record vs entity dossier vs vault
   projection) — or no graph for now.
6. **Run record shape** behind the receipt door — full sheet vs context column vs
   tree ⇄ timeline. Every run door is dead today.
7. **Threads chat-first pick gains a third option** — Zulip-style named topic key on group
   rooms (the one structural idea that keeps chat-first findable).
8. **Voice input placement** — composer mic vs in-app hold-to-talk HUD (system-wide overlay
   is not available to a browser tab).
9. **Admission slate at pack/connector add** (ARCH-0072) — one-tap mints the slate vs
   per-row typed slate vs read-now/write-later. (Owner's own 08-15 question.)
10. **Graduation offer placement** (OF-399) — inside the ask row it graduates from vs a
    quiet offer row on the registry.
11. **Mint posture + restore fork** — /signin is hosted, /mint is a local file; no path
    opens an existing vault. Name the posture; pick where restore lives.
12. **Grants registry as the union** — every standing grant (agent verbs, connectors, packs,
    thread identities) gets a registry row deep-linking home, vs five separate homes as
    built. Canon's line: not on the registry = not a grant.
13. **`expires` column drift** — grants ledger shows hard dates; OF-453 L8 / RS6 say grants
    never auto-expire. Render as slip lifetime, or drop — name it before it hardens.
14. **Pack update that widens scopes** — `update` settles in one beat today; the tooltip
    already names the fuller shape ("the diff waits for your stamp"). Show the diff + fresh
    consent (canon-backed; shape = install ladder reuse). Take-level, listed here because it
    touches consent law.

## Docs canon the lane overtook (one ratification pass, on your GO)

The lane superseded these in person; the docs still say otherwise. One coherent docs pass
after adjudication — not piecemeal edits:

- DESIGN-APPS §5 interaction ladder (hover-peek → centered sheet → j/k dock → page) → lane:
  context column in the sheet (rule 31), open law pending (rule 39).
- DESIGN-APPS §6 breathing live-dot / Agent-Bar dots → rule 36 name-in-ink + shimmer.
- DESIGN-APPS §11.6 "no chat sidebar" vs the ruled floating panel (rules 28/35) — floating
  panel ≠ sidebar on the brief's own test, but the docs line invites re-litigating.
- DESIGN-APPS §7 Cormorant empty voice → lane: Source Serif one-liner + keyed spot art.
- OF-234 bundle verbs (accept-all / reject-all / review-each) → rule 30 killed them.
- OF-239 mission-control console → rule 20 + 08-18: runs demoted to a toggle inside Agents.
- Seal ladder's agent tier (outline=agent) → rules 15/33: seals humans only, agent =
  name-in-ink.
- ARCH-0048 G6 still names Next + Tailwind for render_instrument → lane is TanStack Start +
  bespoke CSS.
- ARCH-0070 mint = preset + plan card → built mint is the six-step working walk (§3·0).
- EF-155 fork law (editing a system agent forks it) → lane edits seeded agents in place.
- ARCH-0011 price ladder ($19/$99 flat) vs the mock's ¥2,900/¥9,800/¥29,000 tiers.
- Stage taxonomy: live ladder (sourced…deposit, adds `audit`) vs ARCH-0059's earned ladder;
  plus cold-cohort-as-board-columns vs the pin that only replied+ is pipeline.
- RS2 logbook-as-a-place vs receipts-settle-where-you-act (no cross-cutting receipt list
  exists in the lane).

## X backfill (what the failed grok_x lanes actually held)

- **Grok Bot** (1 week live): the marketed review list does not exist as lived UX — users
  reinvent it in prompt text. Approval cards land in panes users aren't watching; sidebar
  status lies; Always-Allow leaks or doesn't stick; the shared-VM trust fear is the adoption
  wall; day-2 reliability collapse destroys trust fastest. Praised: 5-minute setup,
  teach-by-demo, the persistent computer. Best idea worth stealing: **a taught routine ships
  with a generated, editable approval boundary**.
- **Toast-free**: consensus is against auto-dismiss + far-from-action + undo-only-in-toast,
  not against feedback. Counter-signal to respect: inline-only outcomes force users to learn
  many local dialects of "done" — the settle grammar must be one language (the DF01 map).
- **Consent**: 93–97% of prompts get approved; catch-rate decays to ~5%; **humans read
  plans, not tool calls** (39% plan-reject vs 3% prompt-reject) — supports run-level /
  bundle-level consent over per-call cards. Praised grammar: scoped standing grants
  (run / workspace / command family) + registry rows with last-used + first-class revoke +
  agent-identity (never host-binary) on the card. No praised shipped registry exists.

## Do not re-research (inherited from the scour, confirmed)

QM (RESEARCH-0319) · Buzz (RESEARCH-0318) · AGenUI (1105) · MCP Apps (1106) · the 7-product
memory-governance field · chat renderer/SDK cohort · RRF vs log-blend · graph-library
bake-offs · event-sourcing UIs · the 1,064-row steal register. Engine-side items the audit
rejected as mock-irrelevant stay engine-side: resume transport, SSE gates, structural gates,
correlation/causation columns, waterfall enrichment policy, notification tiers.
