# Scour audit — full verdict tables (2026-08-19)

One section per scour surface brief; verdicts against the built lane. See [AUDIT.md](AUDIT.md) for the synthesis.

===== 01-inbox-triage =====
[BUILT] Settle in place, never a toast: outcome becomes the row (7px dot ladder + confidence as ink)
    inbox.tsx useSettle/dotClass/chanClass: accept-reject settles the row, the channel glyph takes the outcome ink, verbs become `accepted 14:09`. safelight.css has the exact four-state dot (filled green approved, hollow green auto, hollow amber proposed, faint silver rejected), .conf-1..4 silver ladder, lifecycle as text (.retracted, .superseded). Zero toasts in the repo.
[BUILT] One-line LedgerRow with tiered detail; explainable, not black-box
    FLOWS 3c three tiers: rest = dot + serif claim + verbs (numeral hover-tier), unfold = the reason in a serif sentence + doors, machine provenance only behind `open the claim`. The run's own words sit in the section voice line (Antevon: "42 claims went in on their own. Two wait for you...") — Linear's reasoning-pane honesty without the pane.
[BUILT] Consent row: verb + why + three answers, no duration picker, deny with words
    inbox.tsx b2 row: `allow once` (title: mints a scoped, budgeted, revocable grant) / `allow + grant` / `deny`, plus a free-text reply line ("or answer Eiri in your words…"). Matches OF-367's three answers and DEC-0006 invariant 9; `allow + grant` is the approve-and-stop-asking rung.
[BUILT] Fail-closed burst: pause, never auto-accept
    The `LinkedIn import · paused` bundle: "The burst guard stopped this import before anything landed", verbs `review bundle / resume / discard` (verb: resume_run / cancel_run), head meta "it stopped itself at 180 writes · nothing landed". OF-211 as a row, not a banner.
[BUILT] Cmd+K palette + `/` + keyboard cheatsheet
    Rule 42: Palette.tsx is Raycast-model — pages/claims/acts plus an always-present ask row (⌘↵ asks from anywhere, thinking → answer with doors). `/` and ⌘K both open it. The key list is the hold-⌘ sheet (ShortcutSheet KEYS), not `?` — `?` in the inbox is already bound to "what this screen is".
[RULED] Auto-approve is the default; inbox is an exception queue; the dial is policy
    Rule 8 (08-14): the review dial is dead — it was a view filter pretending to be a policy; now a quiet `show all ⇄ needs you` flip (rule 24 copy) that changes what you see, never what happens. Rule 30: auto-accepted means no bundle verbs. Matches OF-234's amendment; the 40 auto-landed writes are a `40 more` door.
[RULED] Named queue owner + unread badge on the queue
    Rule 4 / 24: one number — the rail's inbox count is the only numeral; per-lens waiting-counts, pack sums and the "5 need you" head count are retired (Rail.tsx tasks row title: "what waits lands in the inbox, not on a badge"). Roles exist in /settings/members (owner/member/guest); triage-responsibility rotation is not a mock concept.
[CONFLICT] DESIGN-APPS §5 dock ladder (hover peek → centered sheet → rail dock → enter page)
    Canon side: §5 specifies a four-step inspect ladder with j/k docking to a side InspectorRail (and §11.6 bans a chat sidebar). Lane side: rule 31 docks a context column INSIDE the sheet (320px bg-well, crumb/title/byline/why/doors, esc closes), rule 39 keeps the open law OPEN with three switchable candidates (gesture · column · kind) in the Tuner, and rules 28/35 built a floating chat panel beside it. No hover-peek, no centered sheet, no enter=page anywhere in the lane.
[CONFLICT] OF-234 bundle verbs: accept-all / reject-all / review-each
    Canon side: OF-234 (ruling 2026-07-07) names bulk verbs at run × verb-class with a bundle receipt. Lane side: rule 30 (08-15) killed them — "if only N wait for you, the rest went in on their own: review each / accept all / reject all are dead; `40 more` is a quiet door to the full record". The group card, per-item receipts and the run headline survive; the verbs do not.
[NEW-TAKE] Keyboard row walk in the inbox (↑↓/j-k cursor, Enter opens, accept/reject keys, cursor advances after a row settles)
    Verified absent: inbox.tsx has only Enter/Space on the two focusable draft rows. Vault, orgs, agents, notes, pipeline and settings all built ↑↓ row walks (vault.tsx:512, orgs.tsx:577, agents.tsx:599), and the hold-⌘ sheet already advertises `↑↓ move` / `⏎ open` globally — the home screen is the one ledger that does not honour it.
[NEW-TAKE] Inline undo + a receipt door on the settled row
    A settled inbox row renders a dead `accepted 14:09` meta-line — no undo, no door. Lane precedent exists (pipeline MovedLine `undo` after a card move, supplier-watch delete + `undo`), canon asks for stamps with inline undo (DESIGN-APPS §5) and every receipt a tappable door (OF-367 RS3); the build law says every mono token is a door. Window stays lane precedent: persistent, no timer.
[NEW-TAKE] Auto-accept policy dial in settings (approve-all ↔ exceptions-only ↔ review-everything)
    Rule 8 promised the dial lives in settings and OF-234's amendment names the three rungs — but /settings/vault only prints read-only policy prose (retention · worlds · "agents never send without your click"). The inbox flip is view-only, so today nothing anywhere changes what surfaces.
[NEW-OPTION] Snooze / defer with time-or-activity return, and mute-thread
    Genuinely uncovered (0 steal hits, no canon row, nothing in the lane). Real call: an exception queue may want `not now` (OF-399 already names not-now for offers) or may want rows to only ever settle. `allow + grant` already covers "stop asking" for consent asks, so mute would only bind claim predicates. Owner picks: (a) no defer, (b) `not now` with a wake, (c) defer + mute-predicate.
[NEW-OPTION] Filters, prefix search, per-identity QuickFilter, impact-order sort
    Built today: only `show all ⇄ needs you`; the wire is strictly chronological (14:05 → 09:15) and the queue groups by run/session, while ARCH-0063 R4 asks for impact order. Rule 42 gave the vault sortable heads + per-column filters + search-as-you-type, so the grammar exists to carry over — but grouping is an owner call already open in FLOWS ("GROUP BY AGENT?"), so it needs his pick, not a decided shape.
[NEW-OPTION] OF-399 graduation offer card (offer, never grant) as an inbox row type
    Nothing in the lane offers a standing grant after a streak of unchanged drafts; `allow + grant` is a one-shot answer to a live ask. Adding it means a fifth card type in one list (offer · exception · consent ask · pause · group), which is the brief's own unmocked seam — a design call for the owner, not a take.
[REJECT] Arbitrary bulk select, archive + auto-unarchive on new activity
    OF-439 is still IDEA and rule 30 killed bundle verbs, so faking multi-select would invent law. There is no archive concept in the lane — rows settle into the record, so auto-unarchive would resurrect settled outcomes. Same row: durable-pending plumbing (LMDB, SSE gate_pending, timed lease) and the crisis T2–T3 never-graduate gate are engine-side; they bind when OF-399 graduation is actually built and render nothing in a fixture mock.
  -- top_new --
  (M) Row cursor + keyboard walk in the inbox: ↑↓ (and j/k) move, Enter opens under the open law, accept/reject on keys, cursor advances to the next unsettled row after a settle
      The inbox is the home screen and the only ledger without the ↑↓ walk every other page built; the hold-⌘ sheet already promises `↑↓ move` / `⏎ open`, so the app currently lies about its own keys. It also makes the open-law pick (rule 39) feelable at speed, which is exactly what the owner is adjudicating.
  (S) The settle line carries `undo` and the receipt door: `accepted 14:09 · undo · the receipt` instead of dead text
      An accept is one click with no way back and no door out — it breaks DESIGN-APPS' "stamps with inline undo", OF-367's "every receipt a tappable door", and the build law that every mono token is a door. Toasts stay dead; the row keeps the record. Pipeline and supplier-watch already ship the exact shape.
  (S) Auto-accept policy dial on /settings/vault: approve-all ↔ exceptions-only ↔ review-everything
      Rule 8 ruled the dial lives in settings and OF-234's amendment names the three rungs, but settings only prints read-only policy prose — so the one promise the inbox makes ("policies live in settings") points at nothing. Not taste-invention: the shape is already written.
  (S) Type the hold reason: make `why held` a named predicate (one source · contradicts a standing claim · critical predicate · burst) instead of free prose in a hover title
      It is the substrate every open call needs — impact-order sort, grouping-by-agent, and any future filter all key off it, and it is already the content of every row tooltip today. Cheap now, and it unblocks the two NEW-OPTION rows without deciding them.
  -- corrections --
  * Material premise is stale: the brief's "DESIGN-APPS cream #F4F0E6 vs fixed film-black desk" conflict is dead. Rule 37 (08-15, oneiron-web f1ce5a5) ruled two rooms following the system via one `light-dark()` token block with contrast parity in both — the fixed film-black desk it audits against is the old direction.
  * "Triage UX essentials are uncovered, not already adjudicated" is now half wrong. Settle-in-place, the four-state 7px dot, tiered row detail, the run-group bundle head, the three-answer consent row and the paused-run row are all built and ruled (FLOWS rules 8/11/11b/30/31; src/routes/app/inbox.tsx). Genuinely uncovered: snooze, undo window, keyboard walk, filters/sort.
  * The steal bullet "OF-234 already names accept-all / reject-all / review-each" is dead in the UI. Rule 30 (08-15) killed bundle verbs — "auto-accepted means NO bundle verbs" — and `40 more` is now a quiet door to the full record.
  * "`?` overlay + command palette (discoverability)" is listed as a gap but is built: rule 42 shipped the ⌘K / `/` Raycast-model palette with an ask row (src/components/safelight/Palette.tsx), and the key list is the hold-⌘ sheet. `?` in the inbox already means "what this screen is", so it is not free for a keymap overlay.
  * The brief treats DESIGN-APPS' InspectorRail/dock as the lane's inspect chrome. It is not: rule 31 docks a context column INSIDE the sheet (320px bg-well), and rule 39 leaves the open law open with three candidates (gesture · column · kind) switchable in the dev Tuner — the owner picks by feel in ADJUDICATE-20260818 (his rec: gesture).

===== 02-chat-panel-gaps =====
[BUILT] Close/reopen restores identity, draft, scroll, in-flight turn
    `Ground` is mounted in the `/app` layout (`src/routes/app/route.tsx:62`) and the closed panel is only `opacity:0 / pointer-events:none` (`chassis.css:238-250`), so scope, draft, sent messages, stopped-run state and thread scroll all survive close→reopen and every route change. Delta vs the brief: no reload survival — the mock has no server.
[RULED] Stop ≠ disconnect; stop persists the partial and cancels the work
    FLOWS rule 34 (owner 08-15): `stop` IS the cancel Signal worn as a run-head verb — it settles the run at its next breakpoint, what landed stays, the thread stays live, and a later message picks the work back up. Built in `Ground.tsx` (`stopRun`, `STOP_ACK`, `RESUME_ACK`, head reads `stopped`, line goes still).
[RULED] Send↔Stop swap / "gate sending, not typing" / F25 queue-vs-steer
    Owner ruled steer-first: a message into a live run is a STEER consumed at the next safe breakpoint and the run CONTINUES; the composer never becomes a Stop button (FLOWS rule 34; `docs/chat-oss-patterns.md` marks the OSS-standard swap DEAD). The brief's F25 dual-channel is the built grammar — placeholder flips `steer <agent>` ⇄ `message <agent>`.
[BUILT] SLK-002 — panel stays open and keeps state across context switch
    The panel never unmounts across pages; pages knock on it with one window event `oneiron:chat` (`Ground.tsx:116-123`, used by agents/today/notes/briefs). No second surface, no remount.
[NEW-TAKE] dashboard-v2:D10 — reopen keeps the structured selection handle
    Named unbuilt in BOTH adjudication packs: `hand to Eiri/Tory` and `ask Antevon` open the panel but it is not scoped to the selection or the note — "needs a Ground contract" (`ADJUDICATE-20260818.md` Left honest; `ADJUDICATE-20260815.md:84`). The entity/span/provenance handle is the missing contract, M effort.
[BUILT] Fresh chat is the recovery, not a recap-resume
    `+ new chat` opens EMPTY on the flock plate with one line and three doors that fill the composer (FLOWS rule 40); past chats live behind the history icon grouped `today` / `earlier` (rule 29, `Ground.tsx` HISTORY). Matches `companion-ux` / `ll-ms` without a recap prompt.
[BUILT] Typed stream envelope (F20 TEXT_DELTA/THINKING/TOOL_*/COMPLETE/ERROR)
    Superseded by a richer doctrine the lane already adopted in `oneiron-web/docs/chat-oss-patterns.md` (patterns 1-3): typed `parts[]` + renderer registry + per-part lifecycle (`streaming-in / ready / awaiting-user / done / error / denied`) + `transient` parts that render live but never enter history. Code currently ships one part type (`Cwidget`).
[RULED] Agent Bar pulsing dots / Slack count-vs-dot badge
    Ruled the other way: FLOWS rule 36 (owner 08-15, "it makes no sense to have separate dot and eiri") killed the presence dot — the NAME in its ink is the mark, live = the doing-text shimmers, stopped = still and dimmed (`chassis.css:334-355`). Rail carries the same stance: "what waits lands in the inbox, not on a badge" (`Rail.tsx:301`). This overrides DESIGN-APPS §6's breathing live-dot and CROSS-ARCH-0009b's Agent Bar dots.
[NEW-OPTION] A mark for new activity while the panel is CLOSED
    Genuinely open and already on the lane's own open list — "remaining chat table-stakes (jump-to-latest + line badge…)" (FLOWS §3c tail) and `chat-oss-patterns.md` ("no prior art for our exact panel-over-strip shape"). Any option must obey rule 36 (no dot) and the no-badge stance, so the owner picks between e.g. name-ink brightening, a re-shimmer on the settled line, or a count in the panel head.
[BUILT] No toasts for chat activity
    Global law, honored everywhere: zero toast code in `src/`; outcomes settle as quiet receipt lines in place (`lens.css:64`, `signin.css`, `settings-area.css`, `threads.tsx` thr-foot with `aria-live`). CROSS-ARCH-0009b's Normal/Critical push tiers never enter the app surface.
[NEW-OPTION] Voice input: composer mic + hold-to-talk overlay
    Nothing voice exists in oneiron-web (no mic, no capture, no `VoiceLine` in the panel — grep is clean). The lane names it as an owner call verbatim: "where voice input joins the reply line" (FLOWS §3c open list). Caveat for the options: Superwhisper's system-wide overlay is not available to a browser tab — for this surface the real choice is composer mic vs in-app hold-to-talk HUD; the global lane belongs to a desktop shell or Eiri iOS.
[NEW-TAKE] Ghost partial transcript, explicit commit
    Contingent on the voice pick but the grammar is already ours: agent text sits in the agent's ink until read (`notes.css:144`, rule 42) and "nothing goes out without your click" (threads). Partial = ghost ink, commit = the click; S effort once a mic exists.
[REJECT] Resume transport — DF06 replay queue + Last-Event-ID, DF05 suffix scan, NSD-009 FIFO, heartbeat 15s vs 30s, Pipecat vs LiveKit, OF-334 mislabel, Grok Bot
    Not this surface: oneiron-web is a fixture mock with no server, and every one of these is already adopted in `steal-evaluations.json` or is an engine/vendor pick. The heartbeat cadence and Pipecat-vs-LiveKit are backend calls, not UI adjudications; the OF-334 registry fix belongs to oneiron-docs.
[CONFLICT] Floating chat panel vs DESIGN-APPS §11 #6 and dr:DF04
    Lane side: FLOWS rules 28/35 build a floating 400×min(600,74vh) panel above a PERMANENT bottom agent line, ruled twice by the owner in person. Canon side: DESIGN-APPS §11 #6 bans a chat sidebar (the agent IS the app; replies materialize in the world) and `dr:DF04` says active agents surface contextually via `self.ui`, not a standing presence surface. Live evidence for the brief's own drift test: an ask thread today exists ONLY in the panel plus the history popover — it never stamps a record.
[NEW-OPTION] Threads screen becoming chat-like
    Adjacent to this surface and pending the owner: `ADJUDICATE-20260818.md` asks chat-first (Antevon in his ink, replies inline) vs history-first as built (`src/routes/app/threads.tsx` = identity table + entry ledger + context column); Fable's rec is chat-first. Deliberately not rebuilt yet, waiting on the rule 39 open-law pick.
  -- top_new --
  (M) The Ground contract: a scoped panel handle
      `hand to Eiri` / `ask Antevon` / `open the run` already knock on the panel but arrive unscoped — both adjudication packs list this as the one honest hole. One structured handle (record id + optional span + provenance + view context) carried into the panel head and kept across close→reopen closes `dashboard-v2:D10` and makes selection-to-agent real instead of decorative.
  (S) A reconnect / catching-up state in the panel head
      The lane has no vocabulary for "the link dropped, the run kept going" — the panel head only knows live, stopped, and new chat. One quiet inline cue in the head (no toast, no badge) is the entire UI half of resumable streams, and it is the piece the backend steal rows (DF06/DF05) cannot decide for us.
  (S) Pin-to-bottom + jump-to-latest, done right
      `.chat-thread` is bare `overflow-y:auto` today, so a streaming run fights the reader's scroll. The lane's own pattern doc already specifies the correct build (sticky flag owned by a ResizeObserver, user scroll cancels instantly, the jump pill gets its OWN observer so pin flips never re-render the thread), and it is on the FLOWS open table-stakes list.
  (M) Widget lifecycle + reconcile-by-id, transient status parts
      `Cwidget` is a static card; the run-scoped panel needs status ticks that render live and never enter history, and cards that patch in place on the same id (loading → filled) instead of stacking. This is the AG-UI snapshot/delta idea rebuilt in our one part type, and it is what keeps a 400px panel readable during a long run.
  -- corrections --
  * The brief's fixed-stack line ("film-black desk, one elevated sheet") audits against a dead direction. FLOWS rule 37 (owner 08-15 eve) replaced it with two rooms following the system via `light-dark()` tokens: day = cream paper sheet on a slightly darker desk, night = deep night room, contrast parity in both.
  * "Agent Bar pulsing dots already specified — implement THAT" is now forbidden. FLOWS rule 36 killed the presence dot on 08-15; presence is the name in the agent's ink plus a shimmer on the doing-text. DESIGN-APPS §6's breathing live-dot and §11.5's "agent names inline at rest" are both superseded by lane rules 33/36.
  * The brief treats stop/abort and the Send↔Stop composer swap as the shape to build. FLOWS rule 34 ruled steer-first: the composer never becomes a Stop button, a message into a live run is a STEER consumed at the next breakpoint, and stop lives as a run-head Signal that leaves the thread alive.
  * "Floating-panel close→reopen contract is unspecified" is out of date. Rules 28/29/35 specify it and `Ground.tsx` builds it: scope kept through the close, esc peels the popover before the panel, × and a desk click close, history is an icon with chats grouped by age.
  * "No prior art for a notification-free dock-line badge" is already recorded inside the lane, independently: `oneiron-web/docs/chat-oss-patterns.md` names the same absence for our panel-over-strip shape and points at a run viewer's "back to live" pill as the nearest thing.
  * Superwhisper-class placement cannot be copied onto this surface. A browser tab owns no global hotkey, menu-bar item, or system overlay; for oneiron-web the placement choice is composer mic vs in-app hold-to-talk HUD, and the system-wide lane belongs to a desktop shell or Eiri iOS (`[VOX-09]`).

===== 03-vault-claim-db =====
[BUILT] Confidence-as-ink (ladder + criticality mark)
    `confClass()` in <workspace>/Desktop/code/oneiron-web/src/routes/app/vault.tsx maps 0.9/0.7/0.4 to the silver ladder (`.conf-1..4`, safelight.css:184-187) applied to the claim text; a critical low-confidence row gets an amber `unverified` mark. No 0-100 badge anywhere, so the confidence-theatre anti-pattern is already closed.
[CONFLICT] Numeral on hover only (DESIGN-APPS §4) vs the visible `conf` column
    DESIGN-APPS §4 and the brief say ink at rest, numeral hover-tier; the built ledger ships `conf` as a visible, sortable mono column (vault.tsx COLUMNS + `.confn`). Owner named this exact call himself in docs/ADJUDICATE-20260818.md ("Keep the column, or sort by ink and drop the numeral?") — pending, do not resolve.
[NEW-TAKE] Criticality floor — critical predicates never render below muted
    The row tooltip promises it ("critical predicate · never renders below muted ink") but `confClass(c.conf)` never sees `c.critical`, so a critical claim under 0.4 would render faint — the one thing DESIGN-APPS §4 forbids. One-line clamp in vault.tsx.
[BUILT] Two-clock columns visible at rest (occurred + learned)
    `occurred` (solid mono) and `learned` (hollow `.clk.hollow`) are both resting columns, each sortable and date-filterable; the inspector adds a TwoClocks block with a hindsight gap line ("learned 25 days later"). Serif-occurred/mono-learned is rendered as solid-vs-hollow mono instead.
[BUILT] As-of scrubber that re-projects the table
    `AsOf` in vault.tsx is a real slider (pointer drag, ←/→, Shift=30d, Home/End, crimson hairline handle) and `stateAt()` resurrects a superseded claim whose successor was not yet learned — honest "what did the vault believe then", not a decorative filter. Owner asks in ADJUDICATE-20260818 only whether the `today` act stays.
[NEW-OPTION] True two-axis scrubber (valid at T1 as believed at T2) + "not on latest" banner
    Built axis is LEARNED only; occurred is served by a column date filter, and while scrubbed there is no frozen/read-only state, just the date plus a `today` act. Shapes for the owner: (a) second hairline for occurred on the same track, (b) keep occurred as a filter and label the scrubber "as believed", (c) a mode flip on the scrubber — all cheap; the frozen line rides whichever wins.
[BUILT] Worlds/scopes filter that actually changes the ledger
    World chips (`base` fixed-on, `work`, `health`, `fiction` archived + disabled) filter rows, beside state chips (active/superseded/retracted) — the ARCH-0044 WorldScope read model, not decoration. Open beside it: worlds vocabulary drift (vault `base·work·health·fiction` vs FLOWS §2 and /settings/vault POLICY `base·clients·internal`), an owner call in both ADJUDICATE packs.
[BUILT] Supersede ≠ retract ≠ delete; wrong values stay walkable
    `state` carries active/superseded/retracted: superseded rows ghost and grow a `→ successor` door (both directions, ledger and inspector), retracted strikethrough, `supersede`/`retract` verbs in the inspector foot. Hard delete is the separate /settings/forget ceremony (arms only with a reason, ERASED receipts + sweep line) — USERS-EXPECT 4 and 10 both land.
[BUILT] Wikidata statement chrome on expand (claim → evidence → receipt) + entity dossier
    The inspector column carries crumb, predicate-to-registry door, conf, status+state+successor, world, actor seal/name+source, two clocks, the source quote with a structured meta line, and a `context receipt` door; the org dossier (standing → people/pipeline → timeline → claims → "the vault, filtered") is app/orgs.tsx. Deltas: the vault inspector's entity crumb is still `href="#"`, there is no person dossier, and qualifiers/rank have no affordance.
[RULED] Headless-table ideas rebuilt native, no TanStack Table / glide dep
    FLOWS rule 42 (08-18): tables are interactive, "hand-rolled on TanStack Table's column-def shape, no dep". vault.tsx `COLUMNS` is literally `{id, header, kind, size, accessor, sortingFn, filterFn}` with sort cycling, per-column filter popovers and a chip row — the brief's steal is already the shipped implementation.
[RULED] No toast for a write that matters; ambient provenance, compact default
    Standing register law: no toasts anywhere ever, quiet inline cues only; rule 42 additionally killed eyebrow chrome and replaced it with one meta-line (`Antevon · as of 14:07` on the vault head) or a hover title. The PaperTrail clutter warning is already the lane's default.
[NEW-OPTION] Saved views = OF-403 SAVED_QUERY (name + filter + sort + columns + deep link)
    Nothing is built: filters, sort, search and as-of are ephemeral React state with no URL params, so no view survives a reload and the inspector's `share a snapshot` icon has nothing to point at. Where saved views live is a real taste call — the rail's `lenses` group (rule 21), the vault head, or the ⌘K palette — so it needs 2-3 options, not a decided shape.
[NEW-OPTION] Bulk select + bulk supersede/retract + undo window
    Selection is single-row only (↑↓ move, Enter opens, Esc peels popover → selection → filters → as-of); no checkboxes, Shift-select, Mod-A, or queued-write undo. It is a genuine gap but the shape collides with ARCH-0040 gates and the no-toast law, so it is an owner pick, not a take.
[NEW-TAKE] Export one-tap JSON/Markdown of the ledger view
    /settings/export already ships whole-vault "export with provenance" (tar.zst, sealed, past-exports ledger), but the view-scoped export the brief asks for does not exist. Small and honest once the current filter set is nameable.
[NEW-TAKE] On-this-day jump of the valid-time scrubber
    The `.otd` strip is already on the ledger's foot with a hardcoded 2025 line and a dead `open` link — the affordance was placed but never wired to the scrubber or an occurred filter. Owner named this himself in the OF-249 registry note as the thing he was unsure how to do.
[REJECT] Wikidata rank as a third axis; 50k-row density / virtualization audit
    Rank (preferred/normal/deprecated) duplicates what the lane already carries in two fields — `state` (active/superseded/retracted) plus `status` (approved/auto/proposed/rejected) — and the engine has no rank field to feed it. Density at 50k rows is premature for a 28-row fixture mock, though the head line already claims "12,408 claims".
  -- top_new --
  (S) Enforce the criticality floor in `confClass`
      The row tooltip already promises "never renders below muted ink" while the code ignores `critical`, so a critical claim under 0.4 renders faint — the exact anti-pattern DESIGN-APPS §4 names. Cheapest possible fix to the one place the ink is allowed to lie.
  (M) Put filters, sort, search and as-of in the URL
      Nothing in the vault survives a reload today, and the inspector's `share a snapshot` icon has no target. This is the un-optional half of saved views (OF-403) and of sharing, with no taste call attached — it unblocks both without deciding either.
  (S) Wire the `on this day` strip to the scrubber
      The strip is already rendered and its `open` link is dead; the owner named the affordance himself in the OF-249 registry note and said he was unsure how to do it in the UI. One keystroke or one click sets the time control to today-last-year.
  (S) Export the current ledger view as JSON / Markdown
      Settings ships only the whole-vault tar.zst; "your vault is yours" at view scope is table-stakes every DB browser has and no memory product does. Rides whatever URL/query state the item above produces.
  -- corrections --
  * Dead direction in the brief's fixed-stack line (§CANON SAYS last para): "film-black desk, one elevated sheet" was superseded by FLOWS rule 37 (owner 08-15 eve). The lane is TWO rooms — cream paper sheet on a darker desk by day, deep night room by night — following the system via one `light-dark()` token block with contrast parity. Audit any vault chrome against the two-room material, not film-black.
  * The brief reads the ledger as open design space; it is BUILT. <workspace>/Desktop/code/oneiron-web/src/routes/app/vault.tsx (949 lines) already ships sortable heads, per-column filter popovers by kind, search-as-you-type, world/state/filter chip rows, a working as-of slider, keyboard rows, the ink ladder and a permanent inspector column — most of USERS-EXPECT 1-7, 11 and 12 and most of the STEAL list land there today.
  * The Engram-diagonal gap is half-closed, not open. The built scrubber moves the LEARNED axis and `stateAt()` resurrects a claim whose successor had not yet been learned — that is the harder "what did the vault believe then" half. What is missing is the second (occurred) axis as a scrubber; occurred is currently a column date filter.
  * DESIGN-APPS §5's escalation (hover=peek → click=sheet → dock=rail → enter=page) is not the built law here. FLOWS rule 5 (owner 08-14 eve) made the vault inspector permanent work inside the sheet as its right column; click selects and opens it, Enter does the same. The general row-open law is rule 39 and is still OPEN — three candidates switchable in the dev tuner, owner adjudicating.
  * The criticality floor is documented but unimplemented: `confClass(conf)` in vault.tsx takes only the number, so `critical` never reaches the ink decision. The single critical fixture sits at 0.52, which hides the bug.
  * Delete-that-deletes and export-with-provenance are not open ground. /settings/forget ships the forget ceremony (arms only once a reason is typed, ERASED receipts with sweep timestamps) and /settings/export ships whole-vault export with provenance plus a past-exports ledger — USERS-EXPECT 10 and 0605d rec 5.8 are already answered at vault scope.

===== 04-graph-view =====
[NEW-OPTION] Two-mode: ≤30 neighborhood default, atlas opt-in behind an affordance
    Nothing graph-shaped exists in oneiron-web — no route, no canvas/WebGL, no SVG graph anywhere in src. The two-mode split is uncontested (DESIGN-APPS §8 + practitioners agree), but where a neighborhood docks (third vault projection beside the table, a strip inside the claim/entity record, or its own rail door) is a real placement choice → owner pick, not an agent decision.
[BUILT] Filters cut the candidate set before layout; as-of scrubber as a graph filter
    src/routes/app/vault.tsx already ships world chips, state chips (active/superseded/retracted), per-column enum/date/conf filter popovers with a chips row + clear, and a real as-of slider (drag, ←/→, Home/End) that re-derives supersession via stateAt(). Delta: filters are include-only — no orphan filter and no NOT/exclusion, which practitioners call the highest-leverage one.
[BUILT] Every node is a door / stable node → sheet identity
    The law is FLOWS §4 ("every mono token is a door") and it holds: claim rows open the inspector, predicate and successor are doors, orgs rows open dossier + full page. Gap: the inspector's entity crumb ({c.entity}) is a dead href="#" — a graph node for a person or claim has no page to land on yet.
[NEW-TAKE] Entity dossier as the node's landing surface (OF-249's other half)
    Orgs already proves the ledger → dossier column → full page shape (src/routes/app/orgs.tsx); people and other entities have none, so the vault's entity crumb goes nowhere. Building it is canon-named work, not taste-invention, and it is the prerequisite for any node-as-door.
[RULED] Split click contracts: body = inspect, explicit + = expand, edge click = claim inspector
    Rule 39 (row-open law) is OPEN and switchable live in the dev Tuner (gesture · column · kind, default 'kind' in src/components/dev/Tuner.tsx); the owner adjudicates in ADJUDICATE-20260818.md. The brief's split-click is compatible with all three but cannot be settled ahead of his pick — a graph inherits whatever wins.
[CONFLICT] Hover = peek popover, zero commitment
    Brief + DESIGN-APPS §5 make hover a peek popover. The built lane makes hover the *title-attribute* tier (rule 3c: confidence numeral, run id, time all ride the tooltip) and reserves popovers for click (filter pop, chip menu, palette, history) — no hover popover exists anywhere in the app, and hover has no touch or keyboard equivalent. Both sides stated; not resolved.
[NEW-TAKE] Display-time reducer over immutable data + graphology-style data/render split
    Matches how the lane already builds: vault's COLUMNS carry accessor/sortingFn/filterFn mirroring TanStack Table's column-def shape with zero deps installed. Same discipline for a graph — typed claim data is truth, the renderer is a throwaway view — costs nothing and keeps the bitemporal record un-mutated by view state.
[RULED] Depth slider 1–3 (2 default) as a user control
    Rule 38 makes sliders a DEV instrument, never product (the tuner is dev-only), and normal-person-first hides power-user config. Depth belongs as a fixed default with a tuner knob behind the backtick, not a user-facing slider — which the brief's own 'aesthetic-chasing sliders' anti-pattern also argues for.
[RULED] Search-to-node rides the one existing search; no second search box
    Rule 42 moved search to the ⌘K/`/` Raycast-style palette (search + ask, src/components/safelight/Palette.tsx), replacing search-as-page; recall is now the printed answer, not the search surface. Any graph find must ride the palette — note the palette's vault entry already carries the keyword 'graph'.
[BUILT] Typed, directed, labeled edges + confidence/source badges; do not flatten the 26 kinds
    The ledger already speaks this: predicate as a door, source column, confidence-as-ink ladder plus a numeral column, status dot, and supersedes drawn as a traversable '→ successor' link both in-row and in the inspector. Delta: only `supersedes` exists as an edge in fixtures — `supports`/`opposes` appear as prose notes, never as edges.
[REJECT] Atlas as clustered density field (Leiden/CPM), 10k draw budget, viewport culling, WebGL
    Premature for a fixture mock: the neighborhood-expansion read is ruled-but-unbuilt (workbench-engine-asks 2026-07-29), the app has zero canvas/WebGL, and the vault's 12,408 is a printed number over 27 fixture claims. Keep it engine-side backlog; the atlas is exactly the thing the brief warns gets built first because it screenshots well.
[RULED] Library bench: sigma.js vs cosmos.gl vs Cytoscape vs xyflow
    Study-never-import is a standing law and the lane lives it — hand-rolled table on TanStack Table's shape with nothing installed, bespoke CSS, no Tailwind/Radix. A renderer bench is also meaningless before the atlas read exists; the four repos stay reading material.
[REJECT] Anti-patterns: hairball, graph-as-primary-navigation, always-on physics, 3D default, proximity implies truth
    Duplicate of the register: the rail IA has no graph door (inbox · vault · agents are the core group), reduced-motion is a build law, transform+opacity only, red scarce. Nothing here changes a decision the lane has not already made.
[REJECT] Cream vs film-black conflict (DESIGN-APPS §0/§1.1 vs 'fixed product direction')
    Dead premise. Rule 37 (08-15) replaced the single fixed look with two rooms following the system via `light-dark()`, one token block, contrast parity within ±0.5 per silver rung — film-black-as-the-direction no longer exists, so there is nothing to flag.
[NEW-TAKE] Graph-FS name collision (ARCH-0051 VFS vs the visual NeighborhoodGraph)
    Worth carrying because the collision is already live in built copy: the rail tooltip says vault · board · graph live inside, the palette's vault keys include 'graph', and settings/packs.tsx advertises 'a symbol graph' (that is ARCH-0050 code graph). Three different graphs named in a UI that draws none — one naming pass when the atom lands.
  -- top_new --
  (M) Entity dossier route + a live entity crumb in the vault inspector
      OF-249's other half and the only door a graph node could open; today the inspector's entity crumb is a dead href="#" and only orgs have a record page. Orgs already proves the ledger → dossier column → full page shape, so this is copy-the-pattern work, and it is useful with or without a graph.
  (M) A printed neighborhood constellation inside the record (SVG, ≤20 nodes, zero physics)
      The cheapest honest test of whether a graph earns a place: static layout, ink ladder for confidence, typed labelled edges, every dot a door — no canvas, no force sim, no engine read needed at fixture scale. Placement (claim record vs entity dossier vs vault projection) stays an owner pick, so build it as 2 placements to look at, not one decided shape.
  (S) Make `opposes` a real edge in the vault fixtures
      The contradiction story is currently prose — cl_13f7aa carries a note saying it contradicts the May claim, while only `supersedes` is traversable. One fixture edge plus a door turns ARCH-0004's contradiction isolation into something visible in the built table, and gives any future graph a second typed edge kind to draw.
  (S) Exclusion and orphan filters in the vault
      Every practitioner source names the NOT-filter (`-path:Daily/`) as the highest-leverage one, and the vault's filters are include-only. Orphan claims (no entity, no successor, no source door) are also the weekly-audit use that keeps a graph alive rather than decorative. Small addition to the existing filterFn contract.
  -- corrections --
  * The brief audits against film-black-as-fixed-direction. Rule 37 (08-15) killed that: two rooms, system-following `light-dark()` tokens, one token block, contrast parity. The cream-vs-film-black CONFLICT row has no live side.
  * The brief puts search-to-node 'on the existing `/` recall surface'. Since rule 42 (08-18), `/` and ⌘K open the palette (search + ask with doors), recall is the printed answer page, and the vault carries its own pane search. Graph search must ride the palette.
  * DESIGN-APPS §5's grammar is not the built grammar. No hover popover exists anywhere in the app; the sheet is not centered (it fills the desk, 08-14 rule 5); the context column docks inside the sheet (rule 31); and the row-open law itself is still open (rule 39, switchable in the Tuner).
  * Lane state the scour could not see: oneiron-web has zero graph code — no route, no canvas or WebGL, no SVG graph. But built copy already promises one: the rail's vault link reads 'vault · board · graph live inside' and the palette's vault keys include 'graph'. The vault ships table + inspector only; the board lives on pipeline.
  * Of DESIGN-APPS §10's three closed atoms, two are already built: AsofScrubber (vault's real as-of slider with keyboard steps and honest supersession replay) and InspectorSheet (the inspector as the sheet's right column, 08-14 rule 5). NeighborhoodGraph is the only one unbuilt.
  * The ≤30 SVG inspection budget needs no engine read at the mock's scale (27 fixture claims behind a printed 12,408 / 214 entities). Only the atlas waits on the unbuilt expansion read — so 'graph is blocked' is not true of the neighborhood half.

===== 05-crm-pack =====
[BUILT] Kanban = view over the same query; board ⇄ ledger toggle with per-stage count/sum
    `<workspace>/Desktop/code/oneiron-web/src/routes/app/pipeline.tsx` — one ORGS projection, `BOARD_ORDER` columns vs `LEDGER_ORDER` stage groups, `proj` switch persisted in localStorage, per-column count `pc-n` + money sum `pc-money`, strip counts per stage. Delta: ledger group heads carry an org count only, no per-stage money sum.
[RULED] Grouped ledger default, slip-board as the alternative
    Owner ruled the opposite on 08-18 (FLOWS rule 42): the board is the pipeline's main view with Trello-grade cards, ledger behind the switch. The brief's `crm-lens.html` ledger-default reading is the dead direction.
[CONFLICT] Drag = a claim-write request; drops lacking the named evidence class are blocked, not silent
    Canon side: ARCH-0059 `crm.stage` is earned AUTO with a named evidence class per transition. Built side: `moveTo` in pipeline.tsx moves any card to any stage by drag or alt+arrow and settles a `moved to X · undo` line — no evidence gate. ADJUDICATE-20260818 (Pipeline Q3) asks the owner only whether a backward drop should arm first.
[CONFLICT] Cold cohort is not a pipeline column (`campaign.member` ≠ `crm.stage`)
    Canon side: CRM-flow pin 2 + ARCH-0059 — only replied+ is pipeline. Built side: FLOWS §3 #6 and pipeline.tsx render one 8-stage funnel where `sourced` (34), `qualified` (18) and `outreach` (11) are full board columns and strip chips. ADJUDICATE-20260818 asks only about collapsing the early stages for layout at 1280, not about their semantics. Same root as the Attio per-(person×campaign) idea: the built model is one stage per org.
[CONFLICT] Mock stage taxonomy vs the ARCH-0059 earned ladder — reconcile before code
    A third ladder is already in code: `sourced · qualified · outreach · replied · call booked · audit · proposal · deposit` (pipeline.tsx `STAGES`, orgs.tsx `STAGES`). Canon: `replied / call_booked / call_held / proposal_sent / deposit_paid / delivering`. The brief's lead/call/proposal/pilot/retainer set is dead.
[BUILT] Dossier law: standing → what-we-know → the thread; a card opens the org, not a fatter card
    `<workspace>/Desktop/code/oneiron-web/src/routes/app/orgs.tsx` — Dossier column: title + byline → people → what we know → the thread → next step → notes; full page adds pipeline, timeline, claims, threads, briefs, tasks. Pipeline's `open the org` act doors to /app/orgs (pipeline.tsx `actTip('org')`).
[BUILT] Two clocks: board on DETECTED, dossier timeline on VALID
    Partial. Claim lines carry `occurred`/`learned` in ink everywhere (pipeline.tsx `Claim.when`, orgs.tsx timeline, vault as-of scrubber). Delta: no ordering law is implemented — cards and rows render in fixture order, so the detected-vs-valid split is vocabulary, not sort.
[BUILT] Today as morning paper (overnight / needs you / meetings / due), not a second kanban
    `src/routes/app/today.tsx` — Now / Next (time ledger with a now marker, `?at=` preview) / Overnight (Antevon voice + receipts) / The week. Due-today and next-action also live as the `next steps due today` chip in pipeline.tsx and as `today · this week · later` groups in `src/routes/app/tasks.tsx`.
[CONFLICT] "Now is a live panel, not Today"
    Brief side (and FLOWS rules 16/19): live presence lives in the agent line, never repeated. Built side: today.tsx opens with a `Now` bundle listing the two live runs with `open the run` doors — the same facts the ground line carries.
[NEW-TAKE] Reason-carrying dedup queue + topology merge (dry-run preview, field chooser only for scalar conflicts)
    Nothing in the app. The only traces are pipeline.tsx's `merge_threads` act (threads, not entities) and a `Merged two records for Mika Tanaka into one` receipt line in briefs.tsx with no surface behind it. ARCH-0055 already fixes the semantics; the missing piece is the inbox proposal row + preview.
[BUILT] Channel capture: actor + scope + receipted auto-log; Twenty-style label/folder picker
    Partial. `src/routes/settings/connectors.tsx` carries channel · as · audience · state · charter · receipts · revoke, with the granted verbs in the scope tooltip; thread tails show `delivered · receipted` and agent name in ink. Gap: the connect fold takes only a workspace string — no channel/label/folder pick — and the scope line is hover-only.
[NEW-TAKE] NSD-030: an inbound reply halts the remaining scheduled outreach
    Absent. Outreach cards carry `second touch · today` and `Two touches, no answer` with no halt-on-reply state; the campaign-ends-at-reply fact has no cue anywhere in pipeline.tsx.
[REJECT] Waterfall enrichment as policy (N providers, first verified wins, per-field source URLs, BYO keys)
    Per-field provenance is already BUILT (claim rows carry source + run-id tooltips in orgs.tsx and vault). The provider-workbook/waterfall config UI is backend policy and power-user config — premature for the mock under normal-person-first; the ship riders (storage letter, GDPR) are not UI at all.
[BUILT] dnd-kit steals: pointer + keyboard sensors, column collision, overlay ghost, live region
    Hand-rolled, no package: `startDrag`/`onPointerMove` with a transform-only ghost, `elementFromPoint` column collision, edge autoscroll, 6px travel threshold, alt+←/→ keyboard move, ↑↓ column walk (pipeline.tsx). Gap: no aria-live region — a drag or keyboard move announces nothing.
[REJECT] Custom fields/stages, saved views, bulk ops, keyboard, undo, recycle-bin restore
    Keyboard and undo are BUILT (walk, alt+arrow, Esc layers, `undo` on every move); saved queries exist as the `watch this org` act plus the rail `lenses` group (/app/lens/supplier-watch). Custom fields, custom stages, bulk ops and recycle-bin restore are power-user completeness — premature for a fixture mock, and stages are pack-defined per OF-276.
  -- top_new --
  (M) A merge proposal that you can read before you commit: an inbox row (`two records look like one person`) whose unfold shows both sides, the reason, and the dry-run result — nothing overwritten, redirect shell, one receipt with both origins.
      The one real table-stakes hole on this surface. Canon already decides the semantics (ARCH-0055 auto-default + reason-carrying proposal), the row grammar exists (rules 11/11b: deep payload → `read` at rest), and briefs.tsx already prints a merge receipt for a merge the app cannot show.
  (S) Halt-on-reply on the outreach cards: when they answer, the remaining scheduled touches stop and the card says so in place (`outreach stopped · they replied`), with the queued touch struck in the tail.
      NSD-030 / campaign-ends-at-reply is the one behavior that makes outreach look honest rather than a drip machine. It is a quiet inline state, so it costs nothing against the no-toast law.
  (S) Scope at connect time: the connect fold picks what the channel may read (which channels / which label or folder / which account), and the granted scope prints as a visible line on the row instead of living in a tooltip.
      Privacy scope is table-stakes for mail and chat capture, not a nicety, and it is the one thing self-hosters check first. The fold, the receipt line and the revoke path already exist in settings/connectors.tsx.
  (S) An aria-live line for the board: announce the pick-up, the column under the hand, and the landing (`Aster Components moved to proposal`), matching what the `undo` line already says visually.
      It is the last unclaimed dnd-kit idea and the only part of the drag that is keyboard-and-screen-reader dark; the keyboard move (alt+arrow) already exists, so it is a few lines against existing state.
  -- corrections --
  * "OF-229 IDEA — the design substrate exists, the surface does not" is out of date. The CRM lens is live code: /app/pipeline (1,352 lines, board + ledger, drag, filters, unfold), /app/orgs (1,407 lines, dossier column + full record page), /app/today, /app/tasks. The 12 HTML mocks (crm-lens.html, today.html) were superseded by these routes on 08-15 (FLOWS rule 41) and are read-only content truth now.
  * "Grouped ledger default, slip-board hidden — already in crm-lens.html" audits a dead direction. Owner ruled on 08-18 (rule 42) that the board is the pipeline's main view with Trello-grade cards; the ledger sits behind a switch and the choice persists per user.
  * The stage-taxonomy conflict is stated against the wrong pair. The live ladder is sourced · qualified · outreach · replied · call booked · audit · proposal · deposit (pipeline.tsx and orgs.tsx), not the mock's lead/call/proposal/pilot/retainer. Reconciliation is live-ladder vs ARCH-0059, and the live one adds `audit` and drops call_held/delivering.
  * DESIGN-APPS §3/§10 atom vocabulary is partly superseded. The instrument eyebrow is dead everywhere by owner ruling (rule 42, ruling 1 — "AI slop sign"); provenance is one quiet meta-line (`Antevon · as of 14:07`) or a hover title. Residue still to sweep on this surface: src/routes/app/lens/supplier-watch.tsx and src/styles/lens.css still build an eyebrow region, as do threads.tsx/recall.css.
  * "Prototype the most interactive lens before locking the kit" (ARCH-0010 / dashboard-v2:c) is done, not open. The pipeline is the interactive prototype: hand-rolled pointer drag with ghost and edge autoscroll, keyboard stage moves, live search, stage filters, unfold-in-place — and tables elsewhere are sortable/filterable per rule 42, all with no dnd-kit, no Tailwind, no shadcn.

===== 06-office-pack =====
[BUILT] Sentence-level citations, click → claim → evidence → receipt
    Built in `src/routes/app/notes.tsx`: cited spans are typed runs (`c(text, id, conf, learned)`) rendered as dotted `a.cite` doors whose ink is the confidence ladder (`rung()` → conf-1..4), reused by `briefs.tsx` across five claim-citing briefs. Delta: every cite navigates to `/app/vault` with no claim id, so the OF-235 trail ends at the ledger, not at the record.
[NEW-OPTION] Hover peek (quote excerpt, ink, date, lifecycle) instead of a raw URL
    Today the hover depth is the native `title` string from `citeTitle()` — `cl_44b1 · 0.91 · learned 2026-06-24 · open the claim in the vault` — per the lane law 'every mono token is a door, the title tells the truth'. A real peek card is a new kit element, so it is an owner pick: title-only as built · a small peek card on the cite · ink alone with depth only in the vault.
[REJECT] Markdown LoroText is the file; rich marks are decorations; PM/TipTap JSON never stored
    Storage-layer law (decision-ledger D1), not a mock surface. The lane already cannot violate it: the Doc engine stores blocks of typed runs, and `onPaste` forces `text/plain` with line breaks folded to spaces, so no foreign markup can enter a document.
[BUILT] Typos in cited sentences are body edits, never supersede_claim
    Editing a block rewrites `runs` and the cite ids ride along on their spans (`serialize()` reads `a[data-cite]` back); no supersede path exists from a document. `supersede_claim` lives only as a vault-inspector act (`vault.tsx:944`).
[CONFLICT] AI mint = retained output, user Accept/Reject, never in-place clobber
    Canon side: D2/OF-233 gated write + Proposed lane, OF-368 retained output, and the fixture prose itself ('edits to protected notes land as proposals'). Lane side: owner ruled 08-18 the Proof model — agents use the SAME operations as people, so an agent edit lands in the body wearing the agent's ink, `unread` until you click `read`, with the `history` fold as the trail (rule 42). There is no reject or undo for an agent's edit today.
[NEW-OPTION] Word-level suggest / track-changes with per-hunk accept/reject
    Not built, and it cuts against the ruled 'editable by default, no edit button' simplicity. Owner pick: per-block diff inside the existing `history` fold · word-level suggest marks you accept · nothing beyond the ink-until-read treatment as built.
[BUILT] Extracted proposals land in a grouped triage inbox, not a badge count
    `src/routes/app/inbox.tsx` groups by run: `Antevon run` (rx_7b12, 2 wait, '40 more' as a door), `Eiri session`, `prepared work`, paused run — accept/reject inline per row, counts hidden while a bundle is open (inbox.css:69-70, rule 16). No snooze verb exists.
[NEW-TAKE] Orphan / unanchored citations visible — strikethrough, shelf, re-anchor
    The visible half is a real S-effort gap: `.superseded` (opacity .45) and `.retracted` (line-through) live in `safelight.css` and are used by vault/pipeline/recall, but `rung()` maps confidence only, so a document renders a retracted claim as live prose. The orphan *shelf* itself is premature — the mock has no anchoring engine to orphan anything.
[REJECT] Tufte margin sidenotes carry the first source beside the sentence
    The 96px left gutter is already spoken for: per-block provenance (who wrote · who edited) rests there, ruled 08-18, and citations are inline dotted doors. A second marginalia column would double the margin and re-open a ruled shape.
[NEW-TAKE] Narrow viewports: the margin collapses to a toggle / bottom sheet
    Genuine gap. `notes.css` and `briefs.css` carry zero `max-width` queries while vault (1400px), orgs and pipeline (1100px) do; the 96px gutter and the 68ch measure are unconditional at every width.
[NEW-OPTION] Share is receipted and revocable; recipient scope redacts live
    Owner ruled the affordance (share = an icon, 08-18) and `ShareAct` copies `location.href` with a quiet 'link copied' line — no receipt, scope or revoke. What the icon opens is a product call: copy-link as built · a small sheet (who can open · scope · revoke) · the share landing as a row in the `history` fold.
[REJECT] Six NOTE kinds with per-kind extraction / context / retention surfaced
    Power-user config, hidden by normal-person-first. The mock carries `kind?: 'digest' | 'handoff'` as a hover word on agent-written notes only, and retention/deletion already has its home at `/settings/export` and `/settings/forget`.
[NEW-OPTION] Office blobs (xlsx/docx/pptx): anchored comments → task-brief → receipted edit (OF-368 SHIPPED)
    No file or artifact door exists anywhere in the app mock — no route, no rail row, no inbox row. Whether the workbench opens real files at all is an owner product call, and it is L effort once picked.
[RULED] DESIGN-APPS cream instrument `{surface}` #F4F0E6 vs the film-black desk
    Rule 37 killed both sides: theme follows the system through one `light-dark()` token block, day = cream sheet on a darker desk, night = deep night room, contrast parity verified in both. The brief audits a direction that died on 08-13.
[CONFLICT] DESIGN-APPS §11.6 bans a chat sidebar ('agent IS the app')
    Canon side: §11.6 forbids a chat sidebar. Lane side: the ground chat panel is fixed furniture, and the 08-18 selection toolbar in `notes.tsx` (`hand to Eiri` · `hand to Tory` · `ask Antevon`) exists to hand words into it via `openChat()`. Not resolved here.
[CONFLICT] ARCH-0048 G6 names Next App Router + React + Tailwind on the render_instrument adapter row
    Docs side: G6 (accepted) still names Next + Tailwind and 'shadcn dead'. Lane side: React 19 + TanStack Start with bespoke CSS per surface. The office pack must not drift onto Tailwind to match G6; the docs row is the one that is stale.
  -- top_new --
  (S) Deep-link a cited span to its claim record
      Every cite in notes and briefs (and `Promise_`'s clocks) navigates to `/app/vault` with no id, so the citation trail ends at the ledger and the reader has to hunt. The vault already keeps `sel`/`open` inspector state; it just has no search param to seed it. This is the load-bearing half of OF-235's peek → sheet → rail → page.
  (S) Carry lifecycle ink onto cited spans inside documents
      `.superseded` (opacity .45) and `.retracted` (line-through) are already tokens in `safelight.css` and are used by vault, pipeline and recall, but `rung()` in `notes.tsx` maps confidence only. A brief today reads a retracted or superseded claim as live prose — the exact forgery ARCH-0032b `#render` forbids, and the fix reuses tokens that exist.
  (M) Revert one block from the history fold
      The 08-18 Proof ruling lets an agent edit land in your prose in place; `read` only settles the ink, and nothing can put the old words back. `TrailFold` rows already carry when · who · what · ¶, so the revert has a home and needs no new element. It is the safety valve that makes the ruled in-place model safe without re-opening it.
  (S) A narrow-viewport rule for the provenance gutter
      `notes.css` and `briefs.css` have no `max-width` query at all, while vault (1400px), orgs and pipeline (1100px) do — the 96px gutter and 68ch measure hold at every width, so the document surface is the one pane with no small-screen behavior. Collapsing the gutter (provenance falls back to its hover title) matches what the other panes already do.
  -- corrections --
  * OF-225 'unbuilt (0 hits)' and DESIGN-APPS §13 'brief renderer specified, unbuilt' are stale for this lane: `src/routes/app/briefs.tsx` (674 lines) renders five claim-citing briefs with confidence ink, agent byline, fixed nodes (who's in the room, the promise + two clocks, receipt ledgers, numbers, acts), trail, share and mark-read — composed at view time, never stored as HTML. It is fixture-driven rather than markdown+claim-refs, but the surface is not zero.
  * The cream-vs-film-black CONFLICT audits a dead direction. Rule 37 (08-13) replaced both with system-following two rooms — day cream sheet on a darker desk, night deep room — from one `light-dark()` token block with contrast parity in both.
  * 'No Tailwind' is nearly true, not literally: `tailwindcss` is a dep and `src/styles/app.css` line 1 imports it, kept only for the scaffold's catch-boundary and not-found components. Every lane surface is bespoke CSS in `src/styles/*.css`. The G6 conflict itself stands.
  * Study-never-import is already satisfied on the editing substrate: there is no Tiptap, ProseMirror, Loro, Hypothesis or diff library anywhere. The Doc engine is hand-rolled contentEditable in `notes.tsx` — blocks + typed runs, plain-text paste, caret restore, split/join/cite, serialize-from-DOM.
  * The brief treats notes and briefs as two builds; the lane made briefs a consumer of the notes Doc engine (`briefs.tsx` imports `Doc`, `seal`, `P/H/LI/LEAD/NODE`, `TrailFold`, `ShareAct`, `HistoryAct` from `./notes`). Any office ruling propagates to both from one file.
  * Agent-proposed *tasks* do not land in the inbox. They land on `/app/tasks` as hollow-bullet `proposed` rows with accept/skip (`tasks.tsx`), while the inbox holds proposed claims and drafts grouped by run. ONE-1183-D2's run-grouping is honored for claims, not for tasks.

===== 07-channels-threads. The lane has built more of this surface than the brief assumes, and split it in two: `/app/threads` (channel identities as revocable grants + one thread stream with a pending→verified→receipted send ladder + per-send receipt records in the context column + "promote this thread" → one review bundle in the inbox) and `/settings/connectors` (Slack · LINE · email · LinkedIn-not-connected, connect-a-workspace, revoke → receipt line), the latter created by the 08-18 settings-area ruling. The consent/send grammar the brief calls table stakes — draft-then-approve, member edits the proposed draft in place, click is the consent, no undo, no toast, receipt proves accept and never `seen` — is already built in the inbox draft row (`inbox.tsx` DraftCard + the message it answers + "or tell Eiri what to change…" reply line). What is genuinely missing is *channel truth at the point of send*: no surface shows which address/face is on the envelope before the click, no absent-verb honesty (LINE cannot react/edit/retract), no character or reply-window limit on the composer, no snooze/schedule/assignment, no draft-ownership or collision model, no internal notes. The brief's biggest structural idea — Zulip topic-first grouping so group decisions stay findable — lands directly on an owner pick that is already open (rule 42: threads chat-first vs history-first, rec chat-first) and should ride it, not be decided beside it. Most of the STEAL list is engine mechanics (envelope split, draft key, ack-first, durable intent) with no UI consequence in a fixture mock. Note: `threads.tsx` is dated 08-15 and is the one page the 08-18 pass deliberately left alone — it still carries an eyebrow (`antevon · as of 14:07`, `threads.css` `.tsec > .label`) that rule 42 killed everywhere else; the chat-first rebuild clears it. =====
[BUILT] One inbox, many rails (ARCH-0063 R4 lens)
    `/app/inbox` is the lens: bundles in impact order, per-row channel glyphs (LINE/LinkedIn/Slack), a today wire section of everything that crossed a channel. Delta from the brief: only a waiting/show-all toggle, no status/assignee/identity/label filters — the 08-18 interactive-table work (sort, per-column filter, search via `useLedger`) landed on the ledgers (vault, connectors), not on the inbox, which is bundles rather than a table.
[BUILT] Receipts, not read-receipts (accept, never seen)
    `threads.tsx` send ladder is pending/verifying → verified → receipted; the context-column receipt carries message id (`sm_7c2e`), audience, sent-by-your-click, delivered/verify, and what it cited. Nothing anywhere claims `seen`; LINE inbound is the only row that says `read`, which matches ARCH-0046's honest read-signal.
[BUILT] Draft-then-approve composer (Gmail drafts→send, LinkedIn ToS R3, no engine undo)
    `inbox.tsx` draft row shows the message it answers, an editable textarea in the agent's ink, send beside it (`verb: send_message · your click is the consent`), plus a natural-language change line. No undo-send and no retract verb exists anywhere in the lane — the brief's warning is already the built posture.
[BUILT] Sticky sender / channel identity as a grant
    `/app/threads` identities ledger = one identity per channel, each with charter, scope line, receipts door and revoke that settles into a receipt in the row; `/settings/connectors` carries the same rows plus LinkedIn connect/revoke. The half the brief asks for that is NOT built: no send surface displays the From identity before the click (see NEW-TAKE).
[BUILT] Answer to Slack thread-burial (decisions vanish in threads)
    `promote this thread` queues one review bundle into the inbox (`queue_review_bundle`) and the quiet line reads "Durable decisions live in the vault"; thread entries door into minted claims (`cl_9f21`). The lane's answer to burial is promotion-to-vault, not a better chevron.
[RULED] No notification toasts (CROSS-ARCH-0016 draft)
    FLOWS §4 build law: "no toasts (records)"; rule 42 outcomes settle in place (revoke cools into a receipt line). At the UI layer the disposition is closed even though the docs-canon disposition is still formally open. `dr:focus-c8-ack-first` is correctly read as adapter ack, never a user toast.
[CONFLICT] DESIGN-APPS §5 interaction ladder (hover=peek → click=centered sheet → dock=rail → enter=page)
    Brief/canon side: DESIGN-APPS §5 line 90 makes the centered sheet the default inspector. Lane side: rule 31 (08-15) replaced it with a docked context column inside the sheet, and rule 39 is OPEN with three candidate open-laws (gesture · column · kind) switchable in the tuner, owner adjudicating. Threads already ships the column (`aside.context`); no centered-sheet inspector exists.
[NEW-OPTION] Topic-first group grammar (Zulip topic on the message, linear DMs/email)
    Genuinely new and the brief's strongest structural idea, but it collides with a live owner pick: ADJUDICATE-20260818 asks threads chat-first vs history-first (rec chat-first) and rule 42 lists it as pending. A named topic/passport key for group rooms is exactly the thing chat-first would otherwise lose — it should be offered as part of that pick, not decided beside it.
[NEW-TAKE] Capability-vs-permission honesty per connector (LINE has no react/edit/retract; Slack mark_read lies)
    The lane shows permission only (`scope: inbound.read · no send verb granted`); it never shows what the channel structurally cannot do. One quiet absence line per connector row is S effort, fits "title tells the truth", and forecloses the uniform-no-op anti-pattern at the UI layer before anyone builds it.
[NEW-TAKE] Composer shows channel limits / reply window before send
    `DraftCard` is a bare textarea with no count and no window. LinkedIn 1900, LINE 5-message batch, LINE replyToken ~1 min are all send-time truths the click-is-consent model owes the human. Quiet meta under the field, no red until it actually blocks.
[NEW-TAKE] Show which face is on the envelope before send; refuse silent From flips
    The brief calls this UX-only because sticky-sender is canon (ARCH-0063 R5 / ARCH-0059) — but no send surface in the lane displays it. The inbox draft row shows the channel glyph and the authoring agent (Eiri), never `as @antevon` / `ops@antevon.jp`. One line on the draft card closes it.
[NEW-OPTION] Draft ownership + collision (Front policy, Chatwoot presence/typing/banner)
    Nothing in the lane models who holds a draft: no presence, no typing, no lock, no take-over. Members exist (`/settings/members`) and the fixture cast is multi-seat (o, Yuki), so the question is real, but the answer is a product choice — full presence infra vs one quiet holder line on the draft ("Yuki is holding this reply"). Owner pick.
[NEW-OPTION] Snooze / schedule / assignment as first-class (Missive Send & Snooze auto-cancels on reply)
    No defer, snooze, wake, schedule or assignee verb exists anywhere in the inbox or threads. `OF-402` snooze-with-wake is canon and currently invisible. Adding a row verb touches rule 30 (auto-accepted means no bundle verbs) and the pending Things-3 tasks rebuild, so it is an owner call, not a free take.
[NEW-OPTION] Internal notes that cannot leak to the counterparty
    Unbuilt. The lane's plausible native answer is that the vault and `/app/notes` already are the internal layer, so a thread-scoped private note may be a duplicate surface — or the missing piece that keeps working talk out of the channel. Owner pick, not taste-invention.
[REJECT] Engine-side steals: envelope split + typed sidecar, per-conversation draft key, ack-first adapter, durable intent-before-attempt, LINE retry key
    All correct and all already canon (`OF-247`/`OF-327`, ARCH-0046 O6, `dr:focus-c8-ack-first`); none has a visible consequence in a fixture mock. The one UI consequence that matters — a draft has exactly one home and never silently double-lives — is already true in the lane (the draft lives in the inbox row, nowhere else). `OF-060` not shipped is an engine blocker, not a mock blocker.
  -- top_new --
  (S) Absent verbs as honest absences on each connector row
      The lane shows permission (`no send verb granted`) but never capability. Naming what LINE structurally cannot do (react, edit, retract) at the one place a human grants reach kills the uniform-no-op anti-pattern before any adapter exists, and it reads as the lane's own voice, not a matrix dump.
  (S) Envelope truth on the draft card: the From identity + the audience above the send
      Sticky-mask is canon but invisible exactly where the consent click happens. Today the inbox draft shows the channel glyph and the authoring agent, never the address the recipient will see. One line makes the click informed and makes a silent From flip impossible to miss.
  (M) Named topic key for group rooms, offered inside the pending chat-first threads pick
      Chat-first is the owner's rec and is the shape that buries decisions worst. Zulip's answer — the topic lives on the message, so later replies stay findable — is the one borrowed idea that changes the thread's structure rather than its skin. It belongs in the open pick as a third option, not as a decided shape.
  (S) Send-window and limit truth on the composer
      Click-is-consent owes the human the constraints of the channel at the moment of the click: LinkedIn's 1900, LINE's 5-message batch, the ~1 minute reply token. Quiet meta under the field, no red until it genuinely blocks — same register as the existing scope lines.
  -- corrections --
  * The brief treats DESIGN-APPS §5 as live interaction canon ("hover=peek / click=sheet / dock=rail / enter=page"). The lane superseded it: rule 31 (08-15) put a docked context column inside the sheet, and rule 39 leaves the open law explicitly OPEN with three candidates switchable in the dev tuner. No centered-sheet inspector exists on any route. Auditing send/receipt surfaces against click=sheet audits a dead direction.
  * The brief's channels picture is one page (`app-channels.html`). Since the 08-18 settings-area ruling the surface is two: `/app/threads` (identities + the thread + receipts column) and `/settings/connectors` (Slack · LINE · email · LinkedIn-not-connected, connect-a-workspace, revoke → receipt). Connector state, not the thread page, is now where a channel is granted or cut.
  * `/app/threads` is the one page the 08-18 review pass deliberately did not rebuild (file dated 08-15). It still carries an eyebrow — `antevon · as of 14:07`, styled at `threads.css` `.tsec > .label` — which rule 42 killed globally. So "as built" in the ADJUDICATE-20260818 threads question means pre-review code; anything the audit reads as current threads styling is provisional and the chat-first rebuild clears it.
  * The brief lists `CROSS-ARCH-0016` vs notification-free as an open conflict needing disposition. In the built lane the UI half is already closed: FLOWS §4 carries "no toasts (records)" as a standing build law and rule 42 has outcomes settling in place as receipt lines. The docs-canon disposition remains formally open, but no UI decision waits on it.
  * The brief treats sticky-sender as canon and asks only to steal the UX. In the lane the UX is the missing half: identity-per-channel is visible on the threads ledger and the connectors ledger, but the two surfaces where a send actually happens (the inbox draft row and the consent ask) show the channel glyph and the authoring agent only — never the sending address. The steal is larger than the brief implies, not smaller.

===== 08-agents-page =====
[BUILT] Roster with identity + state
    `src/routes/app/agents.tsx` roster: face in the agent's ink, name, one-line role, channel glyphs, state word (live/paused/schedule/draft); the glance under a row adds holds, spend-today, last run. Deltas from the brief: no base-model badge on the row (model sits in the sheet top only) and no default/pinned marker.
[CONFLICT] Simple card + expert surface, no wizard
    DESIGN-APPS §5 says roster rows settle in a sheet and expert knobs DOCK (rail); the owner ruled 08-18 (FLOWS rule 42) that the agent opens as a FULL sheet replacing the roster, with `+ new agent` opening the same sheet empty. Both agree on no wizard (RESEARCH-0200G) — that part is built.
[BUILT] Grant slate on the agent (allow-once / standing / revoke)
    Sheet `scopes` section: verb, scope tip, human seal, grant date/expiry tooltips, two-tap armed revoke + restore; the living ledger with receipts, expiry and state chips is `src/routes/settings/grants.tsx`. Deltas: no allow-once rung (standing only), and grant *minting* is circular — grants.tsx says grants are minted on the agents page, the agents sheet's empty state links back to /settings/grants.
[BUILT] Per-agent spend gauge + cap
    Sheet budget ladder (¥300/¥600/¥1,200, `local · no cap` for the house mind) plus `¥170 today`, roster-wide `¥280 today` in the runs head, and meters at /settings/billing + /settings/usage; the cap pauses rather than bills past, stated in the tooltip, so the blocking reason is already a receipt not a toast (no-toast law). Open tension: ARCH-0026 says budget is per tenant and the tenant ceiling is not shown on this page.
[CONFLICT] Run history = door, not a console
    Brief/canon (ARCH-0026, OF-193 IN_BUILD, OF-239 as the live runs panel, surface 9) say the agents page owes only last-N-runs + open-in-Runs; the built lane has a full `runs` view here — live rows with world/elapsed/tokens/cost and stop-settles-in-place, plus a sortable `Earlier today` ledger with receipts and wake reasons — and no separate runs route exists in the app. The owner's 08-18 ruling demoted runs to a toggle but did not move them off the page.
[RULED] Two-plane roster (house mind vs companion)
    FLOWS rule 15 + the naming scour ratified @Company house mind (Antevon) and @Name companions. Built as behaviour, not as typed planes: Antevon is special-cased to `always on`, local model, no cap, and `ask` instead of `chat`, but the roster is one flat list with no plane grouping or label.
[NEW-TAKE] Addressing is the claim / anti-snitch default on the agent
    ARCH-0065 §4's promise is currently prose on /settings/connectors ("It never opens a thread on its own") and only implied by the sheet's schedule ladder; the agent's @-handle and the addressed-not-ambient default appear nowhere on the roster or the sheet where you configure it.
[NEW-OPTION] Base-model picker per agent + fallback tell
    Model is display-only on the sheet (`kimi-k2.6`, `qwen3-4b` with a cost/locality tooltip) — no picker, no fallback-when-base-is-down state. Whether a normal person picks models at all collides with the normal-person-first law, so it is an owner pick, not a default yes.
[NEW-OPTION] MCP/tools binding + skills bindable on the agent
    Not built: the lane's nearest primitives are per-agent `channels` (LINE/mail/Slack/LinkedIn) and vault-level packs at /settings/packs; there is no MCP server row, per-tool expansion, or skill binding anywhere in the app despite ARCH-0028 (OF-205 SHIPPED) and ARCH-0053. Whether the sheet grows a tools/skills section or capability stays implied by packs + grants is a real product call.
[REJECT] Knowledge collections on the card + instructions-vs-knowledge precedence sentence
    Attaching knowledge collections to an agent is the RAG-app shape; Oneiron scopes reach with world grants (`read.world:clients`) over one vault, so it is not-ours. The precedence sentence is moot by construction — there is exactly one place per agent (`what it does` + `voice`) and no workspace-level prompt exists in the app, so the three-places-for-one-prompt bug cannot occur.
[NEW-TAKE] Hide ≠ default + explicit default agent
    Pause exists on the roster and sheet, but `Ground.tsx` hardcodes the agent-line switcher list (eiri/tory/antevon) and defaults `chip` to `eiri`, so a paused agent stays pickable and stays the chat default — the exact Open WebUI anti-pattern the brief names. There is also no way to say which agent the chat opens with.
[NEW-TAKE] Connection verification before/after binding
    The sheet's channel chips are free local toggles: LinkedIn can be switched ON for an agent while /settings/connectors reads `not connected`, and revoking a connector leaves the agent's chip lit. This is the GPT-Actions-vanishes / MCP-offline class the brief flags; the fix is a quiet state on the chip sourced from the connector row.
[NEW-TAKE] Clone / export / version history
    Clone and export are thin here (export is vault-level at /settings/export), but version history is worth taking: config edits stamp an ephemeral `saved · hh:mm` per section that vanishes on reload, while the lane's own law is that every change carries a receipt, and ARCH-0053 forbids terminal deletes.
[CONFLICT] System vs custom fork law; hide ≠ delete
    OF-334 canon (EF-155) says system agents are toggleable seeded rows and editing one FORKS to custom; the built lane edits the three seeded agents in place with no fork and no lineage. Related gap on the same axis: there is no archive or delete at all — a created agent can only be paused, and an unnamed new agent silently vanishes on sheet close.
[REJECT] Compiled resolved context + roster-version fence (QM / RESEARCH-0319)
    Engine concern, not chrome — 0319 itself says the fencing UI is unspecified, and a fixture mock cannot demonstrate a compile-once context pipeline. The one UI residue worth keeping is small: the sheet is editable while a run is live, with nothing saying which setup the running run is on.
  -- top_new --
  (S) Roster state drives the agent-line switcher, plus a default marker
      A paused agent stays pickable and stays the chat default (`Ground.tsx` hardcodes eiri/tory/antevon and defaults to `eiri`) — the exact hide-still-default bug the brief cites with practitioner evidence. Wiring the switcher to the roster's configs and marking one agent default closes it and fills USERS-EXPECT #2 and #3 at once.
  (S) Connector health on the agent's channel chips
      An agent can be bound to LinkedIn while settings says `not connected`, and a revoked connector leaves the chip lit — silent capability loss, the GPT-Actions/MCP-offline failure class. One quiet state line per chip, sourced from the connectors fixture, with `connect` already present as a door.
  (M) Setup change receipts on the agent sheet
      Config edits currently leave an ephemeral `saved · hh:mm` and no record, which is off-key in the one app where every act ends in a receipt; a `history` fold on the sheet (who changed what, when) matches the editable-docs model ruled 08-18 and ARCH-0053's no-terminal-delete lineage.
  (S) @-handle and the addressed-not-ambient line on the sheet
      ARCH-0065 §4's anti-snitch default is the load-bearing social promise of the whole roster, and it currently only exists as prose on the connectors page; naming the handle and the default where the agent is configured makes the promise visible at the point of trust.
  -- corrections --
  * The brief's "DESIGN-APPS §13: no Agents-page mock" is stale: a full agents page is built and has been owner-reviewed twice (08-15, 08-18) — <workspace>/Desktop/code/oneiron-web/src/routes/app/agents.tsx, ~1,456 lines, with roster, glance, full sheet, and a runs view.
  * The brief's "Agents page chrome is unnamed — no ARCH page specifies the roster list, expert-disclosure split, or where model/budget badges live" has been overtaken: FLOWS rules 41-42 and the two ADJUDICATE packs name it. Model + last run sit as one meta-line in the sheet top; budget is a rung ladder plus a spent line.
  * The brief's "per-agent spend UI is a product gap, not a ruled primitive" is wrong for the lane: per-agent day caps are a first-class control on the sheet (¥300/¥600/¥1,200, local = no cap) with a roster-wide day total, and the owner reviewed the page without objecting. The unbuilt half is the ARCH-0026 tenant ceiling on this page, not the per-agent gauge.
  * USERS-EXPECT #1's "avatar" is a moving target here: the pixel creatures the brief would find were RETIRED on 08-18 (rule 42) in favour of a riso stamp masked and filled with the agent's own ink. The roster face is an owner pick in flight (portrait · mark · none, tuner switch) and out of scope for this audit.
  * The brief treats DESIGN-APPS §5's "hover=peek, click=sheet, dock=rail" as settled grammar; in the lane the row-open law is OPEN (rule 39) and switchable live in the dev Tuner (gesture · column · kind) pending owner adjudication, so any recommendation keyed to click=sheet is premature.
  * The brief's "toasts rejected; consent-grade interruptions only as true modals" understates the house law: no toasts anywhere ever, quiet inline cues only, and no small-caps eyebrow lines (owner 08-18). So the STEAL bullet "blocking reason must be a receipt, not a toast" is already standing law, not a new steal.

===== 09-runs-console =====
[BUILT] Steer / pause / stop at a safe breakpoint
    FLOWS rule 34 + Ground.tsx: the composer IS the Steer Signal (placeholder `steer <agent>`, never a Send/Stop swap), `pause` parks the branch and `stop` settles it midway as run-head verbs, the thread stays live and the next message resumes it; agents.tsx Now rows carry open/stop with `stopped at its next breakpoint`. Deltas from the brief: no separate `interject` verb (the message is the steer), and answer-consent is not a run verb — it lives in the inbox.
[CONFLICT] OF-239 mission-control panel / run tree as the product surface
    Canon: ARCH-0026 §run-tree 'the run tree is the product surface' and OF-239's live mission-control panel. Lane: rule 20 killed the mission-control door ('the rail's agents row is the one door') and the 08-18 review demoted runs to a `setup ⇄ runs` toggle inside Agents, with live presence on the ground line. Both sides stand; not resolved here.
[NEW-OPTION] Tree + Timeline peers, aggregated-first loops, typed nested spans
    No run-detail surface exists at all — every `receipt` door in agents.tsx and inbox.tsx is `href="#"`, and no fixture has branches, subagents or steps. Real shape choice for the owner: (a) a full sheet like the agent sheet with flat receipted steps, (b) the context column as the run record, (c) a tree ⇄ timeline switch with aggregated-first loops and collapsed subagent groups.
[RULED] needs_input as a Decision Prompt card, not a toast
    No-toasts is global law; the consent ask is an inbox row with allow/deny visible at rest (rule 11b) inside a live agent-session bundle carrying a throbber. The card shape from CROSS-ARCH-0009b would break the lane's card law (rule 6 / cards DECIDED 08-13): flat sections, one-line rows, cards only where a document-object earns one.
[BUILT] OF-211 exit bundle distinct from mid-run ask
    inbox.tsx carries a `paused import` bundle: run rx_9a04, the burst guard stopped it at 180 writes, nothing landed, verbs `review bundle` · resume_run · cancel_run — structurally separate from the live Eiri session's drafts and consent ask.
[CONFLICT] OF-234 grouping by run root + bulk verbs
    Grouping is built (inbox bundles headed by the run: Antevon run rx_7b12, the Eiri session, the paused import). But OF-234's bulk accept-all / reject-all / review-each were ruled dead 08-15 (rule 30: auto-accepted means no bundle verbs; `40 more` is a quiet door) — registry says bulk lifecycle, ledger says the count is a door.
[BUILT] Cost / latency rollup on the run
    Now table columns world · elapsed · tokens · cost; day roll `¥280 today · as of 14:07`; per-agent budget ladder with cap ('the cap pauses the agent, it never bills past it'); billing/usage got its own door (ruling 6). Kind-aware rollups have nothing to attach to — there are no spans yet.
[NEW-TAKE] Missing run states: `waits on you` and cap warning
    The Now row knows only live vs stopped, so a run parked on a consent, or one crossing its day cap, reads as normal. Add a stilled `waits on you` state (door to the inbox item, one home per item) and a warn-ink cost cell + `paused · cap` roster word. Matches UE3 wait-as-first-class and defuses the Grok quota-blind anti-pattern.
[NEW-TAKE] Status / type filters + search on the runs ledger
    Rule 42 already ruled tables interactive and vault.tsx implements the whole column-def filter/search/keyboard pattern; the runs ledger in agents.tsx only sorts its heads. Port the same chrome (by agent · by wake · waited > 0 · search-as-you-type).
[NEW-TAKE] Follow-newest / pause-live / back-to-live
    FLOWS' open list already names 'jump-to-latest + line badge' as a remaining chat table-stake. Take jump-to-latest in the run-scoped panel (auto-follow pauses when you scroll up, a quiet door returns). A third named Pause-live control is over-chrome for a 400px panel with one run.
[NEW-TAKE] One terminal-status contract (DF01)
    The UI invents its words per page (live · paused · stopped · draft · `2 wait` · schedule words). Stamp one map module: queued|running|waiting|completed|failed|cancelled|timed_out|polling_timed_out|abandoned → the lane's minimal-copy word + ink, read by agents, inbox, today and the ground line.
[BUILT] Contextual presence, never a permanent agent sidebar
    Ground line + floating chat panel (rules 19, 28, 35); rule 36 makes the name-in-ink the presence mark and the doing-text shimmer the liveness (separate dot dead). dr:DF04 and DESIGN-APPS §11.6 are honored; today.tsx and agents.tsx only knock on the panel via `oneiron:chat`.
[NEW-TAKE] Context receipt door — what the run saw
    Write-side provenance is everywhere (claims carry source and confidence, notes carry per-block provenance, the palette answer shows what it stands on); read-side is absent. From a run row, a `what it read` door beside `what it wrote` — OF-369 + H0640-2 in the lane's own provenance grammar.
[RULED] Sessions vs runs — one grouping key
    The run root is already the key: inbox bundles head on the run, the ledger keys on run ids (rx_*), and no second id scheme was invented. GROUP BY AGENT is an open owner pick already sitting on the FLOWS open list ('recommendation given, his pick pending').
[REJECT] Structural gates · episodes-as-return-values · device-unreachable degradation
    All three are engine-plane invariants (ARCH-0026 residence, CROSS-ARCH-0009b, ONE-1184-D2) with no chrome to build in a fixture mock that has no runner or sync plane; the steal register already carries them. Revisit the stale-tick honesty line only when live data lands.
  -- top_new --
  (M) The run record behind the receipt door
      Every `receipt` / `open` door on a run row and inbox bundle is `href="#"` — the lane's one dead end on this surface. It should carry what the run read (OF-369 read-trace), what it wrote, its wake class, its cost and its breakpoints. Shape is a real choice (sheet · context column · tree ⇄ timeline), so it goes to the owner as options, not a decided form.
  (S) Third run states on the Now row
      A run is only live or stopped today, so a branch parked on a consent, or one that hit its day cap, reads as healthy. `waits on you` (stilled, door to the inbox item) and a cap warning close the honesty gap without new chrome.
  (S) Filters + search on the runs ledger
      Rule 42 already ruled tables interactive and vault.tsx has the full implementation; the runs ledger sorts only. Pure port, no new taste.
  (S) Jump-to-latest in the run-scoped panel
      Already named as an open chat table-stake in FLOWS; the external evidence (Temporal had to add Pause) says auto-follow during a read is unusable. Two states — auto-follow, and a quiet door back — fit the 400px panel.
  -- corrections --
  * The film-black vs cream `#F4F0E6` token conflict the brief flags is a dead premise: rule 37 settled two rooms, one token block under `light-dark()`, contrast parity both ways. Nothing to relitigate or flag.
  * 'Engine shipped, surface not — the gap is chrome + live-tail + aggregation' is stale as of 08-18. The steer/stop/pause chrome (rule 34, Ground.tsx), the live agent line, the Now table and the receipted run ledger are all built in oneiron-web. The remaining gap is narrower: run-detail (per-step trace) and live-tail controls.
  * The brief audits toward a standalone mission-control console. The lane killed that door (rule 20) and made runs a `setup ⇄ runs` toggle inside Agents (rule 42 / ruling 5); presence lives on the ground line. Chrome recommendations should be sized to that shape.
  * OF-234's bulk accept-all / reject-all / review-each were ruled dead on 08-15 (rule 30) for auto-accepted bundles — `40 more` is a quiet door instead. Only the paused-run bundle keeps `review bundle`.
  * 'Decision Prompt card' would break the lane's card law (rule 6 + cards DECIDED 08-13): bundle items are one-line rows on flat sections; the five 0009b states are engine vocabulary, not chrome.
  * No fixture in the lane has branches or subagents — one flat run per agent. Brief items keyed to branch-level chrome (per-branch Query strip, branch pause, loop aggregation, collapsed subagent HUD) have nothing to attach to yet; they are questions about the run record's shape, not deltas against what exists.

===== 10-recall-command =====
[BUILT] One global keystroke opens/toggles the palette, restores prior focus; always-visible ⌘K hint
    `useCommandKey('k')` fires even inside a focused field, `/` via `useGlobalKeys` (guarded against INPUT/TEXTAREA/contentEditable), rail search icon knocks with `oneiron:palette`; `cameFrom` restores focus on close (Palette.tsx:183-202, route.tsx:33-52, hooks.ts:321-345). Hint is the hold-⌘ ShortcutSheet (600ms, 8 rows) plus the icon's title, not a persistent chip — minimal-copy law.
[RULED] One sheet, two modes, no second Quick-Open modal
    Rule 42 (08-18): one card, Raycast model — pages · claims · acts AND a permanent ask row; `/`, ⌘K and the vault-name icon all open the same card. The lane's second mode is ask-AI (list → thinking → answer with `open in recall` / `ask in chat` doors), not the brief's goto-vs-command split.
[BUILT] Grouped heterogeneous results with icons separating records / actions / navigation
    `groups` builds runs of pages/claims/acts with a quiet `label` head; pages and acts carry icons, claims carry confidence ink (`conf-1..4`) instead (Palette.tsx:259-327, 390-396). Acts show live state in the mono meta slot (theme glyph, sound on/off).
[NEW-OPTION] Typed filter prefixes (`c ` claim, `e ` entity, `w ` world, `! ` command)
    Not built: the filter is substring over title+keys, with a group-name match only from 3 letters (Palette.tsx:329-341). Prefix grammar is a real front-door choice — owner picks between Linear prefixes, typing the group name (as now), or neither.
[CONFLICT] Result grammar: type chip + ≤600-char snippet + world badge + relative age + provenance chip per row
    Brief wants a chip-rich row (A72/OF-219). The lane ruled the opposite register: rule 42 kills eyebrow/instrument chrome as an AI-slop sign, build laws say labels are a last resort and no chip zoo, and the group head already types the row. World and age on claim rows are the only genuinely missing facts (recall's cut ledger carries both; the palette's stands list carries neither).
[BUILT] Full keyboard walk (↑↓, Enter, Esc, Home/End, ⌘Enter secondary)
    All present with wrap-around and `scrollIntoView({block:'nearest'})`; Esc peels the answer before the card; combobox a11y is complete (role=combobox, aria-controls, aria-activedescendant, listbox/option/aria-selected). Ctrl+N/P and j/k are rejected — `/` is already a bare key and vim rows would collide with typing; no `aria-modal`, correctly, since this is a floating card with no backdrop.
[NEW-TAKE] Value-stable selection instead of index-based (cmdk fix for the kbar activeIndex bug)
    Selection is a flat index (`sel`, `data-i`, `prow-${i}`) clamped to the list length (Palette.tsx:166, 353, 361-388). Safe while filtering is synchronous, but the ask path is already async and any engine-ranked hits will reorder rows under the caret. Key selection to item id — S.
[NEW-TAKE] IME `isComposing` guard on Enter
    Absent in both Palette.tsx:381 and recall.tsx:317-322. This product is JP-first (LINE threads, JP fixtures); Enter that confirms a kana→kanji conversion currently fires the selected row or submits the ask. S.
[BUILT] Empty state = structural "not available" + a next move, never filler or a flash
    recall.tsx prints "No committed record…" plus the proposed 0.52 claim and `review it`; the palette prints "Nothing matches." with the ask row still standing as the next move (Palette.tsx:343-350, 487). Delta: no explicit `help[]` step list (scour:E85) — the lane keeps it quiet.
[CONFLICT] ⌘Enter on a hit = hand to agent as a `ScopedRead` handle (D10)
    Brief: ⌘Enter is the handoff. Built and ruled: ⌘Enter asks Antevon the typed question from anywhere in the card (Palette.tsx:363-367). Select-to-agent exists as the other D10 half — the notes/briefs selection toolbar (`SelTools`: hand to Eiri · hand to Tory · ask Antevon · cite), and ADJUDICATE-20260818 "Left honest" already records that the chat panel is not yet scoped to the selection.
[RULED] Progressive disclosure: a hit opens its record (list → peek → inspector), not a list page
    Palette claims currently `go('/app/vault')` (Palette.tsx:268-275). Already on the owner's desk verbatim in ADJUDICATE-20260818 § Rail · palette: "Palette claims open the vault ledger; should Enter on a claim open the claim's record directly?" — do not pre-empt.
[NEW-OPTION] Visible cap ≤5 rows + "show more"; virtualize large lists; 100ms throttle
    Not built: every match renders in a scroll box (22 fixture rows), unvirtualized, unthrottled. Fine at fixture scale, real at vault scale — owner picks cap-at-5-plus-show-more vs scroll-with-windowing. M.
[REJECT] Power-user chrome on the row: copy handle, pin, `/forget-last`, effort dial chip, world/as-of searchBarAccessory
    Normal-person-first (hide power-user config) plus no-chip-zoo; OF-240 forget verbs are still `needs_owner_input` and the built home for forgetting is `/settings/forget`, while the as-of scrubber already lives in the vault with recall's as-of line as its door.
[BUILT] Ranking chrome vs engine: five signals, one blend, no raw engine numbers
    recall.tsx prints "five signals · one blend · as of 08-13 14:02" and the receipt reads `rc_4e11 · … · 5 signals · 3 in · 3 withheld`; only absolute calibrated confidence surfaces (0.94/0.91/0.84 as ink + numeral), never z-scores, PPR mass or blend weights. World partition is honoured in the cut ledger's `world` column and the "foreign world" withheld line.
[NEW-OPTION] Recents on empty; last-5 queries; clock affordance
    Not built: the empty palette shows the whole pages+claims+acts list (Raycast-shaped), and recall's "asked lately" chips are the two fixture samples and only appear after a question (recall.tsx:327-342). Adding a `lately` group changes the ruled empty shape, so it is the owner's pick. S.
  -- top_new --
  (S) IME composition guard on Enter in the palette and recall's ask field
      JP is a first-class input for this product; today Enter that confirms a kana→kanji conversion fires the selected row or submits the half-typed ask. One `nativeEvent.isComposing` check in each Enter branch.
  (S) Key palette selection to item id instead of the flat index
      The card already has an async phase and will get engine-ranked hits; index selection silently retargets when rows reorder under the caret (the kbar bug cmdk fixed). Swap `sel: number` for `selId: string` with an index derived for aria-activedescendant.
  (S) Mark the matched substring in palette rows using ink strength
      Table-stakes feedback that the filter is working, and it costs no new element: the matched run goes to silver-1 while the rest of the row stays at its resting rung. No highlight box, no colour — stays inside the ink language.
  (M) Display-only match scoring so an exact name outranks a mid-string hit
      Order today is fixed (pages, then claims, then acts) with no relevance sort, so typing a claim word buries the page you meant. kbar's field weights on the display filter only; server rank stays the engine's blend.
  -- corrections --
  * The brief's STEAL preamble builds "inside the one elevated sheet (film-black desk)". Both halves are stale: rule 37 replaced the fixed film-black look with two rooms on `light-dark()` tokens following the system, and the built palette is a floating card with no backdrop that closes on click-outside — so the brief's `aria-modal` + focus-trap advice would be wrong to apply here.
  * "No workbench human palette spec … palette UI is a gap we design" is out of date. The owner ruled and the lane built it on 08-18 (FLOWS rule 42; `<workspace>/Desktop/code/oneiron-web/src/components/safelight/Palette.tsx`, mounted at `src/routes/app/route.tsx:64`), including an ask-AI mode the brief does not anticipate at all.
  * The brief treats recall as unspecified chrome. `<workspace>/Desktop/code/oneiron-web/src/routes/app/recall.tsx` is a full built page: cited spans, the "what made the cut" ledger with two clocks (occurred 05-30 / learned 08-05, +67d), "withheld, and why" (superseded → successor, below floor, foreign world), the receipt, and `watch this question` — which is OF-403 SAVED_QUERY already surfaced.
  * "Invocation collision (⌘K vs in-field) unresolved" is resolved in the lane: ⌘K is deliberately a chord that fires from inside a focused field ("the palette is how you leave a field", hooks.ts:325-345) and `/` is guarded against INPUT/TEXTAREA/SELECT/contentEditable (hooks.ts:209-225). One real collision does remain and is a bug, not a policy question: `/app/recall` registers its own `/` handler (recall.tsx:230-243) on top of the layout's, so `/` on that page focuses the ask AND opens the palette over it.
  * Rule 42 ruling 1 ("eyebrows are dead everywhere") is not yet applied on recall: `Eyebrow()` at recall.tsx:151-169 with `.answer .eyebrow` at src/styles/recall.css:54-63 still renders a mono uppercase 0.12em-tracked kicker (ANTEVON · FIVE SIGNALS · ONE BLEND · AS OF …). The same survivor exists in threads.tsx:312-333/567 and lens/supplier-watch.tsx:387, while briefs.css:73, orgs.css:29 and chassis.css:493 were swept and cite ruling 1 by name.
  * "Steal register has zero rows naming cmdk / kbar / Raycast / command palette" was true on 2026-08-14 and is stale by 08-18: FLOWS rule 42 names the Raycast model explicitly as the ruled shape of the built card.

===== 11-settings =====
[BUILT] Settings is its own area, one page per section
    Ruling 8 / FLOWS rule 42: /settings/route.tsx has its own snav (`you` + `vault · antevon`), "back to app", an esc ladder, and 12 pages; /app/settings|billing|packs redirect in. The brief's "one page, three depths" is superseded by one-page-per-section on the Linear model.
[BUILT] Search-in-settings (persistent field, fuzzy, keyboard)
    Rule 42 put search-as-you-type in the pane head of every ledger page (grants, billing, packs, members, connectors) via PaneHead.qsearch + useLedger, with sort-by-head, filters, ↑↓/Enter/Esc. Deltas: no cross-section search, no jump-and-highlight with breadcrumb, no `#json.path` mode.
[NEW-TAKE] Multiple entry points (⌘, / palette / deep-link)
    Not built and it is the brief's own lockout anti-pattern: settings is reachable only from the vault chip menu (Rail.tsx `vmenu` → settings · usage · Owen) or a typed URL. Palette.tsx PAGES holds zero settings rows and <Palette> is mounted only in routes/app/route.tsx, so ⌘K is dead inside /settings. /settings/usage is the one deep-link alias that exists.
[BUILT] Grants page = registry, not a matrix
    settings/grants.tsx is the registry: who · scope · budget · expires · state chips (live/spent/revoked), receipts fold per row, revoke settles in place with a receipt and "Revoking is not erasing." No duration picker, no consent matrix. Delta: rows display a dated `expires` on standing grants, while canon puts durations on ARCH-0071 delegation envelopes.
[RULED] Toasts / anxiety arithmetic / every policy shows its never-row
    No toasts anywhere ever (lane law); outcomes settle in the row in two phases (billing plan + card, packs install ladder, grants revoke). Billing shows capacity and totals, never per-attempt cost. settings/vault.tsx policy fold carries the literal `agents never — send without your click · write a claim without review`. Do not re-adjudicate.
[BUILT] Billing as a small system (plan, meters, payment, invoices)
    settings/billing.tsx: two thin colourless meters + reset date, plan line with change/end that settles in place, card row with update fold, invoice ledger with a receipt context column (period, storage, inference, paid, receipt hash, download). Meter ≠ invoice is honored; members lives on its own page. Missing: dunning states, danger zone.
[CONFLICT] Price ladder ($19 Builder / $99 Team flat)
    Canon side (ARCH-0011 banner, ladder 2026-07-30): OSS free / $19 Builder / $99 Team flat never per-seat / contact-us, plus asset_gb_days overage and inference credits. Built side: three yen tiers — Solo ¥2,900 · Studio ¥9,800 · Team ¥29,000 with GB·days + credit allowances and a ¥1,440 storage-overage invoice line. The meters match canon; the ladder does not.
[NEW-OPTION] Endpoint-aware Admin (billing/org only on cloud)
    The lane has no endpoint concept: billing, members and connectors are always present for the single owner fixture, so neither the canon behaviour nor the silent-disappearance anti-pattern is live. Owner pick: does the mock grow a local/self-host endpoint state (tuner switch) where billing and members leave behind one stated reason line, or does the mock stay cloud-only?
[NEW-TAKE] Dunning ladder + overage warning before surprise
    Not built: every invoice fixture is `paid` and there is no past_due/suspended state. The page hint already promises "At 80% a note lands in your inbox. Nothing stops in silence." with nothing behind it. Canon ratifies trialing → active → past_due (reads ok) → suspended and "never delete ground truth as a billing action."
[NEW-TAKE] Capability-widening pack update needs fresh consent
    settings/packs.tsx `update` on crm v0.3 is a 1.4s throbber that settles to `v0.3 · updated 14:07` — no diff, no scope comparison, no consent — while its own tooltip says "the diff waits for your stamp". RESEARCH-0319 + ARCH-0040 make widening scopes a fresh-consent moment.
[BUILT] Packs as PackLines with an agent-walked install + receipt
    settings/packs.tsx: installed vs available ledgers, install ladder (reading the pack → granting scopes → done) with checksum and scope lines, pack record column (pages · grants held → doors into /settings/grants · receipts · source), remove keeps every claim and receipts. Antevon's nightly catalog line is digest-not-nag. Per-command enable/disable with defaults-off is deliberately absent — see the reject below.
[REJECT] Per-command pack toggles (Raycast disabledByDefault)
    Contradicts normal-person-first and the lane's own nested-toggle ban; the pack is the atom (DESIGN-APPS §10, rule 42). It would build exactly the settings graveyard the brief lists as an anti-pattern two sections later.
[NEW-OPTION] Layered settings model; GUI writes the manifest, "Edit source" fallback
    settings/vault.tsx shows a three-line read-only policy fold (`read it` / `fold it`); nothing attributes a value to engine default vs manifest vs pack vs preference, and nothing edits a manifest, though DEC-0005 says Settings projects AND edits manifests. Owner pick: read-only projection (as built) or an editable projection with layer attribution. The Zed-style JSON/`#path` source editor is a reject for normal-person-first.
[RULED] Danger zone at the bottom with a friction ladder
    The lane ruled a different shape: forgetting is its own nav page (settings/forget.tsx) whose act stays disarmed until a reason is typed, then tombstones now and sweeps at 03:12 with a sealed receipt row; other destructive acts sit inline as `data-danger` (revoke grant, revoke connector, remove pack, remove member, end plan). No bottom danger zone and no 48h delay. Real gap: there is no delete-vault or leave-vault act anywhere.
[NEW-TAKE] Restore / reseed-after-loss prominent owner surface
    Export is built with provenance (settings/export.tsx: request → sealing → sealed, past-export ledger stamped with the genesis seal), but there is no import or restore path and no `reseeded_after_loss` disclosure, which DEC-0005 requires to be prominent on the owner's surface.
  -- top_new --
  (S) Settings in the palette, and the palette in settings
      Settings is chip-menu-only today — the exact Raycast lockout the brief names. The ⌘K palette already exists (rule 42), so this is wiring: add a settings row per section with synonyms (billing/plan/invoice/subscription → billing; permissions/consent/revoke → grants), mount <Palette> in /settings/route.tsx, bind ⌘, to open settings, and let the ask row answer "what is standing?" from the grants rows (HDU-016 as a complement to the registry, not a replacement).
  (M) Pack update that widens scopes shows the diff and asks again
      The built `update` act promises "the diff waits for your stamp" and delivers a throbber. It is the one governance moment packs have, it is canon-mandated (RESEARCH-0319 + ARCH-0040), and it reuses shapes already in the page — the install ladder for the walk, the pack record column for the old-vs-new scope lines.
  (S) Device gate row on `you` (Touch ID once per device)
      Ratified canon (decision-ledger vault-14) and it answers the owner's own open ADJUDICATE question ("anything missing — notifications, sessions, passkeys?") without inventing taste: the gate is device-level, so it belongs on the account/appearance side, not per vault; software-only is the default and the per-vault opt-out stays hidden as power-user.
  (M) Billing states that are not "everything is paid"
      The page already tells the user that a note lands at 80% and that nothing stops in silence, with nothing built behind it. Add the 80% meter note and a past_due fixture (reads still work, nothing is deleted, one quiet inline line — no toast) behind a tuner switch so the owner can feel the ladder canon ratified.
  -- corrections --
  * The brief audits against `mocks/admin.html` and the single Admin-lens page. The lane shipped a settings AREA on 08-18 (ruling 8, FLOWS rule 42): /settings/* with its own nav, "back to app", an esc ladder, and 12 pages — account, appearance, vault, members, billing (+usage alias), connectors, grants, packs, export, forget. The July `app-settings.html` single governance page is superseded.
  * "No first-class search-in-settings in Oneiron canon... Settings still needs its own in-page search" is out of date. Rule 42 built search-as-you-type in the pane head of every ledger page, with sortable heads, state chips and ↑↓/Enter/Esc, hand-rolled on TanStack Table's column-def shape. The remaining gap is cross-section search, not in-page.
  * The brief frames grants/receipts as doors still to be built into OF-367. /settings/grants is a live ledger — who · scope (with a plain-English tooltip) · budget · expires · live/spent/revoked chips, per-row receipt folds, and revoke that settles in place with its own receipt line.
  * "Billing is endpoint-aware and absent on embedded/local" has no counterpart in the lane: there is no endpoint concept at all, so billing, members and connectors are always present for the single owner fixture. Neither the canon behaviour nor the silent-disappearance anti-pattern is live yet.
  * The ratified commercial shape in the brief ($19 Builder / $99 Team flat) is not what the mock shows: Solo ¥2,900 · Studio ¥9,800 · Team ¥29,000. The meters do match canon (GB·days + inference credits, memory never metered), so only the ladder disagrees.
  * "Toasts rejected" understates the lane law: no toasts anywhere, ever, and every outcome settles in the row in two phases (billing plan and card, packs install ladder, grants and connector revokes, forget receipts). Treat it as settled, not as a recommendation.

===== 12-mint-onboarding =====
[BUILT] No tour / coach marks; no psych-quiz cold-start seeding
    /mint (src/routes/mint.tsx) is a six-step working walk ruled in FLOWS §3 breadboard 0 — name+path, seal, grant sources, first read, first question, open the vault. Zero coach marks, zero questionnaire; the first read is permissive (148 claims proposed, 2 held → inbox), matching the d-mem 'engine not chrome' steal.
[CONFLICT] Plan card + ARCH-0043 preset as the one product choice
    ARCH-0070 (accepted 2026-07-29) says mint = preset pick → one apply → 'N changes, 1 needs your word', same card forever after. The lane's ruled and built mint (FLOWS §3·0, mint.tsx) has no preset and no plan card: it names a file, stamps a seal, grants three sources, indexes, asks one question. Both sides stated; not resolved here.
[NEW-OPTION] Create vs restore on screen one
    No path in the lane opens an existing vault file. The only fork is /signin (email link · passkey · 'mint a new vault' → Rail.tsx chip menu also carries mint). Where restore lives is a real choice: a second act in mint step 1, or a third act in signin's alt row. Owner picks.
[NEW-OPTION] Recovery step + comprehension gate + GENESIS_FRAGILE flag
    Merged: none of the three exist. The built mint shows only public identity (genesis hash, seal, file path) and never asks for or displays a recovery method, so there is nothing for a fragile flag or a confirm-by-retype to attach to. Adding a recovery plane changes the ceremony's ruled length — owner call, not a take.
[NEW-OPTION] Posture-honest split (cloud login-is-pairing vs privacy kit)
    The lane ships both doors and names neither posture: /signin is hosted (email link + passkey, 'Opening the vault'), /mint is a local file at ~/vaults/field-notes.oneiron. Every recovery answer downstream depends on which posture the mock is picturing. Owner call.
[NEW-OPTION] Pairing-code enrollment (E100) + paper-key-as-device + device roster
    Nothing built: no pairing screen, no device list, no paper key. Owner's own open item already brushes the settings half — ADJUDICATE-20260818 §Settings: 'notifications, sessions, passkeys have no fixture yet'. The engine spec (E100) is in the steal register; the UI is unbuilt and is a real design choice.
[BUILT] Age-style public identity beside the secret
    Public half is built twice: mint.tsx stamps the deterministic genesis seal + grouped hash '8f3a 91c4 7d0e 6b25' + copy act + the real path; settings/vault.tsx repeats it as the vault fingerprint. Delta: the secret half and file-mode chrome (0600, O_EXCL) are CLI concerns, not this surface.
[BUILT] No phone-home / no upsell / no account gate at key display
    mint.tsx after the first read: 'Read on this machine. Nothing was sent anywhere.'; signin.tsx foot: 'Nothing leaves your machine without a receipt.' No telemetry toggle, no plan CTA anywhere on either page — the F01 anti-pattern is already refused.
[BUILT] Time-to-first-useful-work right after the ceremony
    Stronger than the brief's bar: the useful work happens inside the ceremony (steps 4-5 index three sources and answer one real question with a withheld line), then 'open the vault' → /app/recall. FLOWS §3·0 calls the thin first answer the soul moment.
[RULED] No toasts; modal reserved for consent-grade only
    Lane law: no toasts anywhere, ever (packet §material; FLOWS §4). Mint settles in place instead — 'granted · read-only', 'copied', 'minted hh:mm'. DESIGN-APPS §5's key-issuance modal allowance is simply unexercised, since no key issuance exists on this surface.
[RULED] DESIGN-APPS cream instrument vs film-black desk
    Rule 37 (08-15) retired both as fixed single looks: one token block under light-dark() with color-scheme: light dark, html.light/.dark force a room, contrast parity ±0.5 per silver rung. The brief correctly says 'don't restyle mint to resolve it' — the lane already resolved it globally.
[RULED] §11 'no chat sidebar' vs floating chat panel
    Rules 28 and 35: the chat is a right-anchored floating panel, 400px × min(600px, 74vh), not a sidebar — compatible on the brief's own test. Moot for this surface: /mint runs outside the chassis (FLOWS §3·0, 'no rail — the vault does not exist yet'), so no chat exists there.
[BUILT] OF-342 Genesis Sigil (brief: still IDEA, pure render)
    Built and load-bearing: 7×7 hash-cell seal, FNV-1a seed → xorshift, left four columns mirrored so one hash always draws one stamp (mint.tsx sealCells), reused in settings/vault.tsx. It is the sanctioned one resting red per FLOWS §3·0 and §7. Open pick: 7×7 grid vs sigil-lab kakuin F3 (ADJUDICATE-20260815 §Settings).
[BUILT] Touch ID once, per-vault key binding (vault:14)
    Partially: signin.tsx has a passkey act — 'Asking this device for its key' → 'Key accepted. Opening the vault.' Delta: the per-vault-binding truth (a key for vault A refuses vault B) is nowhere in the copy; that is one tooltip, not a new shape.
[REJECT] Registry hygiene rows (OF-334 mislabel, stale ceremony-plane text, OF-378/OF-337, Keybase sunset)
    Docs-side, not lane-actionable for the mock. FLOWS rule 15 already cites OF-334 in its correct sense ('Dreamer = internal mechanism only'), and study-never-import already covers the Keybase sunset caveat.
  -- top_new --
  (S) One custody line in the ceremony's own voice
      Mint's opening paragraph promises four things and never says what losing the file costs. The lane's honest consequence is not a seed phrase — it is 'this file is the vault'. One STE sentence in the existing voice block (or under step 1's 'One portable file, yours.') closes the brief's strongest comprehension gap with no new shape, no gate, no tour.
  (S) Sweep rule 42 through /mint and /signin
      Both files date to 08-15 and were not in the 08-18 pass. The killed kicker register survives on exactly this surface: mint.tsx renders a mono uppercase eyebrow 'recall · as of hh:mm' over the first answer, signin.tsx renders 'sign in' over its line. Rule 42 prescribes a quiet meta-line instead. Field labels ('name', 'home') stay — vault/agents keep those too.
  (S) Two drafted options for the restore fork
      A first-run with no way back to an existing vault silently mints a second one — the brief's clearest table-stakes miss, and the lane has no answer at all. Per no-taste-invention, the deliverable is a pick, not a shape: (a) a quiet second act under mint step 1 ('open an existing vault'), (b) a third act in signin's alt row beside passkey.
  (M) Posture decision packet for /mint + /signin
      The lane ships a hosted door and a local-file door and names neither posture, so recovery copy, fragile-genesis chrome, pairing and the emergency-sheet question all sit blocked behind one unasked question. Canon says one script cannot serve both. Cheap to frame now, expensive after the coherent pass builds recovery on the wrong assumption.
  -- corrections --
  * OF-342 is not still an IDEA in the lane. The genesis seal is built and deterministic — mint.tsx sealCells() (FNV-1a → xorshift, mirrored halves, 7×7) and reused in settings/vault.tsx — and is the sanctioned one resting red per FLOWS §3·0 and §7. The only open part is which family: 7×7 grid vs sigil-lab kakuin F3 (ADJUDICATE-20260815).
  * The DESIGN-APPS-cream vs film-black conflict audits a dead direction. Rule 37 (08-15) killed both as fixed looks: one token block, light-dark() under color-scheme: light dark, system-following with html.light/.dark as overrides, contrast parity in both rooms.
  * 'No first-class mint ARCH page … that composition is the build gap' is docs-side only. Lane-side the composition exists and is built: FLOWS §3 breadboard 0 sequences the whole ceremony and /mint implements it, with mint reachable from signin and the chip menu (Rail.tsx, rule 42).
  * The brief models a seed-phrase ceremony; the built mint has no secret material at all. The vault is a file at ~/vaults/field-notes.oneiron and the only identity displayed is the public genesis hash. USERS-EXPECT 3, 4 and 7 plus the emergency-kit and confirm-by-retype steals have no surface to attach to until a secret or recovery plane is decided.
  * §11 'no chat sidebar' is not an open compatibility question in the lane — rules 28/35 ruled the chat a floating 400px panel — and it is doubly moot here, since /mint deliberately runs with no chassis and no chat (FLOWS §3·0).

===== 13-consent-grants =====
[BUILT] Trio on every interrupt (allow once / stop asking / deny), no fourth duration button
    Live on the inbox ask row: `src/routes/app/inbox.tsx` b2 renders `allow once · allow + grant · deny` as rest-verbs, settling in place with no toast. Deltas: copy is "allow + grant", not "approve-and-stop-asking"; and the `allow once` tooltip (inbox.tsx:814) wrongly says it "mints a scoped, budgeted, revocable grant (OF-050)" — that is what allow+grant does.
[BUILT] Review / revoke registry as DEC-0006 surface (b)
    `src/routes/settings/grants.tsx` — sortable ledger (who · scope · budget · expires), search, live/spent/revoked filter chips, receipts fold per row, one-tap revoke that lands its own receipt line, closing note "Revoking is not erasing." It sits in the 08-18 settings area (ruling 8), one page per section.
[BUILT] Incremental / just-in-time consent at point of use, scope-exceed = fresh ask
    The b2 row is exactly this: a new audience for the existing LinkedIn grant raises a fresh ask at the moment of use ("A new audience for the LinkedIn grant, so it asks before it reaches"), not an upfront bundle. Bundled run-level consent also exists (paused import: review bundle / resume / discard).
[BUILT] Grant state machine + Shepherd consume-once settlement for allow-once
    `grants.tsx` State = live | spent | revoked; the importer row is literally consume-once ("one pass · credentials discarded after it, so a spent grant cannot be used twice") with its receipts kept. No PENDING/DENIED states — the owner mints directly, so there is no request queue to model.
[BUILT] Record the human principal who minted (SLK-039) + audit breadcrumb
    Partial. `app/agents.tsx` scope rows carry the granter seal + date + tooltip ("granted by Owen", "granted 2026-08-02 · standing"), and seals are humans-only per rule 15. The registry rows themselves carry no minted-at and no last-used — only `expires`.
[CONFLICT] Registry is the only standing-grant home / "if it is not on the registry it is not a grant"
    Canon (DEC-0006 inv. 9 + the brief's hidden-grants anti-pattern): one pane, one home. Lane: grants live and are revoked in five places — `settings/grants.tsx` (5 rows), `app/agents.tsx` per-verb scopes, `settings/connectors.tsx`, `settings/packs.tsx` scopes, `app/threads.tsx` channel identities — and the registry lists none of the other four. The lane's own settle-in-place law is what pulls revoke out to where you are.
[CONFLICT] No expiry / duration on standing grants (canon non-goal)
    Canon: once-vs-standing only; registry replaces expiry-guessing; OF-050's "expiry" is drift. Lane: `expires` is a first-class column in `grants.tsx` COLS and in the FLOWS §3-7 breadboard ("grantee seal · scope · budget · expires"), with `2026-10-07` on the Eiri send grant, echoed in agents.tsx whenTip, packs.tsx ("expires 2026-10-07") and tasks.tsx ("It expires in 30 days"). Mitigation, not resolution: it is display-only, standing rows read `open`, and no duration picker exists anywhere.
[NEW-TAKE] Ask card = readable consequence (bound, args, actor, what-if-standing)
    Half-built: the ask row shows one plain why-line, the agent name in ink, and doors (the grant / who they are). Missing is the part the trio turns on — what `allow + grant` would remember. Adding one line that names the narrowest bound the click would mint is S, canon-backed, and invents no new shape.
[NEW-TAKE] Expand the bound into concrete unlocks; never show a raw scope string
    `grants.tsx` shows mono scopes (`outbound.email · hokuei.co.jp`) with the plain English hidden in a `title` tooltip — hover-only, invisible on touch, and against normal-person-first. `connectors.tsx` already solves it: a serif `charter` sentence at the top of the fold. Mirror that into the grants fold using the existing `scopeTip` strings.
[NEW-OPTION] Admission slate at connector/pack add — one typed row per tool, optional vs required scopes (ARCH-0072, SLK-055)
    Not built: `packs.tsx` `add` runs the whole install ladder including a single bundled "granting scopes" rung; `connectors.tsx` connect is one click. The owner already has this question open verbatim in `docs/ADJUDICATE-20260815.md` ("Should it stop there and wait for a second click — every grant is your click?"). Give him 2–3 shapes (one tap mints the slate / per-row typed slate / minimal-read-now + write-later).
[NEW-OPTION] Graduation offer, never silent promotion; symmetric self-demote on undo streaks (OF-399, ARCH-0055 r7)
    Absent from the lane — no streak, offer, or demote anywhere in src. Canon-backed but the placement is a real design choice (a line inside the ask row it graduates from, vs a quiet offer row on the registry), so it is an owner pick, not a take.
[NEW-OPTION] Reverse flip auto → confirm-first on the registry (DEC-0006 inv. 9)
    The registry has revoke only; no row carries an auto/confirm-first state, so there is nothing to flip back. Introducing that state on the ledger changes what a grant row *is* — owner pick (a third column, vs a verb beside revoke).
[RULED] Danger confirm on destructive acts (SLK-020)
    Already law: FLOWS §3-7 "revoke arms red on touch", and `app/agents.tsx` implements the two-tap arm (`revoke` → `revoke?`). But the ruling is only half-built: `data-danger` is set on six acts (grants, connectors, packs, members, forget, billing) and has NO CSS rule anywhere in `src/styles`, and the registry's own revoke commits on a single click.
[REJECT] Catastrophe floor never auto-allows · Require beats Always · fail-safe flips by domain
    Engine policy with no surface to show yet: the mock has no auto lane and no rule-precedence UI, so any rendering of it would be invented furniture. Revisit when an auto/confirm-first state exists on grant rows.
[REJECT] SSE gate-pending/resolved (NSD-070) · blocking round-trip · never advisory (Buzz WF-08)
    Backend contract, not a mock surface — and the push idiom has no UI expression here anyway, since toasts are banned globally and asks settle as inbox rows.
[REJECT] Dismiss-without-submit is an event (SLK-016)
    Not ours: the ask is an inbox row, not a modal, so there is no dismiss to record. Leaving the row unanswered is already the visible state.
  -- top_new --
  (S) "What this would remember" line on `allow + grant`
      The standing half of the trio is currently a blind click — the row says why it asks, never what the second button would mint. One line under the ask naming the narrowest bound (actor × verb × audience × budget) makes the durable choice readable before the tap. Canon-backed (DEC-0006 inv. 2 + narrowest-rule prefill); no new shape, it reuses the existing `bd-why` line in `app/inbox.tsx`.
  (S) Plain consequence in the grants fold, plus minted-at and last-used
      Today the registry's English lives only in a `title` tooltip and the row shows a raw mono scope; `connectors.tsx` already carries a serif `charter` sentence in its fold, so this is copying the lane's own solved pattern into `settings/grants.tsx`. Adding minted-at / last-used closes the brief's registry column list without touching the disputed `expires`.
  (M) One registry — every standing grant on `/settings/grants`
      Canon's hard line is that a grant not on the registry is not a grant, and the lane currently hides four other grant homes (agent verbs, connectors, packs, thread identities). Make the page the union, each row deep-linking back to where it lives; in-place revoke stays where it is, because settle-in-place is lane law.
  (S) Wire the dead consent → registry joins
      Six "the grant" doors are `href="#"` (inbox.tsx 326/362/781/844; threads.tsx 185/205/225) and two point at the retired `/app/settings` (inbox.tsx:446, tasks.tsx:297, which now redirect to `/settings/account`). The receipt-join between the ask and the registry is the surface's whole spine and it currently goes nowhere.
  -- corrections --
  * The brief treats this surface as unbuilt UI-over-existing-machinery. It is built: `/settings/grants` is a working registry (sortable ledger, search, live/spent/revoked chips, receipts fold, in-place revoke with its own receipt) and the OF-367 trio is live on the inbox ask row (`src/routes/app/inbox.tsx`, b2). Audit against that code, not a blank slate.
  * The "grants page" is no longer in-app. Ruling 8 (08-18) moved settings to its own Linear-model area, so the registry is `/settings/grants`; `/app/settings` only redirects. OF-367's "pending tray" is the inbox itself, not a separate tray, and it has no `let_go` age-out.
  * The brief's warning "do not add a duration UI to the trio" is aimed at the wrong place: the trio is clean, but display-duration is already in the lane — an `expires` column in `grants.tsx` and in the FLOWS §3-7 breadboard, plus `expires 2026-10-07` copy in agents.tsx, packs.tsx and tasks.tsx. No picker exists, so this is drift in fixtures and copy, not a new anti-pattern risk.
  * The allow-once-is-spent / standing-is-durable split the brief relies on is not yet true in the lane's own words: `inbox.tsx:814` titles `allow once` as "mints a scoped, budgeted, revocable grant (OF-050)", which describes allow+grant. Consume-once IS modelled correctly one surface over (the `spent` importer grant on the registry).
  * SLK-020 danger-confirm is not an unadopted external idea — the lane already ruled it (FLOWS §3-7 "revoke arms red on touch", implemented as a two-tap arm in `app/agents.tsx`). What is actually wrong is enforcement: `data-danger` is used on six destructive acts and has no CSS rule in `src/styles`, and the registry's revoke fires on one click.
  * DESIGN-APPS / Quarto Instrument is no longer the lane's live material law (safelight two rooms, rule 37). Nothing in this surface turns on that, since the brief itself concludes Quarto does not constrain consent UI — but do not cite Quarto's sheet grammar as the authority for any consent-card shape.

===== 14-receipts-audit =====
[CONFLICT] One family, two registers, three homes (STEAL 1 / RS1–RS2)
    Canon RS2 wants a logbook as a PLACE (EF-055 lane: pending tray + grants entry). The lane built no logbook place — receipts settle where the act happened (/settings/grants, /settings/forget, /settings/export, /app/agents runs ledger, /app/threads send ladder, /app/recall + vault inspector), per build law "no toasts (records)" and rule 31 ("the in-place unfold survives ONLY where you act"). Both sides stand; owner call.
[BUILT] Every rendered receipt is a tappable door (STEAL 2 / UE 2 / RS3)
    Build law is already "every mono token is a door (title tells the truth)": grants receipts fold under the row, threads has open receipts / open the receipt, agents runs end in a receipt door, inbox doors into run receipts, vault has the successor door. Delta: several are preventDefault() stubs (vault.tsx:926 context receipt, threads.tsx:182 "the 36 older receipts", agents receipt acts) — dead text is the brief's own bug class.
[RULED] Peek-without-leave / inspector sheet (STEAL 7 / UE 10)
    Rule 31 already ruled the docked 320px context column for read-only detail, with the in-place fold kept only where you act; rule 39's three candidate open-laws (gesture · column · kind) are live in the dev Tuner awaiting the owner's pick. Do not re-propose a peek drawer as a fresh shape.
[RULED] Actor seals: filled=human / outline=agent / dashed=system (STEAL 17)
    FLOWS rules 15 and 33 rule against the agent tier: seals are HUMANS only, an agent is its NAME IN INK, "the herald seal was a drift and is dead." Built as seal-human plus seal-system for non-agent system actors (importer `im`, slack connector `sl` in grants.tsx) and .aname[data-agent] for agents.
[BUILT] Toasts die here; writes settle into records (STEAL 18)
    Build law §4 is "no toasts (records)". Verified on every receipt-minting act: grants revoke rewrites the row and prepends a receipt line, forget lands a stamped ledger row, export appends a past-export row, inbox accept/deny settles in place.
[BUILT] Deletion receipt print (STEAL 14 / DESIGN-APPS §7)
    /settings/forget: the act arms only once a reason is typed, then an ERASED stamp row lands in a deletion ledger with the human seal and the two-phase sweep column. Deltas from the brief: no thermal slide-up, and one row per act rather than one receipt per batch.
[CONFLICT] Three consent verbs, no duration picker (STEAL 15 / RS6)
    Built is two verbs — accept/reject on claims, approve/deny on asks (inbox.tsx) — with "approve-and-stop-asking" expressed instead as an auto-accept POLICY that lives in settings (inbox.tsx:572). Against that, the grants ledger ships an `expires` column with a real date (grants.tsx:132, Eiri 2026-10-07) while OF-453 L8 says no grant type persists expiry and RS6 says grants never auto-expire.
[BUILT] Approve-and-stop-asking is audit-visible + registry-revocable (STEAL 16)
    /settings/grants is the revoke home: one-tap revoke, receipt lands in place, standing line "Revoking is not erasing. The reach ends now." Missing vs RS6: the row shows no origin-ask join and no explicit last-used field (only the newest receipt line implies it).
[NEW-TAKE] Negative space is first-class — held / degraded / suppressed / let_go (STEAL 3 / UE 5)
    Built for WRITES only: inbox rows carry "Held: …" with the reason, the agents runs ledger has a `waited` column, recall has a "Withheld, and why" section (3 withheld). Outbound has no negative space — threads.tsx SendState is `pending | verified | receipted`, all successes.
[NEW-TAKE] Never claim `seen` (UE 11 / ANTI-PATTERN 5 / ARCH-0046 O5)
    One live breach: src/routes/app/threads.tsx:103 tooltip reads "sent · verifying in the thread · the receipt lands when it is seen". The lane's own state word is `verified` (verified in thread 09:12); the fix is one line of copy.
[REJECT] Correlation / causation IDs as columns + bidirectional trace↔log door (STEAL 6, 9 / UE 7, 8)
    No correlation or causation id exists anywhere in oneiron-web, and the brief's own OPEN PROBLEM 11 concedes the vault-receipt ↔ OTel-span join has no canon join. Premature for a fixture-data design mock, and ARCH-0037 telemetry is local-only.
[BUILT] Bimodal tables — audit_log-class vs changelog-class (STEAL 5)
    Rule 42 made every table interactive and the lane has one hand-rolled ledger grammar (settings/-shared.tsx: useLedger + LedgerHead + Fold, TanStack-Table column-def shape, no dep). Grants is the authority-ops table; notes TrailFold and the vault two-clocks/successor inspector are the state-change table. Not smashed into one JSON dump; no receipt_kind join exists yet.
[BUILT] Before/after or reconstructable before-image for mutations (UE 6 / STEAL 4)
    For the vault: the as-of scrubber (OF-082, vault.tsx:725) plus occurred/learned two clocks and the successor door is the frontier-reconstruct made visible, not a stored before-blob — exactly NSD-072's shape. For documents it is missing: notes TrailFold prints "Aug 12 03:12 · antevon · edited ¶7" as dead text with no diff and no door.
[BUILT] Browse facets: actor / verb / resource / time / kind / outcome + free text (UE 9)
    Rule 42 (08-18) made tables interactive: grants has live/spent/revoked chips, search-as-you-type in the pane head, sortable heads and ↑↓/Enter/Esc; vault adds chrome chips, per-column filters and the as-of. No receipt_kind or outcome facet — there is no cross-cutting receipt list to facet.
[REJECT] Export + API + SIEM stream, stated retention, audit-of-audit (UE 12, 13, 14)
    /settings/export ships "export with provenance" — whole vault with every source and receipt, sealed and stamped with the genesis seal, past exports in a ledger — and /settings/forget states the retention sentence ("the record goes now, the sweep clears the history at 03:12"). SIEM streaming, IP/UA columns and audit-of-audit rows are not-ours: the brief's own CONFLICTS section carves OF-333 floor receipts out of user surfaces and warns off phone-home telemetry.
[BUILT] Machine IDs are hover-tier; humans read sentences (UE 18)
    rc_4e11, rx_7b12, cl_58aa and grant ids all live in title= tooltips or as mono doors, while the visible receipt line is a serif sentence ("Sent the pilot quote to mika@hokuei.co.jp. You approved it in the inbox."). Matches the build law "every mono token is a door (title tells the truth)".
  -- top_new --
  (S) Kill the one "seen" claim in the threads send ladder
      threads.tsx:103 says the receipt lands "when it is seen" — the single thing ARCH-0046 O5 explicitly rejects, and the lane already owns the honest word (`verified in thread`). Cheapest possible canon repair.
  (M) Give outbound its negative space: held / degraded / suppressed / let go beside verified
      Canon calls negative space THE trust surface, and the lane already speaks it for writes (inbox "Held: …", agents `waited` column, recall "Withheld, and why"). Sends are the only place that renders successes only, which is the shape that makes a receipts surface a marketing claim.
  (M) Wire the dead receipt doors instead of adding new ones
      vault.tsx:926 "context receipt", threads.tsx:182 "the 36 older receipts" and the agents run receipt acts are all preventDefault() stubs — dead text under the lane's own "every mono token is a door" law. OF-369's field set is already specified, so this is wiring, not taste-invention.
  (M) Make notes TrailFold rows doors that land on the block they changed
      "edited ¶7" is the lane's only mutation record for documents and it currently goes nowhere; landing on the block with the agent's ink still showing closes the before/after expectation without a diff view or a second store.
  -- corrections --
  * The brief's framing — "what is missing is a landed logbook UI, not a new primitive" — understates the lane. Six receipt surfaces landed on oneiron-web since 08-15/08-18: /settings/grants (revoke → receipt in place), /settings/forget (ERASED ledger), /settings/export (sealed export ledger), /app/agents (runs ledger with writes/waited/receipt), /app/threads (send ladder + per-channel receipt sheets), /app/recall + the vault inspector (context receipt). What is genuinely absent is the CROSS-CUTTING list, not the register or the doors.
  * Dead premise: the brief carries "DESIGN-APPS cream #F4F0E6 vs mission film-black desk" as a live conflict. FLOWS rule 37 retired both — theme follows the system via light-dark() tokens, one token block, contrast parity in two rooms. Do not propagate that conflict.
  * STEAL 17's seal ladder (filled=human / outline=agent / dashed=system) is ruled against on the agent tier: FLOWS rules 15 and 33 say seals are humans (plus non-agent system actors) only and an agent is its NAME IN INK — "the herald seal was a drift and is dead."
  * UE 10 / STEAL 7 treat peek-without-leave as an open shape. It is not: rule 31 ruled the docked context column, and rule 39's row-open law (gesture · column · kind) is switchable in the dev Tuner pending the owner's pick. Any inspect proposal must be phrased as one of those three.
  * The packet's "eyebrows dead everywhere" is not true on disk: /app/recall still renders <Eyebrow> at recall.tsx:373, 560 and 612 (styled at recall.css:54), and lens.css still describes an eyebrow. Since that eyebrow IS the answer's provenance line ("who rendered it, from what, as of when"), receipts work there should land it as the one quiet meta-line and clear the residue in the same pass.
  * The grants ledger ships an `expires` column with a hard date (grants.tsx:132; Eiri 2026-10-07). OF-453 L8 says no shipped grant type persists expiry and RS6 says grants never auto-expire — the date belongs on the wire as slip lifetime. Either the column renders that, or it is a drift worth naming before it hardens.

===== 15-cross-cutting =====
[BUILT] No-toast outcomes: the row/receipt is the result (STEAL 4, AP1, AP2)
    Zero toast/snackbar code repo-wide; FLOWS §4 build law states "no toasts (records)". Acts settle into in-place receipt lines — pipeline MovedLine, lens.css receipt+undo, settings-area .receipt, mint receipt, signin .gate-receipt. No timed dismissal anywhere, so the Gmail/Apple snackbar anti-pattern cannot occur.
[RULED] One command palette (⌘K) as fuzzy find-anything
    Owner ruled 08-18 (rule 42): src/components/safelight/Palette.tsx, opened by ⌘K, `/`, or the search icon beside the vault name; groups pages · claims · acts; search-as-page is dead. Delta from the brief: the palette also carries an ask-AI phase (ask row → thinking → answer with `open in recall` / `ask in chat` doors) that the brief did not anticipate.
[BUILT] Discoverable overlay — hold-modifier / `?` sheet / shortcuts on contextual menus (STEAL 2)
    Hold-⌘ is built in the app chassis: useHoldKey('Meta', 600) in hooks.ts + ShortcutSheet in Palette.tsx, bottom-right, dodging the chat panel. Missing: no `?` sheet, no which-key trie/breadcrumb/sticky-prefix state machine, no shortcut printed on contextual menus (only ⌘↵ on the ask row). Note the sheet uses bordered <kbd> chips, which DESIGN.md §7 bans for docs hints (docs-only per the brief's own C2).
[RULED] j/k (or Ctrl+N/P) list walk when not in an input
    Owner ruled the list/table grammar 08-18 as ↑↓ · Enter · Esc (rule 42), implemented per page (vault.tsx:512, orgs, agents, notes rowArrows, settings/-shared, pipeline, Rail, Palette). No j/k, no vim aliases. DESIGN-APPS §5's "j/k list-triage docks by default" is the canon side that the later ruling overrides.
[RULED] j/k docks the inspector / dock-by-default as settled behavior (STEAL 3)
    Docking is precisely what is still open: rule 39's open law (gesture · column · kind) is live-switchable in the dev Tuner (Tuner.tsx:159, inbox.tsx useOpenLaw) and the owner adjudicates it in ADJUDICATE-20260818 (his rec: gesture). The brief treats dock-by-default as decided; in the lane it is the flagship pending pick.
[NEW-TAKE] One Action registry feeds keymap + palette + shortcut sheet (STEAL 1, Zed)
    Not built: keys come from three unrelated hooks (useGlobalKeys, useCommandKey, useHoldKey), a hardcoded KEYS array in Palette.tsx:577, palette acts built inline, and per-page onKeyDown handlers. Nothing binds them, so the sheet can silently drift from what is actually bound and page-level keys are unlisted.
[NEW-OPTION] Receipted undo: ⌘Z over a recorded operation log, vault-global scope (STEAL 6, C6)
    Partly built as inline undo only: pipeline stage move (MovedLine `undo`), supplier-watch delete (receipt + undo), and a stamped ERASED deletion-receipt ledger in settings/forget.tsx. No ⌘Z, no operation log, and scope is unnamed. The owner already has the sibling call open in ADJUDICATE-20260815 ("delete: one click + undo, or a second armed click") — pair it with the ⌘Z scope question rather than deciding it.
[BUILT] Typed empty: first-use vs filtered-no-results vs no-access vs failure (STEAL 8)
    First-use vs no-results is distinguished: inbox `?empty` flock + "Nothing waits for you." + teaching sub-line, tasks-empty, vault "No claim matches this.", palette/pipeline "Nothing matches.", NotFound plate card. Missing kinds: no-access and back-end failure (only a global DefaultCatchBoundary, "Something broke." + try again + inbox).
[CONFLICT] Cormorant empty voice line ("The vault holds no record of this.")
    DESIGN-APPS §7 prescribes a Cormorant empty-state voice line. The lane's empties are Source Serif one-liners plus keyed riso spot art (rule 40: flock on the empty inbox, the plate as the lost page) under the minimal-copy STE law. Both sides stand; no winner picked here.
[BUILT] Morning-paper settle, not shimmer skeleton; loading ladder <1s/2-10s/>10s (STEAL 7, C5)
    Settle-in is built and skeletons are absent everywhere: 160–240ms transform+opacity lands (`land`, `orgs-land`, `brief-in`, `gate-land`, `develop`, `pa-land`) with prefers-reduced-motion blocks in twelve stylesheets. The timed loading ladder is untestable and premature — the mock runs on fixtures with no async fetch path.
[CONFLICT] No looping ambience / hot-path animation (AP5)
    Brief bans looping shimmer outright. The lane deliberately runs a 2.4s infinite shimmer on live "doing" text (agents.css:202, briefs.css:221) as rule 36's live-work language, killed on hover and under reduced motion, beside the braille throbber. DESIGN-APPS §6's own "living marginalia where work is live" is the canon that permits it.
[BUILT] One dock line for ambient work ("N at work", Google-Docs-style status)
    The agent line (Ground.tsx) is the persistent bottom strip: live runs as name-in-ink + doing text + one shared braille throbber (hooks.ts, single 120ms interval, reduced motion holds frame one). It carries no aria-live region, so background outcomes are silent to screen readers — see top-new.
[CONFLICT] Emil rule: 2px {accent} focus ring, offset 2
    Built literally — safelight.css:108-110, `outline: 2px solid var(--safelight)` (red) with offset 2. The owner flagged it on 08-18: red is scarce and the ring reads as alarm, his rec is a 1.5px silver-3 ring with red only when an act arms. Pick pending in ADJUDICATE-20260818; canon and the owner disagree.
[CONFLICT] Modal scarcity — true modals for consent-grade acts (hard-delete, key issuance)
    DESIGN-APPS §5 reserves true modals for consent-grade interruptions. The lane has zero modals: the palette is explicitly a floating card with no backdrop, settings-area.css states "no toasts, no modals", and destruction is gated by arming instead (forget requires a written reason before the act arms; revoke arms red, receipt lands in place).
[BUILT] Named memory verbs as receipted commands + F49 inline consent card (STEAL 10)
    Partly: settings/forget.tsx is the receipted named verb (reason-gated arming, ERASED-stamped deletion-receipt ledger, "the record goes, a receipt stays"), and the inbox is the persisted ask-before queue with accept/reject rather than a toast. Still unbuilt and still owner-blocked per OF-240: /forget-last, archive/revive-world, Incognito.
[REJECT] Notification tiers / quiet hours / in-app ack (C1, C4) and ack-first SSE gate stream (STEAL 9)
    Outreach and transport infrastructure with no surface in a fixture mock; the drift risk the brief names cannot occur here because no toast primitive exists. The one live thread is a settings question the owner already raised himself (ADJUDICATE-20260818: is a notifications page missing from the settings nav?) — leave it there.
  -- top_new --
  (M) One action table (id · title · keys · context · run) that feeds the palette's act rows, the hold-⌘ shortcut sheet, and page key handlers
      Today keys live in three hooks, a hardcoded KEYS array, and per-page onKeyDown, so the sheet drifts from reality and page keys (↑↓, Enter, the Esc ladder) are never taught. One table also makes the row-open law and any future ⌘Z a registered action rather than another bespoke listener.
  (S) One polite live region on the agent line for background outcomes
      The no-toast law leaves screen-reader users with nothing when a run finishes or a receipt lands in place. A single visually-silent aria-live=polite region on the persistent agent line announces the same line the eye already reads — keeps the law, closes the a11y hole. Only the palette answer has one today.
  (S) An inline field-error line (aria-describedby, one quiet line under the field, never a toast)
      No inline error grammar exists anywhere: mint, signin, the members invite and the connectors connect flows all assume success, and the only error surface is the global catch boundary. WAI's forms guidance plus the no-toast law force the placement; the colour should follow whatever the focus-ring ruling settles.
  (S) Unify the empty state on one component with named kinds (first-use · filtered · no-access · failed)
      settings/-shared.tsx already exports an `Empty`, while every app route hand-rolls its own; the no-access and failure kinds are missing entirely. One typed component stops "nothing here" from meaning four different things and gives QM's explicit-semantics point a home.
  -- corrections --
  * The brief treats the workbench keyboard map as unbuilt and unspecified. It shipped 08-18 (rule 42): ⌘K / `/` / search-icon open one Raycast-model palette with an ask-AI answer phase (Palette.tsx), and search-as-page is dead.
  * C2's "do not mint the docs shortcut set as the workbench map" is half stale: the lane took the docs' hold-⌘ *mechanism* into the app chassis (useHoldKey + ShortcutSheet) but bound its own map — `[` folds the rail (not ⌘B), `t`/`m` for theme/sound (not ⌘D).
  * C9 ("the cohesive notification-free grammar must be designed from scratch") is stale: it is designed, built and enforced as a FLOWS build law — in-place receipt lines, an ERASED deletion-receipt ledger, inline undo, and zero toast code in the repo.
  * C5's skeleton-vs-settle question is moot in this lane: no skeleton or load shimmer exists anywhere, and a fixture mock has no async fetch path against which the NN/g loading ladder could be judged.
  * Emil's 2px accent focus ring is not an unmet table stake — it is built literally (safelight.css:108) and is now an owner-flagged problem, because --safelight is red and the ring reads as alarm (ADJUDICATE-20260818, rec 1.5px silver-3).
  * The brief's fixed-direction line ("film-black desk / one sheet") is the dead direction: theme follows the system, two rooms, one light-dark() token block with contrast parity (rule 37). Nothing else in this surface hangs on it.