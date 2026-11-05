# Chat surface — OSS patterns study (2026-08-15)

Survey of OSS chat/thread/agent-console UIs (grok X sweep + exa, early 2026).
We STUDY these, we never import ([[feedback-take-idea-rebuild-native]] house law).
Studied: assistant-ui (the architecture reference, ~6.1M monthly downloads),
Vercel AI SDK + AI Elements, LlamaIndex chat-ui, Open WebUI, LibreChat, Chainlit,
Langfuse-class run viewers, use-stick-to-bottom, TanStack Virtual (May 2026 chat API).

## The converged mental model

A message is not a string; it is a **`parts[]` array of typed parts**
(`text`, `reasoning`, `tool-<name>`, `data-<name>`). The thread renderer is a
switch/registry over part types. Our GenUI widget (title + line + act) is just
one part type. Three bands of generative UI: controlled (agent picks a shipped
component — us), declarative (agent assembles from a catalog), open (iframe).

## The ten patterns to build on

1. **Parts + registry.** Typed parts array; registry maps part type → renderer;
   fallback slot for unregistered types.
2. **Model-chosen vs system-chosen UI, reconciled by id.** Tool-part = the model
   picked the UI; data-part = our backend picked it. Same `id` re-emitted patches
   in place (loading card → filled card); `transient` parts (run status ticks)
   render live but never enter history — exactly the run-scoped chat's need.
3. **Part lifecycle states are the widget UX contract.**
   `streaming-in / ready / awaiting-user / done / error / denied`, rendered
   per-state. A confirm card is a "human tool": its buttons resolve the part.
4. **Pin-to-bottom done right.** Sticky flag owned by a ResizeObserver; user
   scroll cancels it instantly (no debounce); follow new content only when
   pinned; "jump to latest" gets its OWN observer so pin flips never re-render
   the thread (LibreChat); spring/velocity animation, never duration easing
   (use-stick-to-bottom).
5. **Never virtualize by default.** `content-visibility: auto` +
   `contain-intrinsic-size` per message; window history (render last N, top
   sentinel loads older). Open WebUI's JS mount/unmount culling was a disaster;
   if ever needed: TanStack Virtual `anchorTo:'end'`, stable keys, virtualize
   TURNS not rows.
6. **Streaming cost is markdown re-parsing, not DOM size.** rAF-batch chunks to
   one update per frame; never re-tokenize the stable prefix; defer highlight/
   KaTeX until the message completes; repair incomplete markdown while streaming
   (Streamdown) so nothing flashes; memoize prior messages.
7. **Runtime/view split with capability flags.** Chat store (messages,
   isRunning, composer, cancelRun/pauseRun) outside components; selector-hook
   reads; capabilities toggle UI by presence (pass onCancel → cancel exists).
   The run-scoped panel = the same store with a run id + different
   capabilities, never a second surface.
8. **Trigger popover, two behavior kinds.** Declared trigger char + adapter;
   a selection either inserts a Directive token (mention/agent switch) or
   executes an Action (slash command). One mechanism; popover exists only
   while the trigger is live in the input.
9. **Gate sending, not typing.** Textarea stays live during a run; Send ↔ Stop
   swap on isRunning; consider a pending-message queue ("steer" lane).
10. **Group consecutive same-kind parts.** Runs of tool/status parts collapse
    into one wrapper (count + status) — essential in a 440px panel.

## Table-stakes to fold into our panel (owner picks the round)

- ~~Send ↔ Stop swap while a run streams~~ — **DEAD (owner 08-15): Oneiron
  steers, Codex-like.** A message sent into a live run is a STEER Signal
  (ARCH-0026 run tree): non-blocking intent, consumed at the run's next safe
  breakpoint via steering-queue next-turn injection; the run CONTINUES.
  Pause/cancel are run-level Signals in the panel head, never composer chrome.
  The composer is always live; sending is always meaningful.
- Jump-to-latest when unpinned; new-activity badge on the agent line while the
  panel is closed (no prior art for our exact panel-over-strip shape; nearest =
  a run viewer's "back to live" pill).
- Copy on messages; retry on the last assistant message.
- Preserve scroll position on history prepend AND across panel close/reopen.
- Empty state with suggestion chips.
- Enter sends / Shift+Enter newline; Escape closes popover BEFORE panel.
- History grouped by age: validated (everyone clones ChatGPT's Today/Earlier).

## Chat SDK (chat-sdk.dev) — evaluated 08-15, verdict: study, do not adopt

The 2026 Chat SDK is NOT the old Next.js chatbot template: it pivoted into
Vercel's unified BOT SDK for channels (vercel-labs/chat) — write handlers once
(`onNewMention`, `onSubscribedMessage`, actions, slash commands), deploy across
Slack / Teams / Google Chat / Discord / Telegram / GitHub / Linear / WhatsApp;
plus a Web adapter that speaks the AI SDK `useChat` wire protocol.

- **Not for this panel:** it ships NO UI. Its web story is just `@ai-sdk/react`
  useChat against a bot endpoint — the protocol is framework-agnostic and works
  in TanStack Start with or without Chat SDK behind it. The panel stays bespoke.
- **Not for the engine substrate:** channel connectors are Oneiron core
  (provenance, receipts, grants, consent gates ride them; Rust engine). A TS
  webhook/Redis sidecar would fork the substrate. Take the idea, rebuild native.
- **Steal as ideas (the best public checklist for OUR connector canon):**
  per-platform streaming fallback ladder (native stream → rich draft →
  post+edit → buffered); `Plan`/`StreamChunk` = a postable object that
  re-renders in place on mutation (our reconcile-by-id widget, channel-side);
  per-thread concurrency strategies (burst / queue / debounce / drop);
  thread-subscription + distributed-lock state; markdown healing mid-stream
  (remend). Its one-brain-many-surfaces shape independently validates our
  coherent-face law (ARCH-0026: users talk to the face, the face relays).
- **GTM read:** Vercel is commoditizing the channel TRANSPORT layer. That
  squeezes bot-plumbing startups, not us — the memory/provenance substrate
  stays the moat.

## vercel/chatbot (the renamed ai-chatbot template) — evaluated 08-15: study, do not adopt

v1 relaunch 2026-03: Next.js 16.2 + React Compiler, AI SDK 6 + Gateway,
shadcn/Tailwind, Neon Postgres, Auth.js, ~20k stars. It is an APP template you
clone as your whole product — for us that is the wrong chassis (Next; we ruled
TanStack Start), the wrong skin (reskinning shadcn to Safelight = fighting the
whole component layer), and the wrong shape (a chatbot page-app; our chat is
one floating panel in a workbench). Adopting it would replace oneiron-web.

Study it as the best reference IMPLEMENTATION of the AI SDK parts model
(complements assistant-ui's architecture): message-parts persistence schema in
Postgres · **resumable streams** (close mid-generation, reopen, the stream
picks up — exactly our panel-over-live-runs) · **persistent chat shell** that
never unmounts between chat switches (our panel keeping scope state) · the
artifact panel (version browsing, diff toggle, manual edit updates in place
while AI changes mint versions — prior art for document-grade GenUI beyond
widget cards) · tool security checklist (ownership checks, zod validation).

Licenses in passing (study only): assistant-ui, LibreChat, use-stick-to-bottom,
Langfuse-core MIT; Chainlit Apache-2.0; AI Elements "Other"; Open WebUI custom;
Chat SDK (vercel-labs/chat) Apache-2.0.
