# Meeting follow-up drafting

A meeting transcript's landing queues one `calendar.follow_up.draft` attempt for
its SESSION (CAL-08; Engine RULING CAL-08-FOLLOWUP-APPROVAL = A). The host
worker in `crates/oneiron-server/src/ai_host/meeting_follow_up_drafting.rs`
claims it, asks the drafting model which follow-ups the owner promised, and
files the reply. Every follow-up lands as a draft in the owner's inbox; only
the owner's approval sends it. The worker never sends.

Only the owner's own promises become drafts. The engine marks the TURNs whose
speaker label is one of the owner's names, so until the owner's name is in the
vault, no transcript yields a draft. A draft goes only to a PERSON the vault
knows by a name the transcript says.

## Host configuration

The worker runs on the existing `generative_reasoner` model role. Each attempt
uses `[models.chat].turn_budget_units` through the native budget policy, and
`[models.workflows].retry_backoff_secs` between tries. There is no separate
role, budget, retry cap or feature flag.

The host starts the worker once, for attached and standalone hosts. Without a
configured generative seat, attempts stay queued. It needs no running Dreamer
pass and creates no chat conversation.

The shipped instruction is the engine's
(`crates/oneiron/src/calendar/follow_up/producer/instruction.md`), and so is the
reply contract it states. Override the wording with one of the inline/file
prompt forms:

```toml
[models.dreamer.wording]
meeting_follow_up_prompt_file = "prompts/follow-ups.md"
# Or: meeting_follow_up_prompt = "..."
```

A relative prompt file resolves against the configuration file's directory.
The two forms are mutually exclusive, as for the other host wording. A
rewording must keep the reply contract: the engine files only a reply in it.

## Memory and model destinations

The worker reads as the vault's Dreamer, through the strict relationship-grant
scoped reader. Each model offer reads the SESSION through the scoped read bound
to that offer's destination; a TURN the destination may not receive holds the
rung, and a recipient it may not read is not listed. The transcript enters the
request only in that destination-admitted hook. The worker rechecks the read
after the model answers, and the filing checks it again in its own writer.

## Filing, retries and cancellation

Before any model call, the worker reads the SESSION for this device, the widest
destination. A SESSION that is gone, is not a transcript, has no TURN left, or
gives nothing to draft from (no owner speaker, no listed recipient, a transcript
past the size cap) completes the attempt with no model call.

A TURN whose words no read may serve (deleted, stale, held from use, or derived
from a source that no longer stands) leaves the SESSION's read for good, so it
never holds a try.

A reply outside the reply contract completes the attempt with no draft: asking
again would spend the budget on the same refusal. Each item of a reply in the
contract is judged alone, so one refused draft leaves its siblings filed.

A model, source, configuration, budget or filing error schedules a new try
through the native retry door, with no cutoff. A destination that holds the
transcript, or may list none of its recipients (a world it may not reach),
retries the same way, until a model that may see them is configured or the
hold clears.

The size-cap check runs at the widest destination only. A transcript within a
few names' bytes of the cap there completes with no draft, though a narrower
destination, which lists fewer recipients, might fit under it.

A soft cancellation lands the owned attempt with a restart cursor. A forced
cancellation or a lost lease stops the old worker's result. Host shutdown
interrupts a pending model future and requeues still-owned work.

Filing and queue settlement are separate operations. A crash between them can
repeat the model call. A draft's id is derived from the SESSION, the recipient
and the words, so a repeated reply in the same words finds its drafts already
filed; a reply in other words files new drafts beside them.
