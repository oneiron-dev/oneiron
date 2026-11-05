# Commitment reminder wording

The fixed reminder stays available while model wording is absent. The owner
reminder route opts into wording with `voice: Some(CommitmentReminderVoice)`.
`persona_ref: None` asks for a neutral voice. A named `persona_ref` is an opaque
host reference, not a PERSON id and not permission to read that person.

## Host configuration

The consumer runs on the existing `generative_reasoner` model role. Each attempt
uses `[models.chat].turn_budget_units` through the native budget policy. It uses
`[models.workflows].retry_backoff_secs` for failed-wording retries and scheduled
queue rechecks. Changing that existing setting also changes wording retry cadence.
There is no separate role, budget default, retry cap, or delivery wait.

The host starts the consumer once for attached and standalone hosts. Without a
configured generative seat, work stays queued. It does not require a running
Dreamer pass or create a chat conversation or reply.

The shipped instruction is configuration data in
`crates/oneiron-server/src/config/models/commitment_reminder_wording.json`.
Override it with one of the existing inline/file prompt forms:

```toml
[models.dreamer.wording]
commitment_reminder_prompt_file = "prompts/reminders.txt"
# Or: commitment_reminder_prompt = "..."

[models.dreamer.wording.commitment_reminder_personas]
"helper-voice" = "Use brief, plain reminders."
```

A relative prompt file resolves against the configuration file's directory.
The two prompt forms are mutually exclusive, as for the other host wording.
The persona map is empty by default. A named voice without configured text
retries wording; it does not invent a persona and never delays the fixed send.
The existing confession instruction and its settings are unchanged.

## Memory and model destinations

The consumer uses the actual native Dreamer system principal with the existing
strict relationship-grant scoped reader. Resolving that principal grants no
read privilege. Model configuration is not a memory grant.

Each model offer observes the authorization clock before opening its source
snapshot. It reads the actual current commitment head through native scoped
admission bound to that offer's destination. The admitted words, route offset,
read receipt, and model-world verdict share one read transaction. A missing or
closed reminder is distinct from a withheld source. No owner key or unscoped
source fallback is used to send data to a model.

The source hook retains the destination-bound read before sending and rechecks
current policy, head, revision, and wording immediately before the send. It
rechecks again before filing a returned wording. The promise and due time enter
the request as data; persona text comes only from host configuration.

## Filing, retries, and cancellation

The existing trim and 4 KiB maximum still apply. Filing re-reads the frozen
attempt payload and checks its exact lease generation, cancel state, selected
source head, and stored-body revision in the same writer as artifact creation
and version append. A stale worker cannot publish through this door.

The existing approval-prefix rule is unchanged: wording filed after approval
is kept under the unsent prefix, never substituted for the approved send text.
Both kinds of model-worded version retain the exact admitted source head and
revision in the existing version provenance receipt. That receipt records a
source; it does not grant permission to read it or prove model-run capture.

Served exports pin the exact version before checking its source binding through
the actual caller's read lane. A later head or a mutable artifact name cannot
replace that version's source contract. Source admission is separate from an
artifact's own-row coverage; an artifact reference is not a grant on its inputs.
The check does not introduce an input-visibility rule for unrelated artifacts.

When this vault holds a native local wording version, scoped byte reads of
its backing ASSET apply the source contract in the reader's own lane
(FIX 4997 R2). The bytes read only through a complete local alternative: a
protected version whose source and revision the caller admits, or a genuine
body-owning default raw version at the same hash that the caller reads.
Without a local protected version, existing ASSET behavior is unchanged.
Replica-only claims prove no independent body-owning writer and cannot clear
a locally protected read. Source admission for replica-only wording carriers
remains unimplemented under FIX 13484 / 13260 (output-sync).

The raw filing API still accepts privileged caller-owned text. It does not
invent a source revision for that text and is not a fallback for model output
whose source is withheld. The fixed-reminder/send paths remain available
unchanged.

A model, source, configuration, budget, or filing error schedules a new try
through the native retry door. `attempt_count` fences a lease; it is not a retry
counter and does not impose a cutoff. Error stages are stored without prompt or
reminder text in logs.

A soft cancellation lands the owned attempt with a restart cursor and no
automatic successor. A forced cancellation or lost lease stops the old worker's
result. Host shutdown interrupts a pending model future and requeues still-owned
work. These paths use the existing attempt lifecycle, not a second status store.

Artifact filing and final queue settlement are separate operations. A crash
between them can repeat model work; the artifact identity remains tied to the
same frozen reminder. Identical bytes with the same native source binding
deduplicate. Identical bytes with a different source or revision require a new
version through the existing explicit-parent append, rather than silently
reusing another source's version. No atomic artifact-plus-queue or runtime
proof is implied by this implementation.
