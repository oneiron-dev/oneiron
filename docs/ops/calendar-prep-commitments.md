# Calendar prep: counterparty obligations

Calendar prep adds open CMT-5 obligations when an EVENT attendee reference directly
names a CounterpartyContact, or an admitted email attendee exactly matches an
existing contact's party. It creates no contact and does not infer one from a
PERSON id, display name or vendor label. Existing PPR evidence remains available.
There is no new stored prep cache, timer or permission.

Both the raw and actor-scoped prep builders add the two ledger directions. A
self-owed obligation appears once in prep. An obligation already returned by PPR
also appears once. Missing or non-contact attendees do not fail the existing pack;
real ledger/storage errors still propagate.

The scoped builder keeps its current PPR run, then uses the native terminal pack
filter for the serving cut. The existing filter algorithm and cleanup have one
implementation. A same-transaction projection resolves the ledger and admits its
four deciding CLAIM heads (two contact heads, identity channel and address) through
the actual caller's native read lane. A kept PPR candidate is not permission to
read these additional rows. A withheld or future label head drops that attendee's
ledger slice; a withheld or future commitment drops that entry. Existing PPR items
remain. The rendered commitment text is decoded from the caller's projected row,
not copied from the raw ledger. New items cite their commitment and deciding heads.

The commitment scan takes its entity ids and bodies from the serving lane's native
store reader, not from a separate vault-base cursor. A session-backed lane therefore
uses its captured overlay/base union for those obligations, with the same admission
and projected-text callbacks. The unrestricted wrapper still uses the base reader.
Contact and identity labels use that same captured reader, including the contact's
native claim reconstruction and the channel's existing live-head selection. The
shared CLAIM reader keeps its canonical decoding, source-withdrawal checks and
vault-authoritative MACHINE-history projection. Standing party STOP still folds
from the canonical vault; staged content never becomes grant or control authority.
The scoped PPR builder and the final candidate deletion/learned-time reads also use
the serving content reader. The unrestricted builder still supplies the base view.
The public `Memory::calendar_prep` entry still opens its canonical lane. A
session-bound code run opts `vault.calendar.prep` into its captured read context.
EVENT metadata, active deciding CLAIMs, origin binding and source invalidation use
that same content view. Critical-confirm obligations and pending consent remain
vault authority, never staged room policy. A withheld deciding CLAIM still makes
the EVENT unavailable rather than turning the claim into an absent/default fact.

The Session caller routes both retrieval registration and finalization through
`retrieval_telemetry` on the run's captured route. It never opens a fresh route or
writes the room's retrieval ids to base through a canonical builder. The answer
keeps its scoped receipt and returns the EVENT, active deciding CLAIMs and rendered
source refs to the existing code-run release rule. Existing host admission, hooks,
credential checks and final participant admission remain in place.

All new evidence must have been learned by the supplied fire instant. The existing
eligibility, EVENT/attendee PPR seeds, three-hop walk, 64-candidate PPR limit, nine
types, section order, recency order, blank result and 250-word default remain.
The ledger adds candidates outside the PPR walk; the existing final word budget
still applies to the combined evidence. Prep does not adopt the ledger's due sort.
No extra contact-active or send-consent gate is imposed on reading obligations.

An admitted, settled `calendar.attendee` CLAIM can also match a contact by its
exact stored counterparty: a bare address or a lowercase `mailto:` prefix, with
surrounding whitespace removed. Matching does not fold address case or infer a
contact from a display name. It keeps all matching contacts, then rechecks the
selected contact label's exact party before using its ledger. Added items cite the
actual attendee CLAIM as well as the commitment and deciding contact/identity
heads. Existing direct-contact attendees and PPR seeds are unchanged.

The lookup uses the serving content view. Its scan threshold remains vault
policy. Deferred scan observations go to the actual Session's pending checks for
a Session call, or the vault's pending checks for a canonical call; a content
reader's base-forwarding accessor is not used as the room's destination.

General PERSON-to-party resolution, all address spellings, complete off-record
overlay coverage and runtime proof are not claimed. The raw builder retains its
unrestricted API. This change adds no migration, feature flag,
configuration or special deployment step. Deploy the ordinary engine/server update.
