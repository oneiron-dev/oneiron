# Calendar prep: counterparty obligations

Calendar prep adds open CMT-5 obligations when an EVENT attendee reference directly
names a CounterpartyContact. It does not turn a PERSON id, name, vendor string or
`mailto:` URI into a contact. Those attendees keep their existing PPR evidence.
There is no new identity resolver, stored prep cache, timer or permission.

Both the raw and actor-scoped prep builders add the two ledger directions. A
self-owed obligation appears once in prep. An obligation already returned by PPR
also appears once. Missing or non-contact attendees do not fail the existing pack;
real ledger/storage errors still propagate.

The scoped builder keeps its current PPR run, then uses the native terminal pack
filter for the serving cut. The existing filter algorithm and cleanup have one
implementation. A same-transaction projection reads the contact and identity's
four selected label heads plus each obligation through the actual caller's native
read lane. A kept PPR candidate is not permission to read these additional rows.
Withheld labels or commitments do not become raw text. The rendered commitment
text is decoded from the caller's projected row, not copied from the raw ledger.
The new items cite their actual commitment and deciding label heads.

All new evidence must have been learned by the supplied fire instant. The existing
eligibility, EVENT/attendee PPR seeds, three-hop walk, 64-candidate PPR limit, nine
types, section order, recency order, blank result and 250-word default remain.
The ledger adds candidates outside the PPR walk; the existing final word budget
still applies to the combined evidence. Prep does not adopt the ledger's due sort.
No extra contact-active or send-consent gate is imposed on reading obligations.

This is a direct-contact attendee slice. General attendee-to-contact resolution,
complete off-record overlay coverage and runtime proof are not claimed. The raw
builder retains its unrestricted API. No migration, feature flag, configuration or
special deployment step is needed beyond the engine/server rollout.
