# Training-offer comparison and measurement provenance

The typed-question model-trial decision treats both `Better` and `NotWorse`
quality as eligible at a measured candidate cost no greater than the incumbent's.
Equality is included. The existing per-trial `auto_approve` and
`candidate_needs_download` fields still select `AutoApprove` versus `Offer`.
Unknown quality, worse quality, and the better-but-pricier tradeoff paths are
unchanged. This decision records a trial result; it does not itself switch a
binding or acknowledge a download card.

A Coach offer's `evidence.paired_measurement` is the 32-byte request key of the
native Final paired measurement that supplied its card. The real measurement
producer supplies it only after reading the exact requested Final row and card.
The offer's committing transaction reads that same key again and checks:

- Final state and the row's own digest matching the key;
- the exact seat, incumbent and stock candidate model/revision, with no skill arm;
- the same cohort, rubric revision and nonempty card;
- every native measurement exposure occurring in the offer's evidence;
- a settlement time no later than the offer time.

Only the optional key is cleared when those checks do not match or its source
cannot be read. The existing evidence card, pilot validation, manual choices,
and owner-answer flow stay intact. The offer digest includes the qualified key,
so an answer binds the provenance actually stored with its immutable snapshot.
Pilot-only cards and other unqualified evidence keep a null key.

This is historical evidence provenance. It is not a claim that the cohort,
registry, scorer, model files or quality comparison remain current. A non-null
key is not auto-approval authority, an authenticated owner decision, a verified
download manifest, or proof that a download card was shown. The persisted STOCK
policy, automatic answer authority and download-card-once path remain separate
engine work. Training never deploys itself through this change.
