# F3.12 promise ledger

Line references are 1-based in the files read on 2026-11-13. No engine implementation was read.
Sources (canon paths are under the docs repository's `generated/oneiron/`; aliases name documents, not additional specifications):
- B = the builder's F3.12 brief (13 Nov 2026), which restates the MEMORY-01 and MEMORY-07 journeys of J and the operations and invariants of D.
- D = Fable's test-strategy verdict 52 (10 Nov 2026), section 4 and section 5 item 1.
- C = canon ARCH-0003, semantic memory (`core/oneiron-arch-0003-semantic-memory.md`).
- M = canon ARCH-0055, entity merge and split (`core/oneiron-arch-0055-entity-merge-split-consent-ramp-v1.md`).
- X = canon ARCH-0038, deletion (`core/oneiron-arch-0038-deletion-redaction-canonical-snapshot-v1.md`).
- W = canon ARCH-0040, write gates (`core/oneiron-arch-0040-write-gates-provenance-trust-v1.md`).
- R = canon ARCH-0057, the claims read gate (`core/oneiron-arch-0057-claims-read-gate-door-v1.md`).
- J = `tests/e2e/memory.test.ts` in this repository (journey comments only).
- I = canon ARCH-0022, the identity world model (`identity/oneiron-arch-0022-identity-world-model-v1.md`).

## Rules: one model rule and its promise sentence per line
- Independent maps and seeded replay, including restart: D:132-137, “from the promise text” and “seeded generator sends the same random verb sequence”.
- Compare after writes, not just successful replies: D:110, “Read back every write”; D:135, “After each step it compares”.
- Question identity excludes the answer: C:231, “conflictSet keys the question, never the answer”; C:239, profile.name conflict set is “subject+predicate”.
- Questions also separate exact audiences: B:23, “same question and the same audience”; I:180, “a claim never merges across two projects”.
- Owner writes stand immediately and close the old head: B:23, “owner's own direct correction ... also supersedes A immediately”; C:139, “lifecycleStatus flips to superseded and its validTo is stamped”.
- Propose-mode agent writes are Proposed and do not close the old head: B:23, “B lands Proposed, not standing”; W:131, “destructive supersede/retract defers closure until approval”.
- Owner approval stands the proposal, closes the old head and links new to old: B:23, “B becomes the standing head ... A is superseded ... B's supersedes link names A”.
- Only a Proposed claim can be settled, once: W:302, “A proposal settles once”; J:56-57, “required authority ... holder approves exactly the reviewed alternative”.
- Rejection retains the old standing head and retains the rejected row: C:125, “All non-current states are still stored”; B:37, “settle a Proposed claim”.
- Writers remain attributed to their actor, not the approver: D:125, “receipt chain names both actors”; C:84, “stays attributed to its author”.
- Supersession is not deletion: C:143, “lifecycleStatus moves to ... superseded ... nothing is deleted”; J:62-63, “new-to-old supersedes edge, closed validity windows”.
- Merge retains all claims and changes redirects, never subjects: M:71, “both entities' claims remain, subjects intact, read through one canonical head”; M:223, “Claim subjects keep original entity ids forever”.
- A merged source stays an entity, not a tombstone: M:66, “loser is never deleted, never tombstoned”.
- Split can assign inherited claims as well as original ones: B:24, “inherited is assigned to south”; M:98, “reassignment map assigns every claim ... of E to a head”.
- Unassigned inherited claims remain on the survivor before and after split: B:24, “before any split assigns it ... remaining claims”; M:100, “Unattributable residue stays on E ... never force-assigned”.
- A foreign claim cannot be assigned by split: B:24, “still does not assign a claim of an entity that was never merged into the split entity”.
- Assignments change membership, never stored subjects or scope: M:223, “original entity ids forever”; B:32, “no widening ... means ... unchanged”.
- Delete excludes a claim from every live observation: X:230, “Removes it from the vault at once”; X:195, “sync cannot resurrect the entity”; B:38 specifies owner/user delete.
- Restart is identity on all modeled state: B:38, “everything in this model is durable: a restart changes nothing”; D:123, “Write, kill, restart, read back equal”.
- Scope is four required axes: C:94, “worldId, scopeFacetId, scopeRelationshipId and scopeProjectId”; C:80, “audience axis is the PROJECT entity”.
- Each write must be carried by the actor's Grant: R:28, “Every claim write takes the gated write path”; R:34, “refuses a write the Grant does not carry”.
- The owner can rule in their vault; an agent cannot raise its own ceiling: R:33, “owner's own Grant is un-narrowed”; R:114, “actor raising its own ceiling ... can never become standing”.
- Visible means recall-eligible, not inspectable history/review: C:82, “auto, approved ... active ... stale = false”; J:54-55, Proposed remains “inspectable” but is not recalled.
- Read disclosure excludes scopes not held by the credential: R:110, “A disclosure miss hides”; I:125, “reads only records ... in that set” and “owner is never limited by a facet”.
- I1 compares live, held, remaining and assignment sets, not just a total: D:124, “Merge then split keeps every claim”; B:49, “for every entity ... sets equal”.
- I2 compares head count, exact heads, statuses and supersedes links: D:124, “Approve leaves exactly one live version”; B:50, “at most one; statuses and supersedes links equal”.
- I3 compares exact labels and allows only read subsets: B:32, “Do NOT invent an ordering between opaque scope ids”; B:51, “visible set is a subset”.
- Unobserved fields impose no assertion: B:52, “only the fields it can read ... not observed”; an observed empty set still asserts emptiness.

## ASSUMPTIONS / adapter contract
- Default Universe: 6 non-owner persons, 3 ordinary single-valued predicate slots, 2 agents, 2 audiences; Owner is separate from every Ent (M:75 owner-retirement rule is never exercised).
- QKey is a predicate slot, not a whole question. Use Question { subject, predicate, audience } for head observations; subject is the immutable original, not a topology-resolved head.
- Predicate 0 can bind profile.name. Bind other slots only to ordinary single-valued predicates with the same correction contract; no set-valued, Generated, projector-only or enforcement classes.
- Value is a u32 symbolic value, not a text normalizer. The adapter maps each token to a distinct valid engine value; generator values equal fresh claim ids.
- Create two unrelated projects P_private/P_shared. Aud(0) = (base world W0, facet F0, relationship all, P_private); Aud(1) = (W0, F0, all, P_shared). These are exact tuples, not ordered scope ids.
- Owner reads/writes both projects. Each configured Agent holds an explicit propose-mode write Grant and read authority only for P_shared; no agent can call owner-only settlement/delete. No facet limit, world default, relationship or project ancestry changes occur.
- Those Grant/read assignments are fixture choices, not universal agent ceilings. Agents may be more powerful in real deployments. Proposed agent content here is a review candidate, not an autonomous Generated supersession.
- visible_to is the maximal eligible set for an explicit read over the actor's configured scopes; ranking may return any subset. Review/history reads must not populate Observed.visible.
- Standing abstracts auto/approved + active + open validity; Superseded abstracts noncurrent + closed validity. Compare end-time presence, not numerical timestamps. Rejected/Proposed are not recall-eligible. All modeled claims are non-stale.
- When engine lifecycle/approval/validity cannot consistently map to Status, record statuses[id] = None (observed invalid/absent), not an omitted entry. A known deletion tombstone maps to Deleted, even if its payload row is gone.
- Deleted retains only oracle bookkeeping for non-reuse, not a claim that engine reads must return. audience(missing/deleted) is Aud::ABSENT (255), an observation sentinel, never a valid stored scope.
- claims_held_by is the brief's accounting view: direct subject plus inbound merge-chain subjects, unless explicitly assigned to a different head; an assigned claim belongs only to its assigned head. remaining_on excludes every assigned claim.
- Thus a source and its survivor can both report an unassigned inherited claim; I1 never sums per-entity buckets. This is not the 0/1/N resolver result or the discounted residue display through all split heads (M:99).
- Fresh split heads are untouched placeholders in the fixed universe; the adapter mints/binds their actual ids as needed. No claim/merge/split history may already use a requested fresh head.
- Merge conflicts keep separate original-subject questions until consolidation (M:71); this model never silently picks a winner across two subjects.
- C:157 says “old row stays standing”, conflicting with C:139/143's closure. The explicit MEMORY-01 promise B:23 and the precise closure table govern this model.
- Missing Observed map keys mean not observed; a present empty Vec means observed empty. live=None means unobserved. statuses[id]=None means observed absent/invalid; supersedes[id]=None means observed no link. Unknown scope reads may use Aud::ABSENT.
- All observation vectors are sorted by model ids. Invariant comparisons ignore input ordering but reject duplicate rows in equality/count fields. No numeric engine id ordering is assumed.
- Generator draws: 6/16 approval motifs, 4/16 merge/split motifs, 1/16 each owner write, proposal, settlement, delete, merge, restart. A motif may be truncated at requested length; rejected trial state is discarded.
- Split motifs choose assigned versus unassigned inheritance equally. SplitMix64 uses wrapping u64 arithmetic and modulo sampling over ordered vectors; at most 32 redraws precede an Applied Restart fallback. len=0 returns empty.
- No receipts, real clock, stale transitions, erasure-byte sweep, undo, federation or credential verification are asserted by these three first-step invariants; those need separate doors/tests.

## UNSPECIFIED (no mutation)
- Writes or settlement involving topology-participating subjects: cross-original-subject supersession after merge/split and projection-versus-provenance question choice are not decided by this first-step contract.
- Re-merging an already-merged entity, merging a split original/head, or splitting a merged shell, prior split original or split head: no repeated/nested-topology transition contract is pinned here.
- Zero/one split heads: M:96 names resolver semantics, but not this subset's fresh-head/residue assignment contract. Nonfresh heads may carry conflicting earlier topology; only fresh 2+ head splits are modeled.
- Delete touching either end of supersession history: the text does not settle predecessor revival or removal/retention of the other endpoint's link in this abstraction; in particular deleting a standing successor is never guessed to revive the old head.
- Repeated delete: response/idempotence semantics are not pinned, although a deleted claim stays absent. Reusing a claim id is Refused, never resurrection.
- Exact restatement of a Standing/Proposed value: M:283 names “Exact-duplicate write suppression”; identity/dedup versus a fresh correction id is outside these steps. A changed answer can still return to a previously superseded value.
- Aud ids 2+ within a larger configured audience count: no named four-axis fixture/read-authority mapping is provided. Out-of-range ids, invalid request shapes, foreign/repeated assignments and missing grants are Refused.

## Validation boundary
- Unit observations deliberately reproduce both documented broken states; they prove the oracle rejects those states, not that historical engine commits have been run here.
- The builder must bind engine ids/scopes/actors and run the pre-#6930 and pre-#6924 commits. This lane used only rustc/rustfmt, never cargo or engine source.
