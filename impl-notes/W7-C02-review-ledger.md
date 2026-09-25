# W7-C02 review disposition ledger

Scope: branch `w7/W7-C02`, source head `f2c7712c` before authorized-audio continuation.
Collected before new review-driven fixes on 2026-09-19.

## Review surfaces and original roots

- `gh pr view` reports no PR for this branch. All-state `W7-C02` PR search returns
  an empty list. Factory state has no publication or reviewer stage, only the prior
  writer-blocked result. There is no ticket PR number, so top-level comments,
  reviews and inline threads from Qodo/Codex/CodeRabbit do not yet exist to page.
  This is **no PR**, not a pending bot or a quota error. No GitHub disposition was
  posted, and no unrelated PR (including #933) is a substitute destination.
- Original internal roots are `.w7/review-current.md` and
  `.w7/pack-map-integration-review.md`. Their complete contents are preserved.
  The later narrow receipt reviewer delivered no packet and lost direct custody;
  it supplies no review result. Root's actual receipt follow-up findings are in
  the receipt admission section of `impl-notes/W7-C02.md` and its passing tests.
- After publication, fetch every page of issue comments, reviews and inline
  review threads for the actual PR before any additional bot fixes. Preserve
  source IDs, review roots, quota failures and already-running jobs. Post changes,
  skips, tested source heads and actual validation to that PR only.

## Deduplicated internal findings

| ID / source | Disposition and evidence |
|---|---|
| IR-01 review-current P0 calibration supersession | Already fixed. `critic/review/outcomes.rs` uses the non-reserved `supersede_claim_in_txn`; two-round calibration evidence is retained. No repeat fix. |
| IR-02 review-current P0 composite supersession | Already fixed. `affect/state_index.rs` uses the non-reserved supersession door; existing idempotence/progression fixture passes. |
| IR-03 review-current P1 cross-review outcome | Already fixed by a stronger binding. `persisted_artifact` loads the exact private result by verdict ID, checks its stored verdict and artifact membership, then verifies the independently stored artifact. Reusing a run string cannot pair another review. |
| IR-04a review-current P1 forged critic heads | Already fixed. Producer writes stamp exact body digests; reliability/outcome reads require that local stamp and `claim_surfaceable`. Peer/raw assertions alone cannot calibrate. |
| IR-04b review-current P1 forged composite heads | FIXED and validated. Local producer/body binding rejects raw/replayed/future forged heads and modified bodies; imported history stays non-authoritative. The expanded fixture covers idempotence, supersession, repair and reopen. Durable guarded-Arch test at dd5ced70 exited0 on 2026-09-19T18:06:15.995848Z: 1 passed,0 failed,0 ignored. Receipt: `W7-C02-portable-state-validation.json`. |
| IR-05 review-current P1 rerun after Beta drift / inactive cache | Already fixed for posterior drift by immutable private result identity and cached triage. Changed lifecycle/body cannot return as an unchanged cached result because producer digest verification refuses it. Skip proposed silent re-review under the same immutable run identity; a new review needs a new run. |
| IR-06 review-current P1 confidence order/weights | Finding identity now includes `finding_key`, fixing dropped votes/order sensitivity. Skip posterior-normalized denominator: unanimous weak critics would become confidence 1.0. Current denominator counts all distinct votes uniformly while agreement is attenuated by posterior; it does not depend on host order. |
| IR-07 review-current P1 self-attested outcome source | Already fixed: every anchored source requires the active human-owner gate. A second conflicting source/outcome for an artifact refuses rather than double-counting or silently accepting it. |
| IR-08 review-current P2 representative order | Already fixed: merge sorts by artifact ID before selecting representative. |
| IR-09 review-current P2 stale/approval/lifecycle readers | Already fixed for critic paths through `claim_surfaceable` plus producer digest. Composite read gap is deduplicated into IR-04b. |
| IR-10 review-current P2 F64 signals | Already fixed: finite unit F32 and F64 accepted by the owning scalar input read. |
| PM-01 pack-map review credential/numeric payload escape | Already fixed with typed export/import representation, canonical name/hash metadata and mandatory payload redaction; retained mapping/redaction fixtures. No generic base64 exemption. |
| PM-02 pack-map review shared-byte overflow | Already fixed with name-discriminated handle 247, immutable identity/generation bindings and two-vault remapping fixtures. |
| PM-03 pack-map review source/schema/install authority | Already fixed: exact real source facets bind schema identity; source arrival does not install. Qualification, scanner, publisher and authenticated consent remain separate doors. |
| RC-01 root follow-up receipt-ID collision | Fixed at fa8a7337. Per-claim archive binding precedes native fallback; actual native receipt is unchanged. Featureless and expanded all-feature evidence retained. |
| RC-02 root follow-up conflicting raw/replay receipt bindings | Fixed at 995c5435/f1bf856d. Immutable holder/body/ref slot, both arrival orders, atomic refusal; selected 10-test run passed. |
| RC-03 root follow-up uncited pending receipt payload | Same repair: exact body must cite source; bad pending payload retires without vetoing or retiring the legitimate holder. Same 10-test run passed. |

## Current validation / publication boundary

Existing 10 receipt cases, three strict clippy lanes, strict rustdoc and structural
checks retain their exact source boundaries. Later strict featureless clippy and
7 native protocol cases passed. IR-04b's last missing portable runtime fixture
now passes on guarded Arch at dd5ced70 (actual exit0, 1 pass). No broad suite was
repeated. The original lost transient queue attempt remains a no-result failure
of custody, not test evidence.

The committed audio evidence contains actual Mac-native EN/UK/MOSS synthetic runs
and a correctly refused JP zero-duration interval. These are not E1/E3 or full
native-artifact acceptance. Only the explicit external access, admitted cleanup
instructions, reference/enrollment data and post-E1 default act remain. See the
current per-step ledger and final result in `impl-notes/W7-C02.md`.

A fresh branch PR lookup after the portable result again returned no PR. No Qodo,
Codex or CodeRabbit surface exists on this ticket to paginate or post to yet.
No unrelated PR is used. On actual publication, collect all pages and post the
source-bound changes, explicit skips and actual validation to that PR only.
