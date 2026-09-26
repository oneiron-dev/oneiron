# Packet C — claims-read enforcement and clocks

**Status:** proposed probes, no verified new defect. Bound: one same-transaction read comparison and one clock boundary matrix. Baseline `e17eeb2b`.

## Claims-read migration (July surface 5)

Canon: generated `oneiron/core/oneiron-arch-0057-claims-read-gate-door-v1.md` §§3, 5–6: registry-first, enforcement heads plus matching override, locally compiled posture, same-transaction gate read, then retire COUNTERPARTY_CONTACT as communication authority. §6 explicitly rejects a partial authority split. This is tracked by [ONE-1752](https://linear.app/oneiron/issue/ONE-1752/comm-cutover-type-132-demotion-behind-the-claims-read-gate-door), **not a newly discovered defect** merely because it is unfinished on this baseline.

Reached path: `crates/oneiron/src/comm/claims.rs:171-240` defines pure-data `comm.*` descriptor rows, not a runtime registry; `gate/effect/effect_contacts.rs:40-118` still hydrates `counterparty_opted_out` from the type-132 contact record while the override comes from a claim head and trusted store clock. `gate/resolution/evaluation.rs:182-209` applies the override/escalation posture. Trace actual send/admission callers and receipt emission, not only `get_claim` (the deliberate history read). Focused tests live under `comm/tests.rs`, `gate/tests/` and `counterparty_contact/tests.rs`.

| Probe | Setup and attack | Observable expected result and stopping rule |
| --- | --- | --- |
| C1: conflicting authorities | For one counterparty and channel, establish a restrictive `comm.opt_out` or `comm.do_not_contact` head and a divergent type-132 cached state, plus a matching, mismatching and expired `comm.send_override`. Run the real ExternalEffect send gate under each local posture; also include a contact `first_touch` control. | Compare typed Gate decision and receipt reason to canon: restrictive heads + posture decide; a scoped override does not clear the claim; malformed/unreadable head cannot fail open. **Before ONE-1752 lands**, record a demonstrated behavior only as an existing cutover gap, not a surprise new bug; do not make an ad hoc partial cutover in this audit ticket. Stop at gate decision + receipt. |

## Caller-clock discipline (July surface 6)

Canon: generated `oneiron/identity.md` and `oneiron/sync/oneiron-arch-0023b-crdt-sync-implementation-v1.md` for time-bearing authority and replay, plus banked decision 10b (`/home/lexi/w8-opus/int/notes/w8/banked-decisions.md`): holder proofs are checked against the injected **store** clock. A public parameter named `now` is not itself a defect. Pure evaluation may legitimately take caller time; authority mint/expiry and durable stamps may not treat it as a trusted clock without a documented boundary.

| Probe | Setup and attack | Observable expected result and stopping rule |
| --- | --- | --- |
| C2: expiry/skew matrix | Inventory public `now`/`now_ms` parameters by crate and classify each as pure snapshot evaluation, trusted store-clock input, or external authority. Classify event metadata, pure as-of query, maintenance scheduler and authority/lease decisions; select the public checkout lease (`checkout/lease/lifecycle.rs:37-75,95-148`) and symbol lease (`task_verb/symbol_lease.rs:112-145,165-183`) as high-yield authority cases. Compare grant proof and comm override as trusted-clock controls. Hold StoreClock fixed; pass past, far-future and backward-jump timestamps through the public door, then close/reopen or export/import when the result is durable. | An adversary-chosen timestamp cannot extend a permission or make an expired head fresh; a pure evaluator using explicit `now` produces predictable time-relative results. Record exact signatures, callers and typed outcomes. Stop after one reproducible case per class; do not mechanically prohibit caller time everywhere. |

Prior Wave 8 authority audit traced grant-expiry predicates and found no new proven clock defect there (`/home/lexi/w8-opus/audit/authority/REPORT.md`), but it did **not** inventory all public clock inputs. Reuse its caller list as a starting control, not a current verdict.
