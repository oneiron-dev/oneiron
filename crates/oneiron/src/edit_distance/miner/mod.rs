//! ED-04 (ONE-1760, ARCH-0056 §4): the recurring-substitution miner — the
//! Dreamer session-end pass that turns a REPEATED correction into a proposal.
//!
//! ```text
//! judged amendments (ED-03)  ──> Δ (ED-01) ──> proposal artifact (ED-00)
//!    └─ substitution runs ──> normalized token pairs ──> per-scope clusters
//!         └─ >=K distinct receipts ──> chooser
//!              ├─ lexical  ──> preference.phrasing claim (Proposed, gated)
//!              └─ content  ──> gated skill-edit proposal (ONE-1448's source)
//! ```
//!
//! # Recurrence, not weighting (§4, ruling r3)
//!
//! One changed word is not a signal; the SAME changed word across K distinct
//! amendments is. So nothing here scores a substitution — the mining is
//! mechanical (exact normalized pairs, bucketed) and the semantics come from
//! the count. There are no embeddings, no stemming and no similarity: two
//! substitutions cluster when their normalized text is EQUAL, which is the one
//! rule a reader can check by eye.
//!
//! # Where the pass runs
//!
//! It rides the LANDED SessionEnd wake as a consolidation-scope job —
//! `dreamer_consolidation`'s executor dispatches
//! [`DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE`](crate::dreamer_consolidation::DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE)
//! exactly as it dispatches the reflection gap scan: a payload discriminator on
//! the existing queue, never a second wake mechanism.
//!
//! The registration is
//! [`register_substitution_mine_in_txn`](crate::dreamer_consolidation), inside
//! `Vault::end_session_with_wake`'s own close transaction and dedupe-keyed on
//! the sitting — so the pass is a durable fact of the close rather than
//! something the closing process meant to do, session close never blocks on it,
//! and a pass that dies is simply re-admitted by the queue. Concurrency is not
//! assumed away: the emission's dedup check runs INSIDE its write transaction,
//! so two passes running at once still mint one proposal per cluster.
//!
//! # Two ledgers, one law
//!
//! * **Counts are never stored.** [`mine_substitution_clusters`] recomputes
//!   every cluster from the judgment ledger on every pass (doc-13 r1, the
//!   `skill.reliability` posterior posture). The watermark is a WORK GATE —
//!   "did anything new arrive?" — never a counting boundary; a cluster's
//!   recurrence accumulates across sittings because nothing ever consumes it.
//! * **Emissions are marked.** A cluster that emitted records a MINT-MARK in
//!   the SAME transaction as its proposal, and the dedup check that gates that
//!   emission READS the marks inside that same transaction. Both halves land or
//!   neither does, and nothing can slip between the check and the write, so one
//!   cluster mints one proposal even when two callers race.
//! * **The watermark advances ONCE, at the end of a pass.** It is a pass-wide
//!   work gate, and folding it into a cluster's transaction would make the
//!   first emission speak for clusters it never reached: a pass that died
//!   between two eligible clusters would leave the second one behind a bound it
//!   never earned, and the replay that should have emitted it would find
//!   nothing new to do. The mint-marks are what make the replay emit ONCE; the
//!   watermark only decides whether a replay does any work at all.
//!
//! # Hysteresis is a dial, not a wall
//!
//! A cluster whose proposal is OPEN, or which already landed, never
//! re-proposes. A cluster whose proposal the decider REJECTED goes quiet for
//! [`MINER_REJECTION_COOLDOWN_SECS`] and may then speak again — the sibling of
//! `DREAMER_GAP_DECAY_MS`'s escalate-or-let-go rule. Nagging is the failure
//! mode; permanent silence after one "no" is the other one.
//!
//! Both emission classes answer that question the same way, because both have
//! to: the preference arm reads the tray row and the gate ledger the inbox door
//! writes, and the skill-edit arm reads the DECISION its own proposal row
//! carries ([`resolve_mined_skill_edit`] is the door ONE-1448's gated apply
//! answers through). Row-existence alone cannot say "rejected, recently" — it
//! collapses a no into either permanent silence or instant re-proposal — so the
//! verdict is recorded rather than inferred from a deletion.
//!
//! # A proposal nobody can answer is not a proposal
//!
//! Both emissions are PROPOSALS, never applications, so both are worthless
//! unless a decider can reach them. That makes two things load-bearing rather
//! than cosmetic: the preference claim's envelope must carry the `Agent`-class
//! Generated dreamer provenance `gate.rs` derives an INBOX GROUP KEY from, and
//! it must NOT carry a session tag (see `miner_envelope`). [`MinerRun`] is
//! shaped by that requirement, and the pass refuses rather than landing a
//! proposal into a tray with no group.

mod config;
mod emission;
mod mining;
mod model;
mod store;

pub use self::config::{
    MINER_K_DEFAULT, MINER_K_SETTINGS_KEY, MINER_REJECTION_COOLDOWN_SECS,
    PREDICATE_PREFERENCE_PHRASING,
};
pub use self::mining::{
    classify_substitution, mine_substitution_clusters, miner_attempt_input, miner_k, miner_run_id,
    miner_session_from_input, run_substitution_miner, set_miner_k,
};
pub use self::model::{
    MinedOutcome, MinedSkillEditDecision, MinedSkillEditProposal, MinedSkillEditVerdict, MinerRun,
    MinerWatermark, SubstitutionClass, SubstitutionCluster,
};
pub use self::store::{
    mined_skill_edit, miner_watermark, pending_substitution_skill_edits, resolve_mined_skill_edit,
};

// The flat miner.rs module used to provide these names to the sibling test
// module through `use super::*`: every miner-internal item the tests name
// bare, and the crate/std imports the tests name bare. After the directory
// split the seam re-imports both so `tests.rs` resolves exactly as it did
// before.
#[cfg(test)]
use self::{config::*, emission::*, mining::*, model::*, store::*};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::actor_claims::edit_cost_scope;
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimSource, ClaimSubject};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::write_envelope::{ClaimCandidate, WriteActor};
#[cfg(test)]
use rmpv::Value;

#[cfg(test)]
mod tests;
