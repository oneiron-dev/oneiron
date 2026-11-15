//! Moved from `crates/oneiron/src/self_heal/heal_context.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::claim::ScopedReadReceipt;
use serde::Serialize;
use serde_json::Value;

/// The one selection hook a heal's context is read under (OF-418 L2, L10).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealContextPolicy {
    /// The seed's whole logical window or failure, every ref its records name, and the
    /// complete retry, run-tree and message-graph ancestry of everything it reaches, each
    /// read once, with no age, depth, count or byte bound.
    #[default]
    RecordedClosure,
}

/// One part a heal's context could not read, and why. Never a refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealUnavailable {
    /// The part, engine-authored: its kind and its 32-hex id, as `body:<id>`.
    pub source: String,
    /// Why: `unrecorded`, `missing`, `missing_or_withheld`, `withheld`,
    /// `withheld:<count>`, `unprovable`, `host_ref`, `not_an_entity_ref`,
    /// `source_withheld`, `response_erased`, `unlinked`, a read's own code or an error's
    /// kind. `withheld`: the reader may not read a row or world the part records it was
    /// read from; `unprovable`: the part records no complete set of the rows it was read
    /// from, so a record part is the vault owner's alone while a body part with unknown
    /// sources stays unavailable off this device; `source_withheld`: a body carries a
    /// secret mark or taint; `response_erased`: an erase of the run's actor took it.
    pub reason: String,
}

/// One stored link a heal's context followed, once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HealLink {
    /// 32-hex id of the attempt or record the link is stored on.
    pub from: String,
    /// 32-hex id it names.
    pub to: String,
    /// `retry_of` or `run_parent` between attempts; `parent` or `spawned_by` from a
    /// message.
    pub kind: &'static str,
}

/// What a heal reads about a failure's recorded cause (OF-418 L2, L10).
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct HealEvidenceContext {
    /// The selection it was read under.
    pub policy: HealContextPolicy,
    /// Every attempt the cause walk reached that the reader may know of (FIX 10814): one
    /// whose record its lane admits, or a root its request named. 32-hex, in source
    /// order: each before the attempts its links name, ties by id, and those
    /// [`Self::cyclic`] names last. Another reached attempt is only an `unavailable`
    /// entry, without its id.
    pub attempts: Vec<String>,
    /// Every stored retry, run-tree and message-graph link followed, once; an attempt
    /// link only when the attempt it is stored on is admitted and the one it names is
    /// in [`Self::attempts`].
    pub links: Vec<HealLink>,
    /// 32-hex ids of the attempts and messages on a link cycle, or reached only through
    /// one, by id.
    pub cyclic: Vec<String>,
    /// Every part it could not read, and why.
    pub unavailable: Vec<HealUnavailable>,
    /// What the reader's scope narrowed across the lane reads the context was admitted
    /// under, conjoined; `None` when no lane read ran.
    pub narrowing: Option<ScopedReadReceipt>,
    /// Everything read, whole: `runs`, `conversations`, `bodies`, `attempts`,
    /// `code_runs`, `reports` and `gate_decisions`. Foreign text rides only here, as
    /// data, never an instruction.
    pub untrusted: Value,
}

impl HealEvidenceContext {
    /// The context as a decision state's or a draft's data field.
    #[must_use]
    pub fn value(&self) -> Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}
