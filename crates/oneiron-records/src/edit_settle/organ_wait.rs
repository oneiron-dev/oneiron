//! Moved from `crates/oneiron/src/edit_settle/organ_wait.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::write_envelope::WriteActor;
use oneiron_store::write_envelope::provenance::made_by::MadeByTrigger;
use serde::Deserialize;
use serde::Serialize;

/// One organ call to hold until a node can run it.
#[derive(Debug, Clone, PartialEq)]
pub struct OrganWait {
    /// The artifact its export files land beside.
    pub artifact_id: EntityId,
    /// The run ref its proposals take: the consume-once key.
    pub run_ref: String,
    pub organ: String,
    pub verb: String,
    /// The call, as the organ host encodes it.
    pub call: Vec<u8>,
    pub trigger: Option<MadeByTrigger>,
    /// The authenticated principal who submitted the call, when one did:
    /// its proposals' made_by is admitted through that principal's own read
    /// when they land, a redrive's included (FIX 9310). None for a host's own
    /// call, whose envelope waits as the host built it.
    pub submitter: Option<EntityId>,
    /// Who asked: the actor its proposals are made by.
    pub held_by: WriteActor,
    pub held_at: u64,
}

/// A held call as a surface shows it: what waits, since when, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganWaitView {
    pub artifact_id: EntityId,
    pub run_ref: String,
    pub organ: String,
    pub verb: String,
    pub held_by: EntityId,
    pub held_at: u64,
    /// Why it waits, in the router's words: which nodes it tried and what
    /// each said.
    pub reason: String,
    /// Redrives so far.
    pub tries: u32,
    pub last_try_at: u64,
    /// Set when a node ran the call and it failed there; it no longer
    /// waits, and stays until released so the failure is seen.
    pub failed: Option<String>,
}
