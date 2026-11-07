//! The critical-confirm pending record: its reason codes, its deadline, and
//! the deterministic binding the authority log keys a confirm by.

use sha2::{Digest, Sha256};

use oneiron_authority::authority::CRITICAL_WRITE_CONFIRM_DOMAIN;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The lifetime a critical confirm hold with no frozen deadline signs: one
/// attached on sync or reopened for an open obligation, which never times
/// out. A locally attached confirm freezes the policy's
/// `critical_confirm_lifetime_seconds` instead (FIX 8760), shipped at the
/// same 300 seconds.
pub const CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS: u64 = 300;
// The decision receipt uses the allow namespace; the durable pending row must
// remain in store.rs's existing pending namespace.
pub const GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED: &str =
    "gate.pending.critical_confirm_attached";
/// The pending reason of a critical confirm that timed out.
pub const GATE_REASON_CRITICAL_CONFIRM_TIMEOUT: &str = "gate.pending.critical_confirm_timeout";
/// The pending reason of the confirm this device attaches to a critical claim
/// that reached it by sync. The peer's Auto stamp is not this device's Clear.
/// The hold has no deadline here, since a timeout's demotion would rewrite the
/// peer's bytes on this device.
pub const GATE_REASON_PENDING_REPLICATED_CRITICAL_CONFIRM: &str =
    "gate.pending.critical_confirm_replicated";
/// The pending reason of the item a claim's open owner-answer obligation
/// shows its owner after a door removed the one it had without an answer, or a
/// later revision outdated it (the gate's owner-answer doors). Like a replicated
/// hold, it has no deadline.
pub const GATE_REASON_PENDING_CRITICAL_CONFIRM_REOPENED: &str =
    "gate.pending.critical_confirm_reopened";
