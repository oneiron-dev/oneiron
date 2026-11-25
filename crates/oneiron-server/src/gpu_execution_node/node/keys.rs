//! The node's keys ([`NodeKeys`]): what the job service and the authority tick hand row R3a's
//! journal once the gate has passed. [`super::ExecutionNode`] holds them after
//! [`super::ExecutionNode::attach_keys`].

use std::collections::BTreeSet;

use oneiron::EntityId;

use super::super::wire::{
    JobAnswer, JobRefusal, JobReserve, JobStatusAnswer, LogTailRequest, NodeReadiness, ScopeReport,
    SignedJobSubmit,
};

/// The node's keys: the journal, the key states, admission and the launch
/// commit (row R3a's `NodeJobs`). The job service hands it every request
/// that names a key, once the gate has passed; the authority tick hands it
/// a withdrawn grant or an ended standing. Every call may block on the
/// journal's disk.
pub trait NodeKeys: Send + Sync {
    /// `Reserve` from the proven issuer `peer`.
    fn reserve(&self, peer: EntityId, reserve: JobReserve) -> JobAnswer;

    /// `Release` from the proven issuer `peer`.
    fn release(&self, peer: EntityId, key: &str) -> JobAnswer;

    /// `Submit` from the proven issuer `peer`.
    fn submit(&self, peer: EntityId, signed: SignedJobSubmit) -> JobAnswer;

    /// Whether the start-up reconciliation has ended (`Node`'s `swept`).
    fn swept(&self) -> bool;

    /// The journal's epoch, lower hex; `None` while the history is lost.
    fn epoch(&self) -> Option<String>;

    /// The disk the node's live keys keep booked, in MiB.
    fn booked_disk_mib(&self) -> u64;

    /// The issuers of every key that has not ended: the tick checks each
    /// one's standing, whatever the file names now.
    fn live_issuers(&self) -> BTreeSet<EntityId>;

    /// EN-4 A: the fold no longer authorises `issuer`'s work here (`None`:
    /// no issuer's, as when this node's own grant was withdrawn). Every key
    /// of that issuer that has not ended ends: a key that has not launched
    /// closes, and a launched one is stopped as revoked with `why`.
    fn revoke_live_keys(&self, issuer: Option<EntityId>, why: &str);

    /// `disable --stop` at the box: every key that has not ended ends; a
    /// launched one is stopped.
    fn stop_live_keys(&self);

    /// `Find` and `Status` from the proven issuer `peer` (row R4): the key's
    /// newest receipt.
    fn find(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        let _ = (peer, key);
        JobStatusAnswer::Refused(JobRefusal::NotEnabled)
    }

    /// `Stop` from `peer`: closes a key that has not launched (also one the
    /// node never saw), ends one that has.
    fn stop(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        let _ = (peer, key);
        JobStatusAnswer::Refused(JobRefusal::NotEnabled)
    }

    /// `Keys` from `peer`: one page of its keys after `after`.
    fn keys_page(&self, peer: EntityId, after: Option<&str>) -> JobStatusAnswer {
        let _ = (peer, after);
        JobStatusAnswer::Refused(JobRefusal::NotEnabled)
    }

    /// `Signal` from `peer`: a checkpoint notice to the key's workload.
    fn signal(&self, peer: EntityId, key: &str, signal: &str) -> JobStatusAnswer {
        let _ = (peer, key, signal);
        JobStatusAnswer::Refused(JobRefusal::NotEnabled)
    }

    /// `Fetch` from `peer`: the bytes of one returnable output.
    fn fetch(&self, peer: EntityId, key: &str, name: &str) -> JobStatusAnswer {
        let _ = (peer, key, name);
        JobStatusAnswer::Refused(JobRefusal::NotEnabled)
    }

    /// `Ack` from `peer`: it holds every returnable output of the key it
    /// wants.
    fn acknowledge(&self, peer: EntityId, key: &str) -> JobStatusAnswer {
        let _ = (peer, key);
        JobStatusAnswer::Refused(JobRefusal::NotEnabled)
    }

    /// `Tail` from `peer`: the key's log from an offset (pass 34, 7.2).
    fn tail(&self, peer: EntityId, request: &LogTailRequest) -> JobStatusAnswer {
        let _ = (peer, request);
        JobStatusAnswer::Refused(JobRefusal::NotEnabled)
    }

    /// What the node's last idle readiness check found (pass 34, 7.3), for
    /// `Node`; `None` while the node keeps no journal.
    fn readiness(&self) -> Option<NodeReadiness> {
        None
    }

    /// The launch scopes the keys' job unit starts runs in, each with what
    /// it can enforce now, as its probe reads them (pass 34, section 2.2):
    /// `Node`'s `scopes`. A scope that does not meet the minimum contract is
    /// listed and runs nothing. None until a unit probes them.
    fn scopes(&self) -> Vec<ScopeReport> {
        Vec::new()
    }
}
