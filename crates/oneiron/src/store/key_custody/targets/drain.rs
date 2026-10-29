//! The journal's half of a member drain (FIX 5843, ruled 10-20): the owner's
//! door out of the required set, after the member's deletion ack, with a
//! set-history row at a new revision. Never a forced unpin, and no hosted
//! target or content backup is a member to drain.
//!
//! A begun drain is a durable fence (`drains/f.<target hex>`): the fenced
//! member takes no head and has no publication ack accepted, so no stale
//! publish or commit lands while it empties. The commit checks the ack
//! against the fence and writes the set once: the member out, the revision
//! up, and the history row with the drain's evidence beside it. Only then
//! go the fence and the member's ack bookkeeping. Nothing local is
//! deleted: custody's own keys, the keyless log and what a hold keeps all
//! stay. A pass never adds a drained member back; only the owner's
//! re-enrolment does, at a newer revision.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

use super::super::files::{read_whole, replace_file};
use super::super::folder::FolderTarget;
use super::super::identity::hex_decode;
use super::super::log::{CustodyPosition, Journal};
use super::super::protocol::{
    AckPosition, DRAIN_VERSION, DrainAck, DrainTicket, DrainToken, Lineage, TargetId, TargetKind,
    TargetSpec, drain_operation_id, drain_origin, drain_placement, hex,
};
use super::{
    ACKS, Member, RequiredSet, TARGETS, WIRE_VERSION, decode, encode, journal_corrupt,
    remove_quietly, target_file,
};
use crate::store::Store;

const DRAINS: &str = "drains";

/// One owner change of the set's membership: its history, kept in the set
/// itself, so one write moves the members, the revision, the history and
/// the evidence together.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SetEvent {
    /// The revision the change made.
    revision: u64,
    target: String,
    change: SetChange,
    /// A drain's evidence, from the member's accepted ack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence: Option<DrainEvidence>,
    /// Unix seconds the change committed.
    at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetChange {
    Drained,
    Reenrolled,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainEvidence {
    /// The drain's operation id, 64 hex.
    operation_id: String,
    /// BLAKE3 (64 hex) of the accepted ack's named MessagePack.
    ack_digest: String,
    /// The member's post-deletion inventory digest, 64 hex.
    inventory_digest: String,
    /// Heads, stages and temporaries the member removed.
    superseded_removed: u64,
}

/// A begun drain's fence.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FenceWire {
    version: u8,
    target: String,
    revision: u64,
    position: AckPosition,
    operation_id: [u8; 32],
    token: [u8; 32],
}

impl Drop for FenceWire {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl FenceWire {
    fn ticket(&self) -> Result<DrainTicket> {
        Ok(DrainTicket {
            target_id: TargetId::new(&self.target)?,
            set_revision: self.revision,
            position: self.position.position().ok_or_else(journal_corrupt)?,
            operation_id: self.operation_id,
            token: DrainToken::from_bytes(self.token),
        })
    }
}

impl RequiredSet {
    /// Whether the owner drained `id` and has not re-enrolled it since.
    pub(super) fn drained(&self, id: &TargetId) -> bool {
        self.history
            .iter()
            .rev()
            .find(|event| event.target == id.as_str())
            .is_some_and(|event| event.change == SetChange::Drained)
    }
}

fn refused(why: &str) -> Error {
    Error::InvalidConfig(format!("the custody member drain {why}"))
}

/// Whether two MACs are equal, every byte compared.
fn same_mac(left: &[u8], right: &[u8; 32]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

impl Journal {
    fn fence(&self, id: &TargetId) -> Result<Option<FenceWire>> {
        match read_whole(&self.dir().join(DRAINS).join(target_file("f", id)))? {
            Some(bytes) => decode(&bytes).map(Some),
            None => Ok(None),
        }
    }

    /// Whether a begun drain fences `id`: it takes no head, and no
    /// publication ack of it is accepted, until the drain commits.
    pub(crate) fn drain_fenced(&self, id: &TargetId) -> Result<bool> {
        Ok(self.fence(id)?.is_some())
    }

    /// Begins the drain of member `id` at the local position `position`:
    /// fences it, synced, and returns the ticket its ack must name. A retry
    /// at the same set revision returns the same ticket; a fence an older
    /// revision left is begun again with a new token.
    pub(crate) fn begin_drain(
        &self,
        id: &TargetId,
        position: &CustodyPosition,
    ) -> Result<DrainTicket> {
        let _lock = self.lock()?;
        let set = self.required_set()?;
        if set.member(id).is_none() {
            return Err(refused("names no member of the required set"));
        }
        if let Some(fence) = self.fence(id)?
            && fence.revision == set.revision
        {
            return fence.ticket();
        }
        let mut token = Zeroizing::new([0u8; 32]);
        crate::world_keys::os_fill(&mut token[..])?;
        let fence = FenceWire {
            version: WIRE_VERSION,
            target: id.as_str().to_owned(),
            revision: set.revision,
            position: AckPosition::of(position),
            operation_id: drain_operation_id(id, set.revision, position),
            token: *token,
        };
        replace_file(&self.sub(DRAINS)?, &target_file("f", id), &encode(&fence)?)?;
        fence.ticket()
    }

    /// Commits the drain `ack` names, once it names exactly its begun drain:
    /// the member, the set revision the drain began at (a later one makes
    /// the drain stale), its position and operation, zero heads left, the
    /// member's placement and the lineage, under the drain's token. One
    /// write takes the member out at the next revision with its history row
    /// and evidence; the new revision is returned.
    pub(crate) fn commit_drain(&self, ack: &DrainAck) -> Result<u64> {
        let id = TargetId::new(&ack.target_id)?;
        let _lock = self.lock()?;
        let mut set = self.required_set()?;
        let fence = self.fence(&id)?.ok_or_else(|| refused("was never begun"))?;
        let member: Member = set
            .member(&id)
            .cloned()
            .ok_or_else(|| refused("names no member of the required set"))?;
        if fence.revision != set.revision {
            return Err(refused(
                "is stale: the required set changed since it began; begin it again",
            ));
        }
        let ticket = fence.ticket()?;
        let mac = hex_decode(&ack.mac).unwrap_or_default();
        let fits = ack.version == DRAIN_VERSION
            && ack.set_revision == fence.revision
            && ack.position == fence.position
            && ack.operation_id == hex(&fence.operation_id)
            && ack.evidence.remaining_heads == 0
            && hex_decode(&ack.evidence.inventory_digest).is_some_and(|digest| digest.len() == 32)
            && ack.placement == hex(&drain_placement(&member.spec))
            && ack.origin == hex(&drain_origin(&ticket.position))
            && same_mac(&mac, &ack.mac_under(&ticket.token)?);
        if !fits {
            return Err(refused("acknowledgement does not match its drain"));
        }
        let revision = set
            .revision
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("key custody target set revision"))?;
        set.members.retain(|kept| kept.spec.id() != &id);
        set.revision = revision;
        set.history.push(SetEvent {
            revision,
            target: ack.target_id.clone(),
            change: SetChange::Drained,
            evidence: Some(DrainEvidence {
                operation_id: ack.operation_id.clone(),
                ack_digest: hex(blake3::hash(&encode(ack)?).as_bytes()),
                inventory_digest: ack.evidence.inventory_digest.clone(),
                superseded_removed: ack.evidence.superseded_removed,
            }),
            at: crate::unix_seconds_now(),
        });
        replace_file(self.dir(), TARGETS, &encode(&set.wire())?)?;
        remove_quietly(&self.dir().join(DRAINS).join(target_file("f", &id)));
        let acks = self.dir().join(ACKS);
        for prefix in ["a", "p", "r"] {
            remove_quietly(&acks.join(target_file(prefix, &id)));
        }
        Ok(revision)
    }

    /// Adds `spec` back at the next revision when the owner drained it: the
    /// one way a drained member returns, never a pass's silent add. A
    /// member already in the set keeps its revision.
    pub(crate) fn reenrol(&self, spec: &TargetSpec) -> Result<u64> {
        let _lock = self.lock()?;
        let mut set = self.required_set()?;
        if set.member(spec.id()).is_some() {
            return Ok(set.revision);
        }
        let revision = set
            .revision
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("key custody target set revision"))?;
        set.members.push(Member {
            spec: spec.clone(),
            added: revision,
        });
        set.revision = revision;
        if set.drained(spec.id()) {
            set.history.push(SetEvent {
                revision,
                target: spec.id().as_str().to_owned(),
                change: SetChange::Reenrolled,
                evidence: None,
                at: crate::unix_seconds_now(),
            });
        }
        replace_file(self.dir(), TARGETS, &encode(&set.wire())?)?;
        Ok(revision)
    }
}

impl Store {
    fn drain_journal(&self) -> Result<Journal> {
        self.core
            .key_custody
            .local()
            .ok_or_else(|| refused("finds no custody here"))?
            .journal()
    }

    /// Begins the owner's drain of member `target` at the local log
    /// position (FIX 5843): fenced, synced, and its ticket returned for the
    /// member's own adapter.
    pub(crate) fn begin_custody_drain(&self, target: &TargetId) -> Result<DrainTicket> {
        let journal = self.drain_journal()?;
        journal.begin_drain(target, &journal.position()?)
    }

    /// Commits the drain the member's `ack` names; the set's new revision.
    pub(crate) fn commit_custody_drain(&self, ack: &DrainAck) -> Result<u64> {
        self.drain_journal()?.commit_drain(ack)
    }

    /// Drains folder member `target` here, its own adapter: begun, the
    /// folder emptied of the lineage's heads, and committed on its ack.
    pub(crate) fn drain_custody_folder(&self, target: &TargetId) -> Result<u64> {
        let journal = self.drain_journal()?;
        let folder = journal
            .required_set()?
            .members
            .iter()
            .find(|member| member.spec.id() == target && member.spec.kind() == TargetKind::Folder)
            .and_then(|member| member.spec.folder_path().map(std::path::Path::to_path_buf))
            .ok_or_else(|| refused("names no folder member"))?;
        let ticket = journal.begin_drain(target, &journal.position()?)?;
        let ack = FolderTarget::at(folder).drain(Lineage::of(&ticket.position), &ticket)?;
        journal.commit_drain(&ack)
    }

    /// Re-enrols `spec`, a member the owner drained, at the next revision.
    pub(crate) fn reenrol_custody_member(&self, spec: &TargetSpec) -> Result<u64> {
        self.drain_journal()?.reenrol(spec)
    }
}
