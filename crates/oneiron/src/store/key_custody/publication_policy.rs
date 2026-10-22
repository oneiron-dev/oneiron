//! The publication policy each custody head is sealed under (KS-5, FIX
//! 7191): which worlds' pads a member's head leaves out, by its kind.
//!
//! A hosted member's head and every other member's (a folder, the residence
//! home) are sealed apart at one log position, each with its own
//! recipients' eligibility, so a hosted head never strips a pad a folder
//! may keep. A change of the policy alone (a world's sealed copies setting)
//! is journaled as one content-free `PublicationPolicy` frame of the custody
//! log, so the log moves on and every member's head is sealed and
//! acknowledged again through the existing due, status, Covered and anchor
//! rules. A pass holds the policy lock from before it reads the folded
//! policy until its pass ends, so no pass seals an older policy at a newer
//! position than another pass recorded.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

use super::files::{open_dir, read_whole, replace_file};
use super::head::{CustodyRecipients, PadRecipients};
use super::log::LogEntry;
use super::platform;
use super::protocol::{TargetKind, TargetSpec};
use super::publish::custody_empty;

/// The digest of the policy the last `PublicationPolicy` frame recorded,
/// in the journal: written only once its frame is.
const POLICY: &str = "policy";
/// The lock a pass holds from its policy read to its pass's end.
const POLICY_LOCK: &str = "policy.lock";
const POLICY_CONTEXT: &[u8] = b"oneiron/custody-publication-policy/v1";

/// Who each member's head is wrapped to and which pads it leaves out (KS-5,
/// FIX 7191): a hosted member's, and every other member's.
pub(crate) struct TargetRecipients {
    /// A folder's and the residence home's.
    pub(crate) own: CustodyRecipients,
    /// A hosted member's.
    pub(crate) hosted: CustodyRecipients,
}

impl TargetRecipients {
    /// The recipients `spec`'s head is sealed for.
    pub(crate) fn of(&self, spec: &TargetSpec) -> &CustodyRecipients {
        match spec.kind() {
            TargetKind::Hosted(_) => &self.hosted,
            TargetKind::Folder | TargetKind::Residence => &self.own,
        }
    }

    /// The digest of the policy both heads follow: each group's recovery
    /// root by id, the worlds each leaves the pads of out, then the
    /// credentials whose keys each may carry (KS-6), then each world's
    /// admitted pad recipients (FIX 6706), in order.
    fn policy(&self) -> [u8; 32] {
        policy_digest(
            &[
                &self.own.pad_worlds_kept_local,
                &self.hosted.pad_worlds_kept_local,
                &self.own.credentials_eligible,
                &self.hosted.credentials_eligible,
            ],
            [&self.own, &self.hosted].map(|group| group.root.as_ref().map(|(id, _)| *id)),
            [&self.own.pad_worlds, &self.hosted.pad_worlds],
        )
    }
}

fn policy_digest(
    sets: &[&BTreeSet<[u8; 16]>],
    roots: [Option<[u8; 32]>; 2],
    pads: [&BTreeMap<EntityId, PadRecipients>; 2],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(POLICY_CONTEXT);
    // Each group's recovery root by identity, not presence alone (FIX
    // 7995): a changed root moves the policy, so every head is sealed to the
    // new kit and acknowledged again. A root also decides whether a
    // credential's keys may ride at all (KS-6).
    for root in roots {
        match root {
            Some(id) => {
                hasher.update(&[1]);
                hasher.update(&id);
            }
            None => {
                hasher.update(&[0]);
            }
        }
    }
    let credentials = sets.iter().skip(2).any(|set| !set.is_empty());
    let hashed = if credentials { sets.len() } else { 2 };
    for worlds in sets.iter().take(hashed).copied() {
        hasher.update(&(worlds.len() as u64).to_be_bytes());
        for world in worlds {
            hasher.update(world);
        }
    }
    // Each group's world pad recipients (FIX 6706): each world, then each
    // admitted machine's and root's id and canonical public key, counted and
    // in order, so a recipient-only change seals and acknowledges every head
    // again at a new position. Hashed once a group names a world, so the
    // policy of a vault with none stays the digest it is.
    if pads.iter().any(|group| !group.is_empty()) {
        hasher.update(b"pad-recipients");
        for group in pads {
            hasher.update(&(group.len() as u64).to_be_bytes());
            for (world, admitted) in group {
                hasher.update(world.as_bytes());
                hasher.update(&(admitted.len() as u64).to_be_bytes());
                for (recipient, public) in admitted {
                    for part in [recipient.envelope_recipient(), public.to_bytes()] {
                        hasher.update(&(part.len() as u64).to_be_bytes());
                        hasher.update(&part);
                    }
                }
            }
        }
    }
    *hasher.finalize().as_bytes()
}

/// The policy lock, held for a pass: none while nothing is in custody.
pub(crate) struct PolicyGuard {
    _lock: Option<File>,
}

impl Store {
    /// Takes the publication policy lock of this vault's custody, before a
    /// pass reads the folded policy its heads are sealed under (KS-5, FIX
    /// 7191). Nothing is taken while nothing is in custody: there is no head
    /// to seal.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn custody_policy_guard(&self) -> Result<PolicyGuard> {
        let none = PolicyGuard { _lock: None };
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(none);
        };
        // An archived vault's custody is the one of the vault that replaced
        // it, which publishes it.
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Ok(none);
        }
        let journal = custody.journal()?;
        if custody_empty(self, custody, &journal)? {
            return Ok(none);
        }
        custody.open_compartment()?;
        open_dir(journal.dir(), true, None)?;
        Ok(PolicyGuard {
            _lock: Some(platform::lock_at(&journal.dir().join(POLICY_LOCK))?),
        })
    }

    /// Journals `recipients`' policy as one `PublicationPolicy` frame when
    /// it is not the one the last frame recorded, then records it. A record
    /// missing, undecodable or unread proves no policy: the frame is
    /// journaled again, so no head acknowledged under an older policy stays
    /// current (KS-5). The record is a cache: a fault reading or writing it is
    /// warned and never stops the pass. The caller holds the policy guard
    /// from before it read the policy.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn note_custody_policy(&self, recipients: &TargetRecipients) -> Result<()> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(());
        };
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Ok(());
        }
        let journal = custody.journal()?;
        if custody_empty(self, custody, &journal)? {
            return Ok(());
        }
        let policy = recipients.policy();
        let recorded = match read_whole(&journal.dir().join(POLICY)) {
            Ok(bytes) => bytes.and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the custody publication policy record did not read; the policy is \
                     journaled again"
                );
                None
            }
        };
        if recorded == Some(policy) {
            return Ok(());
        }
        custody.journal_entry(&LogEntry::PublicationPolicy(policy))?;
        if let Err(error) = replace_file(journal.dir(), POLICY, &policy) {
            tracing::warn!(
                kind = ?error.kind(),
                "the custody publication policy record was not written; the next pass \
                 journals it again"
            );
        }
        Ok(())
    }
}
