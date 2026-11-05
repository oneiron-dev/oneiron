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
//! rules. So is a change of the world pad compartments a restore left
//! unopened, which every head carries (PAD-3, FIX 11133). A pass holds the
//! policy lock from before it reads the folded policy until its pass ends,
//! so no pass seals an older policy at a newer position than another pass
//! recorded. A pass the lock did not take is bound by the log itself (FIX
//! 11783): the record names the position its policy is proven through, and
//! a head is sealed only where no other policy's frame came after that.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

use super::files::{open_dir, read_whole, replace_file};
use super::head::{CustodyRecipients, PadRecipients, carried_set_digest};
use super::log::{CustodyPosition, LogEntry, POSITION_LEN};
use super::platform;
use super::protocol::{TargetKind, TargetSpec};
use super::publish::custody_empty;

/// The digest of the policy the last `PublicationPolicy` frame recorded,
/// then the log position it is proven the policy in force through (FIX
/// 11783), in the journal: written only once its frame is.
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
    /// admitted pad recipients (FIX 6706), in order, then the `carried` set's
    /// digest (PAD-3).
    fn policy(&self, carried: Option<[u8; 32]>) -> [u8; 32] {
        policy_digest(
            &[
                &self.own.pad_worlds_kept_local,
                &self.hosted.pad_worlds_kept_local,
                &self.own.credentials_eligible,
                &self.hosted.credentials_eligible,
            ],
            [&self.own, &self.hosted].map(|group| group.root.as_ref().map(|(id, _)| *id)),
            [&self.own.pad_worlds, &self.hosted.pad_worlds],
            carried,
        )
    }
}

fn policy_digest(
    sets: &[&BTreeSet<[u8; 16]>],
    roots: [Option<[u8; 32]>; 2],
    pads: [&BTreeMap<EntityId, PadRecipients>; 2],
    carried: Option<[u8; 32]>,
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
    // The carried world pad compartments, wraps included (PAD-3): a change
    // of them alone seals every head again. Hashed only while one is
    // carried, so a vault with none keeps the digest it has.
    if let Some(carried) = carried {
        hasher.update(b"carried-world-pads");
        hasher.update(&carried);
    }
    *hasher.finalize().as_bytes()
}

/// The policy a pass read, and the log position through which it is proven
/// the policy in force (FIX 11783): its own frame's, or the record's carried
/// on through every frame since. `None` when nothing proves it (a frame that
/// did not append): the pass then seals as FIX 7314 rules, and the next pass
/// journals the policy again.
#[derive(Default)]
pub(crate) struct PolicyStanding {
    digest: [u8; 32],
    through: Option<CustodyPosition>,
}

impl PolicyStanding {
    /// Whether a head sealed at `position` follows the policy in force
    /// there: no other policy's frame came after this pass's proof. A
    /// standing nothing proved does not bind.
    ///
    /// # Errors
    ///
    /// A frame that does not open.
    pub(super) fn holds_at(
        &self,
        journal: &super::log::Journal,
        position: &CustodyPosition,
    ) -> Result<bool> {
        match &self.through {
            Some(through) => journal.policy_unchanged(&self.digest, through, position),
            None => Ok(true),
        }
    }
}

/// The policy record: its digest, then the position it is proven through.
fn encode_record(digest: &[u8; 32], through: &CustodyPosition) -> Vec<u8> {
    let mut record = Vec::with_capacity(32 + POSITION_LEN);
    record.extend_from_slice(digest);
    record.extend_from_slice(&through.to_bytes());
    record
}

/// A record that does not decode, an empty one included, proves no policy.
fn decode_record(bytes: &[u8]) -> Option<([u8; 32], CustodyPosition)> {
    if bytes.len() != 32 + POSITION_LEN {
        return None;
    }
    let (digest, through) = bytes.split_at(32);
    Some((
        digest.try_into().ok()?,
        CustodyPosition::from_bytes(through)?,
    ))
}

/// The policy lock, held for a pass: none while nothing is in custody.
pub(crate) struct PolicyGuard {
    _lock: Option<File>,
    /// The lock did not take and the pass runs without it (FIX 7314): what
    /// the pass records then proves no policy.
    unlocked: bool,
}

impl Store {
    /// Takes the publication policy lock of this vault's custody, before a
    /// pass reads the folded policy its heads are sealed under (KS-5, FIX
    /// 7191). Nothing is taken while nothing is in custody: there is no head
    /// to seal. A lock that does not take is warned and never stops the pass
    /// (FIX 7314): the pass runs without it, and its policy record is left
    /// unproven, so the next pass journals the policy again and every head is
    /// sealed and acknowledged again under the policy that pass reads.
    pub(crate) fn custody_policy_guard(&self) -> PolicyGuard {
        self.custody_policy_lock().unwrap_or_else(|error| {
            tracing::warn!(
                kind = ?error.kind(),
                "the custody publication policy lock did not take; the pass runs without it \
                 and the next pass journals the policy again"
            );
            PolicyGuard {
                _lock: None,
                unlocked: true,
            }
        })
    }

    fn custody_policy_lock(&self) -> Result<PolicyGuard> {
        let none = PolicyGuard {
            _lock: None,
            unlocked: false,
        };
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
            unlocked: false,
        })
    }

    /// Journals `recipients`' policy as one `PublicationPolicy` frame unless
    /// the record proves it the policy in force now, then records it with
    /// the position it is proven through (FIX 11783). The record proves a
    /// policy only through its position; every frame journaled since is read,
    /// and one recording another policy proves none. A record missing,
    /// undecodable or unread proves no policy: the frame is journaled again,
    /// so no head acknowledged under an older policy stays current (KS-5).
    /// The record is a cache: a fault reading or writing it is warned and
    /// never stops the pass. Neither does a frame that does not append (FIX
    /// 7314): it is warned, nothing is recorded, and the pass seals under the
    /// policy it read, so the next pass journals the frame again. A pass run
    /// without the policy lock (`guard`) records a policy no pass matches,
    /// for the same end. The caller holds the policy guard from before it
    /// read the policy, and seals under the standing this returns.
    ///
    /// # Errors
    ///
    /// Custody faults.
    pub(crate) fn note_custody_policy(
        &self,
        recipients: &TargetRecipients,
        guard: &PolicyGuard,
    ) -> Result<PolicyStanding> {
        let Some(custody) = self.core.key_custody.local() else {
            return Ok(PolicyStanding::default());
        };
        if self.archived_in_txn(&self.env.read_txn()?)? {
            return Ok(PolicyStanding::default());
        }
        let journal = custody.journal()?;
        if custody_empty(self, custody, &journal)? {
            return Ok(PolicyStanding::default());
        }
        let carried = {
            let _guard = self.core.key_custody.read_guard()?;
            carried_set_digest(&custody.carried()?)?
        };
        let policy = recipients.policy(carried);
        let recorded = match read_whole(&journal.dir().join(POLICY)) {
            Ok(bytes) => bytes.as_deref().and_then(decode_record),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "the custody publication policy record did not read; the policy is \
                     journaled again"
                );
                None
            }
        };
        let now = journal.position()?;
        let proven = match &recorded {
            Some((digest, through)) if *digest == policy => {
                journal.policy_unchanged(&policy, through, &now)?
            }
            _ => false,
        };
        let through = if proven {
            now
        } else {
            match custody.journal_entry(&LogEntry::PublicationPolicy(policy)) {
                Ok(position) => position,
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "the custody publication policy frame did not append; the pass seals \
                         under the policy it read and the next pass journals the frame again"
                    );
                    return Ok(PolicyStanding {
                        digest: policy,
                        through: None,
                    });
                }
            }
        };
        let standing = PolicyStanding {
            digest: policy,
            through: Some(through),
        };
        // Unlocked, an empty record: it decodes as no policy (FIX 7314).
        let record = if guard.unlocked {
            Vec::new()
        } else if recorded == Some((policy, through)) {
            return Ok(standing);
        } else {
            encode_record(&policy, &through)
        };
        if let Err(error) = replace_file(journal.dir(), POLICY, &record) {
            tracing::warn!(
                kind = ?error.kind(),
                "the custody publication policy record was not written; the next pass \
                 journals it again"
            );
        }
        Ok(standing)
    }
}
