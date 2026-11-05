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
//! recorded.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;

use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::key_custody::files::open_dir;
use crate::key_custody::files::read_whole;
use crate::key_custody::files::replace_file;
use crate::key_custody::head::pad_scope::PadRecipients;
use crate::key_custody::platform;
use crate::key_custody::protocol::TargetKind;
use crate::key_custody::protocol::TargetSpec;

/// The digest of the policy the last `PublicationPolicy` frame recorded,
/// in the journal: written only once its frame is.
pub const POLICY: &str = "policy";
/// The lock a pass holds from its policy read to its pass's end.
pub const POLICY_LOCK: &str = "policy.lock";
const POLICY_CONTEXT: &[u8] = b"oneiron/custody-publication-policy/v1";

pub fn policy_digest(
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

/// The policy lock, held for a pass: none while nothing is in custody.
pub struct PolicyGuard {
    pub _lock: Option<File>,
    /// The lock did not take and the pass runs without it (FIX 7314): what
    /// the pass records then proves no policy.
    pub unlocked: bool,
}
