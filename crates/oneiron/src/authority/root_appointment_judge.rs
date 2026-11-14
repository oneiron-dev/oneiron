//! The fold's judgement of a root appointment (row
//! OWNER-ANCHOR-ROOT-RECOVERY, PLAN v3 sections 4, 4a and 5; Engine RULINGs
//! 14 Nov 21:01, 21:47 and 22:32).
//!
//! An appointment's verdict is a function of its own signed ancestry and the
//! root it names, so it is the same on every install:
//! - V1: the row's shape (the codec's check), and a successor key no row of
//!   its ancestry names ([`AppointmentVerdict::SuccessorNotFresh`]);
//! - V2: an owner root of that id, signed by the appointing anchor, that the
//!   anchor fold of the ancestry took, and a sequence above the anchor's own
//!   rows there;
//! - V3: the ancestry's canonical fold ([`proof_fold`]) holds no live
//!   `ROLE_OWNER` key;
//! - V4: the anchor is not burned in the ancestry.
//!
//! An anchor is burned by one void appointment (V2, V3 or V4 failed on a
//! complete ancestry), or by two valid ones beside each other, neither in the
//! other's ancestry. Its appointments are judged in topological order, and
//! after its first burn every later one is void with no proof fold, which
//! bounds the proof folds an anchor costs.
//!
//! Only the anchor of this install's pinned root is judged; every other
//! appointment costs no proof fold. No install counts an appointment yet:
//! the fold refuses every one, with its descendants, and reports its verdict
//! ([`AuthorityFoldIssue::AppointmentRefused`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use super::*;

/// Why a root appointment is void. A void appointment burns its anchor.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AppointmentVoidReason {
    /// Its ancestry holds no owner root of its id that its anchor signed and
    /// the anchor fold took, or folds into another vault (V2).
    NoOwnerRoot,
    /// Its sequence is not above its anchor's own rows in its ancestry (V2).
    SequenceNotAdvanced,
    /// Its ancestry, folded canonically, still holds a live root key (V3).
    RootedAncestry,
    /// Its anchor is burned in its ancestry, or at an earlier appointment of
    /// this install's log (V4).
    AnchorBurned,
}

/// A root appointment's verdict on this install.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AppointmentVerdict {
    /// Not judged: this install pins no root of the appointing anchor.
    Unjudged,
    /// Its ancestry is incomplete here, or its proof fold passed the fold's
    /// memory floor. It is judged again when that changes.
    Pending,
    /// A row of its ancestry names the successor key (V1). It burns nothing.
    SuccessorNotFresh,
    /// V2, V3 or V4 failed. It burns its anchor.
    Void(AppointmentVoidReason),
    /// V1 to V4 hold.
    Valid,
}

/// The verdicts of every root appointment a fold holds, and the anchor of
/// the fold's pin when its appointments burn it.
#[derive(Debug, Default)]
pub(super) struct AppointmentJudgement {
    pub(super) verdicts: BTreeMap<AuthorityEntryHash, AppointmentVerdict>,
    pub(super) burned: Option<[u8; 32]>,
}

/// Judges every root appointment of `by_hash` under `pin`: the pinned
/// anchor's in topological order, each other one [`AppointmentVerdict::Unjudged`].
pub(super) fn judge_appointments(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    pin: Option<&PinnedRoot>,
) -> AppointmentJudgement {
    let mut judgement = AppointmentJudgement::default();
    let anchor = pin.map(|pin| pin.anchor_key);
    let mut judged = Vec::new();
    for (hash, entry) in by_hash {
        if !matches!(entry.op, AuthorityOp::RootAppointment(_)) {
            continue;
        }
        if anchor.is_some() && RootAppointment::anchor_key(entry) == anchor {
            judged.push(*hash);
        } else {
            judgement
                .verdicts
                .insert(*hash, AppointmentVerdict::Unjudged);
        }
    }
    let Some(anchor) = anchor else {
        return judgement;
    };
    let (verdicts, burned) = judge_anchor(by_hash, &judged);
    judgement.verdicts.extend(verdicts);
    judgement.burned = burned.then_some(anchor);
    judgement
}

/// One anchor's appointments `judged`, all rows of `by_hash`, in topological
/// order (ancestry size, then hash): their verdicts, and whether they burn
/// the anchor.
fn judge_anchor(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    judged: &[AuthorityEntryHash],
) -> (BTreeMap<AuthorityEntryHash, AppointmentVerdict>, bool) {
    let mut ordered: Vec<_> = judged
        .iter()
        .map(|hash| {
            let ancestry = ancestry_of(by_hash, &by_hash[hash]);
            let size = ancestry.as_ref().map_or(usize::MAX, BTreeSet::len);
            (size, *hash, ancestry)
        })
        .collect();
    ordered.sort_by_key(|(size, hash, _)| (*size, *hash));
    let mut verdicts = BTreeMap::new();
    let mut valid: Vec<AuthorityEntryHash> = Vec::new();
    let mut burned = false;
    for (_, hash, ancestry) in ordered {
        let verdict = match &ancestry {
            _ if burned => AppointmentVerdict::Void(AppointmentVoidReason::AnchorBurned),
            None => AppointmentVerdict::Pending,
            Some(ancestry) => {
                let verdict = verdict_of(by_hash, hash, ancestry);
                match verdict {
                    AppointmentVerdict::Void(_) => burned = true,
                    AppointmentVerdict::Valid => {
                        burned = valid.iter().any(|earlier| !ancestry.contains(earlier));
                        valid.push(hash);
                    }
                    _ => {}
                }
                verdict
            }
        };
        verdicts.insert(hash, verdict);
    }
    (verdicts, burned)
}

/// The hashes of `entry`'s strict ancestry in `by_hash`; `None` when a row of
/// it is missing.
fn ancestry_of(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    entry: &AuthorityLogEntry,
) -> Option<BTreeSet<AuthorityEntryHash>> {
    let mut ancestry = BTreeSet::new();
    let mut stack = entry.parent_hashes.clone();
    while let Some(hash) = stack.pop() {
        if !ancestry.insert(hash) {
            continue;
        }
        stack.extend(by_hash.get(&hash)?.parent_hashes.iter().copied());
    }
    Some(ancestry)
}

/// The verdicts already reached, by appointment hash. A verdict is a function
/// of the hash alone (the row names its ancestry by content), so one map
/// serves every fold of the process. It keeps only completed verdicts, never
/// [`AppointmentVerdict::Pending`] nor the log-order burn of [`judge_anchor`],
/// and it empties itself at [`MEMO_ROWS`].
static MEMO: OnceLock<Mutex<BTreeMap<AuthorityEntryHash, AppointmentVerdict>>> = OnceLock::new();
const MEMO_ROWS: usize = 4096;

fn memo() -> &'static Mutex<BTreeMap<AuthorityEntryHash, AppointmentVerdict>> {
    MEMO.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// The verdict of appointment `hash`, whose ancestry `ancestry` is complete in
/// `by_hash`.
fn verdict_of(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    hash: AuthorityEntryHash,
    ancestry: &BTreeSet<AuthorityEntryHash>,
) -> AppointmentVerdict {
    if let Some(verdict) = memo().lock().ok().and_then(|memo| memo.get(&hash).copied()) {
        return verdict;
    }
    let verdict = judge_one(by_hash, &by_hash[&hash], ancestry);
    if verdict != AppointmentVerdict::Pending
        && let Ok(mut memo) = memo().lock()
    {
        if memo.len() >= MEMO_ROWS {
            memo.clear();
        }
        memo.insert(hash, verdict);
    }
    verdict
}

fn judge_one(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    entry: &AuthorityLogEntry,
    ancestry: &BTreeSet<AuthorityEntryHash>,
) -> AppointmentVerdict {
    let (AuthorityOp::RootAppointment(appointment), Some(anchor)) =
        (&entry.op, RootAppointment::anchor_key(entry))
    else {
        return AppointmentVerdict::Pending;
    };
    let rows: BTreeMap<AuthorityEntryHash, AuthorityLogEntry> = ancestry
        .iter()
        .map(|hash| (*hash, by_hash[hash].clone()))
        .collect();
    // V4 first: an anchor burned beneath the row costs no proof fold.
    let earlier: Vec<AuthorityEntryHash> = rows
        .iter()
        .filter(|(_, row)| {
            matches!(row.op, AuthorityOp::RootAppointment(_))
                && RootAppointment::anchor_key(row) == Some(anchor)
        })
        .map(|(hash, _)| *hash)
        .collect();
    let (earlier, burned) = judge_anchor(&rows, &earlier);
    if burned {
        return AppointmentVerdict::Void(AppointmentVoidReason::AnchorBurned);
    }
    if earlier
        .values()
        .any(|verdict| *verdict == AppointmentVerdict::Pending)
    {
        return AppointmentVerdict::Pending;
    }
    if !successor_is_fresh(&rows, appointment, anchor) {
        return AppointmentVerdict::SuccessorNotFresh;
    }
    let scoped: Vec<AuthorityLogEntry> = rows.values().cloned().collect();
    let proof = proof_fold(&scoped, appointment.root, anchor);
    if proof
        .issues
        .iter()
        .any(|issue| matches!(issue, AuthorityFoldIssue::FoldMemoryFloor { .. }))
    {
        return AppointmentVerdict::Pending;
    }
    let anchor_key = AuthorityKey::Ed25519(anchor);
    let root_taken = rows.iter().any(|(hash, row)| {
        matches!(&row.op, AuthorityOp::OwnerRoot(record)
            if record.root == appointment.root && record.anchor_key == anchor)
            && proof.valid_entries.contains(hash)
    });
    if proof.vault_id != entry.vault_id || !root_taken {
        return AppointmentVerdict::Void(AppointmentVoidReason::NoOwnerRoot);
    }
    if rows.iter().any(|(hash, row)| {
        *row.signer_key() == anchor_key
            && proof.valid_entries.contains(hash)
            && row.seq >= entry.seq
    }) {
        return AppointmentVerdict::Void(AppointmentVoidReason::SequenceNotAdvanced);
    }
    if proof
        .roster
        .values()
        .any(|device| !device.revoked && device.roles & ROLE_OWNER != 0)
    {
        return AppointmentVerdict::Void(AppointmentVoidReason::RootedAncestry);
    }
    AppointmentVerdict::Valid
}

/// Whether no row of the ancestry `rows` names the successor key: as its
/// signer or a cosigner, as a device it enrols, rotates from or to, hands the
/// root to or revokes, as an owner root's anchor, or as another appointment's
/// successor. The appointing anchor is never its own successor (the codec).
fn successor_is_fresh(
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    appointment: &RootAppointment,
    anchor: [u8; 32],
) -> bool {
    let successor = &appointment.successor.key;
    if *successor == AuthorityKey::Ed25519(anchor) {
        return false;
    }
    !rows.values().any(|row| {
        row.signer_key() == successor
            || row
                .cosigns
                .iter()
                .any(|cosign| cosign.public_key == *successor)
            || match &row.op {
                AuthorityOp::Genesis { device, .. }
                | AuthorityOp::EnrollDevice { device }
                | AuthorityOp::ReRoot { new_device: device }
                | AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll { device, .. })
                | AuthorityOp::RootAppointment(RootAppointment {
                    successor: device, ..
                }) => device.key == *successor,
                AuthorityOp::RotateKey {
                    old_key,
                    new_device,
                } => old_key == successor || new_device.key == *successor,
                AuthorityOp::RevokeDevice { revoked_key } => revoked_key == successor,
                AuthorityOp::OwnerRoot(record) => {
                    *successor == AuthorityKey::Ed25519(record.anchor_key)
                }
                _ => false,
            }
    })
}

/// ProofFold (PLAN v3 section 4a): the strict fold of exactly `rows`, under
/// inputs no install holds alone: no seen-times and no clock, no peer roots,
/// no local observations, floors, vouches or holds, and no capture; the pin
/// is `root` under `anchor`; the posture is hosted exactly when the genesis
/// among `rows` carries the host's stamp (`ROLE_CLOUD` or
/// [`AuthorityTier::CloudCustodial`]), never the install's config.
pub(super) fn proof_fold(
    rows: &[AuthorityLogEntry],
    root: RecoveryRootId,
    anchor: [u8; 32],
) -> AuthorityFold {
    let hosted = rows.iter().any(|row| {
        matches!(&row.op, AuthorityOp::Genesis { device, .. }
            if device.roles & ROLE_CLOUD != 0 || device.tier == AuthorityTier::CloudCustodial)
    });
    let posture = if hosted {
        crate::HostingPrivacyPosture::Hosted
    } else {
        crate::HostingPrivacyPosture::SelfHostLocal
    };
    let pin = PinnedRoot {
        id: root,
        anchor_key: anchor,
    };
    super::fold_engine::fold_own_authority_log(rows, posture, Some(&pin))
}
