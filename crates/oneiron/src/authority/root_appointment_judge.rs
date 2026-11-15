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
//! complete ancestry), by one whose successor is not fresh (V1), or by two
//! valid ones beside each other, neither in the other's ancestry. The door
//! never signs a void or not-fresh appointment (it judges each candidate
//! first, and its successor key is new), so only a probe by a holder of the
//! anchor key burns it alone. Its appointments are judged in topological
//! order, and after its first burn every later one is void with no proof
//! fold, which bounds the proof folds an anchor costs.
//!
//! Only the anchor of this install's pinned root is judged; every other
//! appointment costs no proof fold.
//!
//! An install counts a valid appointment that names its pinned root, while
//! its log burns no anchor of that root (PLAN v3 section 5). Every pin is the
//! owner's own act (row CARRIED-PIN), so the pin decides no validity: it
//! decides which valid appointment counts. A counted appointment installs its
//! recovered world ([`Recovered`], section 6): every row of its ancestry keeps
//! the verdict and state its proof fold gave it, the appointment folds as
//! that fold's merge with every roster key revoked and its successor live,
//! and its fence seals every row an old roster key signs outside that line.
//! Every other appointment is refused, with its descendants, and reports its
//! verdict ([`AuthorityFoldIssue::AppointmentRefused`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, OnceLock};

use super::fold_resume::{FoldCapture, ProofParts};

use super::*;

// The two verdict types live in oneiron-records, beside the fold issue that
// carries them (lib split R1: record types below the lib).
#[doc(hidden)]
pub use oneiron_records::authority::fold_state::{AppointmentVerdict, AppointmentVoidReason};

/// The verdicts of every root appointment a fold holds, the anchor of the
/// fold's pin when its appointments burn it, and what the appointments this
/// install counts recover.
#[derive(Default)]
pub(super) struct AppointmentJudgement {
    pub(super) verdicts: BTreeMap<AuthorityEntryHash, AppointmentVerdict>,
    pub(super) burned: Option<[u8; 32]>,
    pub(super) recovered: Recovered,
}

/// The recovered world of the appointments a fold counts (PLAN v3 section 6).
#[derive(Default)]
pub(super) struct Recovered {
    /// The proof folds of the counted appointments' ancestries.
    proofs: Vec<Arc<ProofParts>>,
    /// Each row of a counted appointment's ancestry: the proof fold, in
    /// `proofs`, that holds its state, or none when that fold refused it.
    rows: BTreeMap<AuthorityEntryHash, Option<usize>>,
    /// Each counted appointment's own state: its proof fold's merge with every
    /// roster key revoked and the successor live, in its own custody line
    /// (E1).
    worlds: BTreeMap<AuthorityEntryHash, FoldState>,
    /// Each counted appointment's fence (E2).
    pub(super) fences: Vec<AppointmentFence>,
    /// The handoffs the proof folds closed inside the counted lines: they keep
    /// that status, and the fold never settles them again (E3).
    pub(super) closed_handoffs: BTreeSet<AuthorityEntryHash>,
}

/// A counted appointment's fence: every key a row of its ancestry names as a
/// device, other than its successor, signs nothing that stands outside its
/// line.
pub(super) struct AppointmentFence {
    pub(super) row: AuthorityEntryHash,
    pub(super) vault_id: Option<AuthorityVaultId>,
    pub(super) keys: BTreeSet<AuthorityKey>,
    /// The appointment and its whole ancestry.
    pub(super) line: BTreeSet<AuthorityEntryHash>,
}

impl Recovered {
    /// How the row `hash` folds when a counted appointment's line holds it:
    /// its proof fold's state, or a refusal. None for every other row.
    pub(super) fn entry_fold(&self, hash: &AuthorityEntryHash) -> Option<EntryFold> {
        if let Some(world) = self.worlds.get(hash) {
            return Some(EntryFold::Ready(world.clone()));
        }
        let proof = self.rows.get(hash)?;
        Some(
            match proof.and_then(|index| self.proofs[index].states.get(hash)) {
                Some(state) => EntryFold::Ready(state.clone()),
                None => EntryFold::Invalid(AuthorityFoldIssue::InvalidAncestry(*hash)),
            },
        )
    }

    /// Whether a counted appointment's line holds `hash`: the fold never
    /// refuses, prunes or settles such a row again.
    pub(super) fn holds(&self, hash: &AuthorityEntryHash) -> bool {
        self.worlds.contains_key(hash) || self.rows.contains_key(hash)
    }

    /// The world the appointments of `by_hash` that `verdicts` holds valid and
    /// that name `pin`'s root recover, each over its own ancestry, smallest
    /// first.
    fn of(
        by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        verdicts: &BTreeMap<AuthorityEntryHash, AppointmentVerdict>,
        pin: &PinnedRoot,
    ) -> Self {
        let mut counted: Vec<_> = verdicts
            .iter()
            .filter(|(hash, verdict)| {
                **verdict == AppointmentVerdict::Valid
                    && matches!(&by_hash[*hash].op,
                        AuthorityOp::RootAppointment(appointment) if appointment.root == pin.id)
            })
            .filter_map(|(hash, _)| {
                ancestry_of(by_hash, &by_hash[hash])
                    .map(|ancestry| (ancestry.len(), *hash, ancestry))
            })
            .collect();
        counted.sort_by_key(|(size, hash, _)| (*size, *hash));
        let mut recovered = Self::default();
        for (_, hash, ancestry) in counted {
            let entry = &by_hash[&hash];
            let AuthorityOp::RootAppointment(appointment) = &entry.op else {
                continue;
            };
            if let Some(parts) =
                proof_parts(by_hash, entry, appointment.root, pin.anchor_key, &ancestry)
            {
                recovered.install(by_hash, hash, entry, appointment, ancestry, parts);
            }
        }
        recovered
    }

    fn install(
        &mut self,
        by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
        hash: AuthorityEntryHash,
        entry: &AuthorityLogEntry,
        appointment: &RootAppointment,
        ancestry: BTreeSet<AuthorityEntryHash>,
        parts: Arc<ProofParts>,
    ) {
        let index = self.proofs.len();
        for row in &ancestry {
            self.rows
                .insert(*row, parts.states.contains_key(row).then_some(index));
        }
        let mut world = parts.merged.clone();
        super::op_apply::apply_op(&mut world, &entry.op, hash, entry.signer_key());
        world.seqs.insert(entry.signer_key().clone(), entry.seq);
        // It passed anchor authority: no roster fence holds it (F4).
        world.anchor_entries.insert(hash);
        self.worlds.insert(hash, world);
        self.closed_handoffs
            .extend(parts.closed_handoffs.intersection(&ancestry).copied());
        let mut keys = named_device_keys(ancestry.iter().map(|row| &by_hash[row]));
        keys.remove(&appointment.successor.key);
        let mut line = ancestry;
        line.insert(hash);
        self.fences.push(AppointmentFence {
            row: hash,
            vault_id: entry.vault_id,
            keys,
            line,
        });
        self.proofs.push(parts);
    }
}

/// Every key `rows` name as a device: a genesis, enrolled, rotated (old and
/// new), handed-to, owner-enrolled or revoked key, and an earlier
/// appointment's successor. Every roster key of their folds is one, live or
/// revoked, and so is every roster signer; a row the fold refused names its
/// keys here too, as the successor's freshness reads them.
fn named_device_keys<'a>(
    rows: impl Iterator<Item = &'a AuthorityLogEntry>,
) -> BTreeSet<AuthorityKey> {
    let mut keys = BTreeSet::new();
    for row in rows {
        match &row.op {
            AuthorityOp::Genesis { device, .. }
            | AuthorityOp::EnrollDevice { device }
            | AuthorityOp::ReRoot { new_device: device }
            | AuthorityOp::OwnerKeyEnroll(OwnerKeyEnroll { device, .. })
            | AuthorityOp::RootAppointment(RootAppointment {
                successor: device, ..
            }) => {
                keys.insert(device.key.clone());
            }
            AuthorityOp::RotateKey {
                old_key,
                new_device,
            } => {
                keys.insert(old_key.clone());
                keys.insert(new_device.key.clone());
            }
            AuthorityOp::RevokeDevice { revoked_key } => {
                keys.insert(revoked_key.clone());
            }
            _ => {}
        }
    }
    keys
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
    let (Some(anchor), Some(pin)) = (anchor, pin) else {
        return judgement;
    };
    let (verdicts, burned) = judge_anchor(by_hash, &judged);
    judgement.verdicts.extend(verdicts);
    judgement.burned = burned.then_some(anchor);
    // C3: a burn in this log counts none of the anchor's appointments.
    if !burned {
        judgement.recovered = Recovered::of(by_hash, &judgement.verdicts, pin);
    }
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
                    AppointmentVerdict::Void(_) | AppointmentVerdict::SuccessorNotFresh => {
                        burned = true;
                    }
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

/// The verdict of the appointment at `hash` over `rows`, which hold it and
/// its ancestry: what the fold of any install that pins its root judges it,
/// a burn elsewhere in that install's log aside ([`judge_anchor`]). Pending
/// while `rows` lack an ancestor.
pub(super) fn verdict_of_row(
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    hash: &AuthorityEntryHash,
) -> AppointmentVerdict {
    match rows.get(hash).and_then(|entry| ancestry_of(rows, entry)) {
        Some(ancestry) => verdict_of(rows, *hash, &ancestry),
        None => AppointmentVerdict::Pending,
    }
}

/// The verdict of the appointment `entry`, which `rows` need not hold, over
/// its ancestry in `rows`, as [`verdict_of_row`] gives it once `entry` is
/// signed: no verdict reads the signature, which the fold checks before it
/// judges. The appointment door judges each candidate this way before its
/// anchor signs one, so the anchor signs no void appointment. Pending while
/// `rows` lack an ancestor; the unsigned row's verdict is not remembered.
pub(super) fn verdict_of_candidate(
    rows: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    entry: &AuthorityLogEntry,
) -> AppointmentVerdict {
    match ancestry_of(rows, entry) {
        Some(ancestry) => judge_one(rows, entry, &ancestry),
        None => AppointmentVerdict::Pending,
    }
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
    // V1 first: it reads the ancestry once, and a not-fresh row costs no walk
    // of earlier appointments and no proof fold.
    if !successor_is_fresh(by_hash, ancestry, appointment, anchor) {
        return AppointmentVerdict::SuccessorNotFresh;
    }
    let rows: BTreeMap<AuthorityEntryHash, AuthorityLogEntry> = ancestry
        .iter()
        .map(|hash| (*hash, by_hash[hash].clone()))
        .collect();
    // V4 next: an anchor burned beneath the row costs no proof fold.
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
    let scoped: Vec<AuthorityLogEntry> = rows.values().cloned().collect();
    let (proof, parts) = proof_fold(&scoped, appointment.root, anchor);
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
    if let Some(parts) = parts {
        remember_proof(proof_key(entry, appointment.root, anchor), Arc::from(parts));
    }
    AppointmentVerdict::Valid
}

/// The proof folds of valid appointments, kept for counting, by
/// [`proof_key`]: an appointment's ancestry is a function of its parents.
/// Each holds every state of an ancestry, so the map stays small and
/// empties itself at [`PROOF_MEMO_ENTRIES`].
type ProofKey = ([u8; 32], [u8; 32], Vec<AuthorityEntryHash>);
static PROOF_MEMO: OnceLock<Mutex<BTreeMap<ProofKey, Arc<ProofParts>>>> = OnceLock::new();
const PROOF_MEMO_ENTRIES: usize = 16;

fn proof_memo() -> &'static Mutex<BTreeMap<ProofKey, Arc<ProofParts>>> {
    PROOF_MEMO.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// The root, the anchor and the sorted parents of an appointment.
fn proof_key(entry: &AuthorityLogEntry, root: RecoveryRootId, anchor: [u8; 32]) -> ProofKey {
    let mut parents = entry.parent_hashes.clone();
    parents.sort_unstable();
    parents.dedup();
    (root.0, anchor, parents)
}

fn remember_proof(key: ProofKey, parts: Arc<ProofParts>) {
    if let Ok(mut memo) = proof_memo().lock() {
        if memo.len() >= PROOF_MEMO_ENTRIES {
            memo.clear();
        }
        memo.insert(key, parts);
    }
}

/// The proof fold of a valid appointment's complete ancestry `ancestry`, from
/// the memo or folded again.
fn proof_parts(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    entry: &AuthorityLogEntry,
    root: RecoveryRootId,
    anchor: [u8; 32],
    ancestry: &BTreeSet<AuthorityEntryHash>,
) -> Option<Arc<ProofParts>> {
    let key = proof_key(entry, root, anchor);
    if let Some(parts) = proof_memo()
        .lock()
        .ok()
        .and_then(|memo| memo.get(&key).cloned())
    {
        return Some(parts);
    }
    let scoped: Vec<AuthorityLogEntry> =
        ancestry.iter().map(|hash| by_hash[hash].clone()).collect();
    let parts: Arc<ProofParts> = Arc::from(proof_fold(&scoped, root, anchor).1?);
    remember_proof(key, Arc::clone(&parts));
    Some(parts)
}

/// Whether no row of `ancestry` (complete in `by_hash`) names the successor
/// key: no row's canonical signed body carries the key's bytes, so no op of
/// any variant names it (a device it enrols, rotates, hands the root to or
/// revokes, an actor binding or its revocation, an owner root's anchor,
/// another appointment's successor), and neither does a signer or cosigner.
/// A row the codec cannot encode fails freshness. The appointing anchor is
/// never its own successor (the codec).
fn successor_is_fresh(
    by_hash: &BTreeMap<AuthorityEntryHash, AuthorityLogEntry>,
    ancestry: &BTreeSet<AuthorityEntryHash>,
    appointment: &RootAppointment,
    anchor: [u8; 32],
) -> bool {
    let successor = &appointment.successor.key;
    if *successor == AuthorityKey::Ed25519(anchor) {
        return false;
    }
    let key = match successor {
        AuthorityKey::Ed25519(bytes) => bytes.as_slice(),
        AuthorityKey::P256(bytes) => bytes.as_slice(),
    };
    if key.is_empty() {
        return false;
    }
    !ancestry.iter().any(
        |hash| match encode_authority_log_entry_body(&by_hash[hash]) {
            Ok(body) => body.windows(key.len()).any(|window| window == key),
            Err(_) => true,
        },
    )
}

/// ProofFold (PLAN v3 section 4a): the strict fold of exactly `rows`, under
/// inputs no install holds alone: no seen-times and no clock, no peer roots,
/// no local observations, floors, vouches or holds, and no capture; the pin
/// is `root` under `anchor`; the posture is hosted exactly when the genesis
/// among `rows` carries the host's stamp (`ROLE_CLOUD` or
/// [`AuthorityTier::CloudCustodial`]), never the install's config. With the
/// fold, what its last once fold settled ([`ProofParts`]).
pub(super) fn proof_fold(
    rows: &[AuthorityLogEntry],
    root: RecoveryRootId,
    anchor: [u8; 32],
) -> (AuthorityFold, Option<Box<ProofParts>>) {
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
    let (consent, local) = super::fold_engine::own_log_inputs(posture, Some(&pin));
    let capture = FoldCapture::for_proof();
    let fold = super::fold_engine::fold_authority_log_inner(
        rows,
        &BTreeMap::new(),
        None,
        &BTreeMap::new(),
        consent,
        super::fold_engine::FoldLocalInputs {
            capture: Some(&capture),
            ..local
        },
    );
    (fold, capture.take_proof())
}
