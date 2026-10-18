//! A late joiner's access to the kept pad objects (FIX 4271): the home's
//! custody of the grants, and the outbox of the machine where an admission
//! happened. One keyspace ([`SEALED_PAD_GRANT_STORAGE`]):
//!
//! - `q:<machine>:<key digest>`: an admission this vault queued for the home
//!   (`after_machine_admission`), no secret. Queued until a home took
//!   it, then kept as asked, so a later admission does not ask again. A vault
//!   that keeps generations itself takes it at once.
//! - `g:<generation>:<machine>:<key digest>`: the home's custody of one grant
//!   of that generation's pad object outer key to that machine: pending, or
//!   offered with the sealed grant. The home opens none. It keeps an offer
//!   only while the generation is kept, the issuer's signature and standing
//!   hold in the home's own authority, and the recipient stands as the
//!   owner's there under the key the grant names.
//! - A generation's rows go when it retires ([`SEALED_PAD_GRANT_RETENTION`]).
//!
//! No door here asks where a machine runs or what class it is: a machine's
//! standing and the key it proved are the checks (owner rule, 10-19).

use super::bundle::{
    denied, entries_in, entry_in, hex, sealed_digest_from_hex, sealed_generation_from_hex,
    sealed_generation_hex,
};
use crate::Vault;
use crate::authority::{AuthorityFold, PeerMachine};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};
use crate::world_keys::{
    PadAdmissionTarget, RecoveryRootId, SealedBundleGeneration, SealedPadAdmissionGrant,
};

const ACCESS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::SYNC_RESIDENCE_BUNDLE_ACCESS);

/// Where a late joiner's grants live (SEALED_PAD_GRANT_STORAGE).
enum GrantStorage {
    /// The home keeps each grant, pending or offered, beside its
    /// generation; the vault where an admission happened keeps only that it
    /// asked. No grant is kept opened, and no key in the clear.
    HomeCustodyWithLocalAdmissionOutbox,
}

const SEALED_PAD_GRANT_STORAGE: GrantStorage = GrantStorage::HomeCustodyWithLocalAdmissionOutbox;

/// How long the home keeps a grant (CALLS: SEALED_PAD_GRANT_RETENTION).
enum GrantRetention {
    /// As long as its generation: they retire in one transaction. A rewrite
    /// of the pad object keeps it.
    GenerationLifetime,
}

const SEALED_PAD_GRANT_RETENTION: GrantRetention = GrantRetention::GenerationLifetime;

/// A queued admission's row: not yet taken by a home.
const QUEUED: u8 = 0;
/// A queued admission a home took.
const ASKED: u8 = 1;
/// A grant row's state: no grant yet.
const PENDING: u8 = 0;
/// A grant row's state: the sealed grant follows.
const OFFERED: u8 = 1;

/// One machine an admission asks the home for access for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PadAccessRequest {
    pub target: PadAdmissionTarget,
    /// The kept generations it asks for; `None` for every one.
    pub generations: Option<Vec<SealedBundleGeneration>>,
    /// Generations whose offered grant the target itself found unusable,
    /// back to pending; the home takes these from that machine alone.
    pub invalid: Vec<SealedBundleGeneration>,
}

/// What a machine of the owner's may serve: the grants it may issue, and the
/// generations whose grant it waits on itself, which it holds no key of to
/// issue with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PendingPadAccessList {
    pub pending: Vec<PendingPadAccess>,
    pub waiting: Vec<SealedBundleGeneration>,
}

/// One grant a machine of the owner's may issue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingPadAccess {
    pub generation: SealedBundleGeneration,
    pub target: PadAdmissionTarget,
    /// The root the generation's publisher named: the grant is sealed to it
    /// too where the issuer holds its record.
    pub kit_root: Option<RecoveryRootId>,
}

/// One grant row, as its recipient reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PadAccessState {
    /// No grant yet.
    Pending,
    /// A grant the home checked; the recipient checks it again and uses it
    /// only once its key opens the current pad object.
    Offered(SealedPadAdmissionGrant),
}

fn target_key(target: &PadAdmissionTarget) -> String {
    format!(
        "{}:{}",
        target.machine.to_hex(),
        hex(&target.encryption_key_digest)
    )
}

fn queue_key(target: &PadAdmissionTarget) -> String {
    format!("q:{}", target_key(target))
}

fn generation_prefix(generation: &SealedBundleGeneration) -> String {
    format!("g:{}:", sealed_generation_hex(generation))
}

fn grant_key(generation: &SealedBundleGeneration, target: &PadAdmissionTarget) -> String {
    format!("{}{}", generation_prefix(generation), target_key(target))
}

/// `machine:digest` back into a target.
fn parse_target(text: &str) -> Option<PadAdmissionTarget> {
    let (machine, digest) = text.split_once(':')?;
    Some(PadAdmissionTarget {
        machine: EntityId::from_hex(machine).ok()?,
        encryption_key_digest: sealed_digest_from_hex(digest)?,
    })
}

/// A `g:` row's generation and target, from its key after the table prefix.
fn parse_grant_key(key: &[u8]) -> Option<(SealedBundleGeneration, PadAdmissionTarget)> {
    let (generation, target) = std::str::from_utf8(key)
        .ok()?
        .strip_prefix("g:")?
        .split_once(':')?;
    Some((
        sealed_generation_from_hex(generation)?,
        parse_target(target)?,
    ))
}

/// Whether `fold` stands `target` as a machine of the owner's under the key
/// it names.
fn admitted(fold: &AuthorityFold, target: &PadAdmissionTarget) -> bool {
    PadAdmissionTarget::admitted(fold, target.machine) == Some(*target)
}

/// The machine `peer` proved, when it stands as the owner's here on the key it
/// proved.
fn owner_peer(fold: &AuthorityFold, peer: PeerMachine) -> Option<EntityId> {
    let PeerMachine::Proven { machine, key } = peer else {
        return None;
    };
    (fold.trusted_machine(machine).is_some() && fold.machine_proof_key(machine) == Some(key))
        .then_some(machine)
}

/// The kept generations, oldest first.
fn kept_in(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<SealedBundleGeneration>> {
    Ok(entries_in(vault, txn)?
        .into_iter()
        .map(|entry| entry.generation)
        .collect())
}

/// A pending row for `target` in each of `kept` that `generations` names
/// (all with `None`) and that has none, and each of `reset` whose offer is
/// back to pending.
fn ensure_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    kept: &[SealedBundleGeneration],
    target: &PadAdmissionTarget,
    generations: Option<&[SealedBundleGeneration]>,
    reset: &[SealedBundleGeneration],
) -> Result<()> {
    for generation in kept {
        let key = grant_key(generation, target);
        let held = ACCESS.get_bytes(&vault.store, wtxn, &key)?;
        let asked = held.is_none() && generations.is_none_or(|named| named.contains(generation));
        let invalid = reset.contains(generation)
            && held
                .as_ref()
                .is_some_and(|row| row.first() == Some(&OFFERED));
        if asked || invalid {
            ACCESS.put(&vault.store, wtxn, &key, &vec![PENDING])?;
        }
    }
    Ok(())
}

/// Takes each of `requests` whose target stands as the owner's here under the
/// key it names: a pending grant row in each kept generation it asks for that
/// has none. Only the machine `peer` proved, asking for itself, sets an offer
/// it could not use back to pending. Returns the targets taken; any other
/// waits, unanswered, until this home's authority stands it.
///
/// # Errors
///
/// Storage errors.
pub fn ensure_sealed_pad_access(
    vault: &Vault,
    peer: PeerMachine,
    requests: &[PadAccessRequest],
) -> Result<Vec<PadAdmissionTarget>> {
    vault.with_write_txn_grouped(|wtxn| {
        let fold = vault.authority_fold_readonly_in_txn(wtxn)?;
        let addressed = owner_peer(&fold, peer);
        let kept = kept_in(vault, wtxn)?;
        let mut taken = Vec::new();
        for request in requests {
            if !admitted(&fold, &request.target) {
                continue;
            }
            let reset = if addressed == Some(request.target.machine) {
                &request.invalid[..]
            } else {
                &[]
            };
            ensure_in(
                vault,
                wtxn,
                &kept,
                &request.target,
                request.generations.as_deref(),
                reset,
            )?;
            taken.push(request.target);
        }
        Ok(taken)
    })
}

/// Every pending grant a machine of the owner's whose proof stands here may
/// issue: each for another machine still standing as the owner's here under
/// the key it names, with its generation's kit root; and the generations
/// whose grant that machine waits on itself.
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn pending_sealed_pad_access(vault: &Vault, peer: PeerMachine) -> Result<PendingPadAccessList> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    let issuer = owner_peer(&fold, peer).ok_or_else(denied)?;
    let entries = entries_in(vault, &txn)?;
    let mut out = PendingPadAccessList::default();
    for row in ACCESS.iter_raw_from(&vault.store, &txn, b"g:")? {
        let (key, raw) = row?;
        let Some((generation, target)) = parse_grant_key(&key) else {
            continue;
        };
        if raw.first() != Some(&PENDING) || !admitted(&fold, &target) {
            continue;
        }
        if target.machine == issuer {
            out.waiting.push(generation);
        } else if let Some(entry) = entries.iter().find(|entry| entry.generation == generation) {
            out.pending.push(PendingPadAccess {
                generation,
                target,
                kit_root: entry.kit.map(|kit| kit.root),
            });
        }
    }
    Ok(out)
}

/// Keeps `grant` as offered for its recipient: its generation is kept, its
/// issuer's signature and standing hold in this home's authority, its
/// recipient stands as the owner's here under the key it names, and the only
/// root it names is the one the generation's publisher named. Whoever uploads
/// it, the grant's own signature is its authority.
///
/// # Errors
///
/// A refused grant; storage errors.
pub fn offer_sealed_pad_access(vault: &Vault, grant: &SealedPadAdmissionGrant) -> Result<()> {
    let row = {
        let mut row = vec![OFFERED];
        row.extend_from_slice(&grant.to_bytes()?);
        row
    };
    vault.with_write_txn_grouped(|wtxn| {
        let fold = vault.authority_fold_readonly_in_txn(wtxn)?;
        let target = grant.recipient();
        let Some(entry) = entry_in(vault, wtxn, &grant.generation())? else {
            return Err(denied());
        };
        let root_named = grant
            .kit_root()
            .is_none_or(|root| entry.kit.is_some_and(|kit| kit.root == root));
        if !root_named || !admitted(&fold, &target) || !grant.issued_by_authority(&fold) {
            return Err(denied());
        }
        ACCESS.put(
            &vault.store,
            wtxn,
            &grant_key(&grant.generation(), &target),
            &row,
        )
    })
}

/// The grant rows of `generation` addressed to the machine `peer` proved,
/// whose proof stands here as the owner's: the recipient comes from the proof,
/// never from the request. Rows under any of its keys; the machine picks its
/// current one.
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn sealed_pad_access(
    vault: &Vault,
    peer: PeerMachine,
    generation: SealedBundleGeneration,
) -> Result<Vec<(PadAdmissionTarget, PadAccessState)>> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    let machine = owner_peer(&fold, peer).ok_or_else(denied)?;
    let prefix = format!("{}{}:", generation_prefix(&generation), machine.to_hex());
    let mut out = Vec::new();
    for row in ACCESS.iter_raw_from(&vault.store, &txn, prefix.as_bytes())? {
        let (key, raw) = row?;
        let Some((_, target)) = parse_grant_key(&key) else {
            continue;
        };
        let state = match raw.split_first() {
            Some((&PENDING, [])) => PadAccessState::Pending,
            Some((&OFFERED, grant)) => match SealedPadAdmissionGrant::from_bytes(grant) {
                Ok(grant) => PadAccessState::Offered(grant),
                Err(_) => continue,
            },
            _ => continue,
        };
        out.push((target, state));
    }
    Ok(out)
}

/// Drops `generation`'s grant rows with it, in its retiring transaction
/// ([`SEALED_PAD_GRANT_RETENTION`]).
pub(super) fn retire_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    generation: &SealedBundleGeneration,
) -> Result<()> {
    match SEALED_PAD_GRANT_RETENTION {
        GrantRetention::GenerationLifetime => {
            ACCESS.delete_from(&vault.store, wtxn, generation_prefix(generation).as_bytes())?;
        }
    }
    Ok(())
}

impl Vault {
    /// The admission hook (FIX 4271): queues each machine the owner admitted,
    /// live here, under its current key, that this vault has not asked for
    /// yet, for an old reader to grant it each kept pad object. A vault that
    /// keeps generations itself, the home, takes it at once. Idempotent; a
    /// failure leaves the machine's own sweep to ask.
    ///
    /// A vault that never queued one cannot tell an old reader from a machine
    /// just admitted: it notes every machine standing now as asked, and asks
    /// for none, so no old reader waits on a grant it does not need. Each of
    /// those that lacks a key asks for itself when it sweeps.
    pub(crate) fn queue_sealed_bundle_pad_admissions(&self) -> Result<()> {
        match SEALED_PAD_GRANT_STORAGE {
            GrantStorage::HomeCustodyWithLocalAdmissionOutbox => {}
        }
        self.with_write_txn_grouped(|wtxn| {
            let fold = self.authority_view_readonly_in_txn(wtxn)?;
            let kept = kept_in(self, wtxn)?;
            let first = ACCESS
                .iter_raw_from(&self.store, wtxn, b"q:")?
                .next()
                .is_none();
            let machines: Vec<EntityId> = fold.machines.keys().copied().collect();
            for machine in machines {
                let Some(target) = PadAdmissionTarget::admitted(&fold, machine) else {
                    continue;
                };
                let key = queue_key(&target);
                if ACCESS.get_bytes(&self.store, wtxn, &key)?.is_some() {
                    continue;
                }
                let state = if first {
                    ASKED
                } else if kept.is_empty() {
                    QUEUED
                } else {
                    ensure_in(self, wtxn, &kept, &target, None, &[])?;
                    ASKED
                };
                ACCESS.put(&self.store, wtxn, &key, &vec![state])?;
            }
            Ok(())
        })
    }

    /// The admissions this vault queued that no home took yet, each still
    /// standing as the owner's here under its key. A queued or asked row
    /// whose machine no longer does goes.
    pub(crate) fn queued_pad_admissions(&self) -> Result<Vec<PadAdmissionTarget>> {
        let (queued, obsolete) = {
            let txn = self.store.env.read_txn()?;
            let fold = self.authority_view_readonly_in_txn(&txn)?;
            let mut queued = Vec::new();
            let mut obsolete = Vec::new();
            for row in ACCESS.iter_raw_from(&self.store, &txn, b"q:")? {
                let (key, raw) = row?;
                let Some(target) = std::str::from_utf8(&key)
                    .ok()
                    .and_then(|key| key.strip_prefix("q:"))
                    .and_then(parse_target)
                else {
                    continue;
                };
                if !admitted(&fold, &target) {
                    obsolete.push(queue_key(&target));
                } else if raw == [QUEUED] {
                    queued.push(target);
                }
            }
            (queued, obsolete)
        };
        if !obsolete.is_empty() {
            self.with_write_txn_grouped(|wtxn| {
                for key in &obsolete {
                    ACCESS.delete(&self.store, wtxn, key)?;
                }
                Ok(())
            })?;
        }
        Ok(queued)
    }

    /// Marks each of `taken`, which a home took, as asked.
    pub(crate) fn acknowledge_pad_admissions(&self, taken: &[PadAdmissionTarget]) -> Result<()> {
        if taken.is_empty() {
            return Ok(());
        }
        self.with_write_txn_grouped(|wtxn| {
            for target in taken {
                let key = queue_key(target);
                if ACCESS.get_bytes(&self.store, wtxn, &key)?.is_some() {
                    ACCESS.put(&self.store, wtxn, &key, &vec![ASKED])?;
                }
            }
            Ok(())
        })
    }
}
