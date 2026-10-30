//! OF-422 Phase 1 (ARCH-0069 `#custody-seal-planned`): a portable credential
//! syncs again, but only as a custody transition the owner's act stands
//! behind.
//!
//! The custody record stays sealed from every replicated door, as before: a
//! peer's custody body proves nothing about who wrote it. What travels
//! instead is a transition: the record at one generation with its value taken
//! out, the value sealed to each recipient the owner permitted, and the
//! signature of the install that enacted it. A transition names the admitted
//! custody request it enacts (WILL L04 row 04, CALLS CUSTODY_PAYLOAD): the
//! request's named executor signed it, its generation, input and permits are
//! the request's, and a receiver checks exactly that against its own fold,
//! in the transaction that writes the record. A receiver writes the record
//! through the local custody door only when its own machine opens the value.
//! An install that was not permitted holds the transition unread and
//! forwards it.
//!
//! A device-bound, cross-vault or "this device only" record never makes one:
//! that material stays on the device that holds it.

mod kit_request;
mod payload;
mod pieces;
mod rebind;

#[cfg(feature = "sync")]
pub(crate) use self::rebind::moves_custody_floor;

use ed25519_dalek::SigningKey;
use oneiron_crypto::HybridPublicKey;

use self::payload::{status_byte, unsigned};
pub(crate) use self::pieces::{CustodyPieces, custody_row_key, parse_custody_row_key};
#[cfg(feature = "sync")]
pub(crate) use self::pieces::{completed_custody_groups_in_txn, keep_custody_piece_in_txn};
use super::codec::encode_secret_custody_body;
use super::doors::bind_synced_name_in_txn;
use super::types::{CustodyClass, SecretCustodyRecord, SecretCustodyStatus};
use crate::Vault;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, CustodyChange, CustodyRecipientPermit, OwnerWorkBody,
    OwnerWorkOutcome, owner_act_signer_admits,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, HexId, Raw, SideTable};

/// The latest transition this vault holds of each portable credential, signed
/// here or taken from a window, by record id. The sync layer mirrors each into
/// the window of its signing month.
const TRANSITIONS: SideTable<HexId, Vec<u8>, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_TRANSITION);

/// What a custody transition proves (CALLS CUSTODY_PAYLOAD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyPayload {
    /// The artifact names the admitted custody request it enacts and the
    /// digest of that request's encrypted input, and carries the request's
    /// permits; each value envelope binds the request, the status and the
    /// recipient's profile entry and key. A receiver admits it only on that
    /// causal evidence: the request counted in its fold, signed for by the
    /// request's named executor, with exactly its generation, input and
    /// permits. A bare hash, or a bare enacted result, is not enough.
    RequestBoundOct1,
}

const CUSTODY_PAYLOAD: CustodyPayload = CustodyPayload::RequestBoundOct1;

/// Whether ordinary custody control ever signs with the owner's recovery
/// seed (CALLS CUSTODY_ORDINARY_CONTROL_SEED).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyOrdinaryControlSeed {
    /// Never: register, rotate, rewrap and revoke are each a request a live
    /// linked install carries and its holder enacts, the recorder being its
    /// own holder when nobody else holds the secret. The recovery ceremony
    /// keeps its own seed proof, and no origin is authority anywhere.
    Never,
}

const CUSTODY_ORDINARY_CONTROL_SEED: CustodyOrdinaryControlSeed = CustodyOrdinaryControlSeed::Never;

/// The one push the owner's recovery kit still signs (CALLS CUSTODY_KIT_PUSH,
/// Engine ruling 10-19 08:0x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyKitPush {
    /// The owner's kit is his authority; the install carries no act. Only an
    /// install with no live machine profile in the vault, which can carry no
    /// owner act and so cannot be any request's holder, pushes the portable
    /// record it holds with the anchor of the root this vault pins, to the
    /// recipients he names. Every other install takes the explicit-holder
    /// path, and a receiver admits an anchor signature only on a transition
    /// that names no request and no input.
    UnprofiledInstallOnly,
}

const CUSTODY_KIT_PUSH: CustodyKitPush = CustodyKitPush::UnprofiledInstallOnly;

/// One custody transition of a portable credential.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct CustodyTransition {
    /// The custody record's id.
    pub(crate) id: EntityId,
    /// The record's rotation generation.
    pub(crate) generation: u32,
    pub(crate) status: SecretCustodyStatus,
    /// Unix seconds at signing.
    pub(crate) signed_at: u64,
    /// The entry hash of the admitted custody request this transition
    /// enacts; zero for the owner's kit push (CALLS CUSTODY_KIT_PUSH).
    pub(crate) request: AuthorityEntryHash,
    /// The digest of the encrypted input the request names; `None` for a
    /// rewrap, a revoke and a kit push.
    pub(crate) input: Option<[u8; 32]>,
    /// The commitment to the complete permitted set every piece of this
    /// transition carries part of (`custody_recipient_set`).
    pub(crate) set: [u8; 32],
    /// This piece's place among the transition's `pieces`, from zero.
    pub(crate) piece: u32,
    pub(crate) pieces: u32,
    /// Where this piece's permits start in the complete set.
    pub(crate) first: u32,
    /// The record in the body codec, its value taken out.
    body: Vec<u8>,
    /// The value sealed to each permitted recipient, with its permit,
    /// ascending by machine, a value too large for one carrier in numbered
    /// envelopes, each beside its permit (FIX 7953); none once revoked.
    sealed: Vec<(CustodyRecipientPermit, Vec<u8>)>,
    /// The Ed25519 key that signed.
    pub(crate) signer: [u8; 32],
    signature: [u8; 64],
}

// Never print the sealed value or the body.
impl std::fmt::Debug for CustodyTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodyTransition")
            .field("id", &self.id)
            .field("generation", &self.generation)
            .field("status", &self.status)
            .field("signed_at", &self.signed_at)
            .field("piece", &self.piece)
            .field("pieces", &self.pieces)
            .field("recipients", &self.permits().count())
            .finish_non_exhaustive()
    }
}

/// Whether `record` may leave this device: custody-portable with its "this
/// device only" dial off.
pub(crate) fn custody_portable(record: &SecretCustodyRecord) -> bool {
    record.class == CustodyClass::CustodyPortable && !record.device_only
}

/// What a transition enacts: the request's entry hash (zero for a kit push),
/// the digest of its input, and each permit with the key it seals to.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Enactment<'a> {
    pub(crate) request: AuthorityEntryHash,
    pub(crate) input: Option<[u8; 32]>,
    pub(crate) permits: &'a [(CustodyRecipientPermit, HybridPublicKey)],
}

/// Signs the transition of record `id` as it stands in `record` with
/// `signing`, its value sealed to each permit of `enactment`, at `signed_at`,
/// in as many pieces as the carrier's frame floors need (CALLS `Phase2
/// custody pieces request bound`). A live record is sealed to every permit,
/// however many, a revoked one to none.
///
/// # Errors
/// The vault has no authority genesis; the record may not leave its device;
/// it is live but an admitted revoke names its id, which nothing brings
/// back; the permits do not fit its status; its body leaves a carrier no
/// room for a value.
pub(crate) fn sign_custody_transition(
    fold: &AuthorityFold,
    signing: &SigningKey,
    id: EntityId,
    record: &SecretCustodyRecord,
    enactment: Enactment<'_>,
    signed_at: u64,
) -> Result<CustodyPieces> {
    let Some(vault_id) = fold.vault_id else {
        return Err(refused("this vault has no authority genesis to sign for"));
    };
    let revoked = record.status == SecretCustodyStatus::Revoked;
    if !custody_portable(record) {
        return Err(refused("this secret stays on its device"));
    }
    if !revoked && fold.custody_revoked(&id) {
        return Err(refused("an admitted revoke ended this secret"));
    }
    if revoked != enactment.permits.is_empty() {
        return Err(refused(
            "a live secret is sealed to its permitted recipients, a revoked one to none",
        ));
    }
    let mut bare = record.clone();
    zeroize::Zeroize::zeroize(&mut bare.value_bytes);
    let body = encode_secret_custody_body(&bare)?;
    let mut permits: Vec<CustodyRecipientPermit> = enactment
        .permits
        .iter()
        .map(|(permit, _)| *permit)
        .collect();
    permits.sort_unstable_by_key(|permit| permit.machine);
    let template = CustodyTransition {
        id,
        generation: record.rotation_generation,
        status: record.status,
        signed_at,
        request: enactment.request,
        input: enactment.input,
        set: crate::authority::custody_recipient_set(&permits),
        piece: 0,
        pieces: 1,
        first: 0,
        body,
        sealed: Vec::new(),
        signer: signing.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    pieces::sign_pieces(
        &vault_id,
        signing,
        template,
        enactment.permits,
        &record.value_bytes,
    )
}

/// The second a new transition of record `id` is signed at: `at`, or just
/// after the transition held at the same generation and status, which it
/// then replaces.
fn signed_after_held_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    record: &SecretCustodyRecord,
    at: u64,
) -> Result<u64> {
    let order = (record.rotation_generation, status_rank(record.status));
    Ok(TRANSITIONS
        .get(&vault.store, txn, &HexId(id))?
        .and_then(|held| CustodyPieces::decode(&held))
        .map(|held| held.lead().clone())
        .filter(|held| held.order() == order)
        .map_or(at, |held| at.max(held.signed_at.saturating_add(1))))
}

/// Signs, with this install's key, and stores in the executor's own write
/// transaction the transition of record `id` as `record` now stands, for
/// `enactment`'s request: every piece, each verified, or none. A transition
/// is never optional here: no install key, or any reason
/// [`sign_custody_transition`] refuses, refuses the transaction. Returns the
/// pieces written.
pub(crate) fn write_custody_transition_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: EntityId,
    record: &SecretCustodyRecord,
    enactment: Enactment<'_>,
    at: u64,
) -> Result<CustodyPieces> {
    let signing = crate::identity::read_machine_signing_key_in_txn(vault, wtxn)?
        .ok_or_else(|| refused("this install has no install key to sign the custody transition"))?;
    let fold = vault.authority_view_readonly_in_txn(wtxn)?;
    let signed_at = signed_after_held_in_txn(vault, wtxn, id, record, at)?;
    let pieces = sign_custody_transition(&fold, &signing, id, record, enactment, signed_at)?;
    TRANSITIONS.put(&vault.store, wtxn, &HexId(id), &pieces.encode())?;
    Ok(pieces)
}

/// Keeps `transition`, one piece, as this vault's latest of its record when
/// it supersedes the one held, so this vault relays it, and drops the
/// carrier it supersedes from the window that carrier rides; a piece of the
/// transition held joins its siblings, the rest still owed. An erased
/// credential's is never kept (KS-6 part 2). Returns whether it kept it.
pub(crate) fn remember_custody_transition_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    transition: &CustodyTransition,
) -> Result<bool> {
    if vault.store.credential_fenced_in_txn(wtxn, &transition.id) {
        return Ok(false);
    }
    let key = HexId(transition.id);
    let held = TRANSITIONS
        .get(&vault.store, wtxn, &key)?
        .and_then(|held| CustodyPieces::decode(&held));
    let kept = match held {
        Some(held) if held.lead().same_transition(transition) => {
            match held.with_piece(transition) {
                Some(joined) => joined,
                None => return Ok(false),
            }
        }
        Some(held) if !transition.supersedes(held.lead()) => return Ok(false),
        _ => CustodyPieces::single(transition.clone()),
    };
    TRANSITIONS.put(&vault.store, wtxn, &key, &kept.encode())?;
    Ok(true)
}

/// [`remember_custody_transition_in_txn`] for every piece of `pieces`.
fn remember_custody_pieces_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    pieces: &CustodyPieces,
) -> Result<bool> {
    let mut kept = false;
    for piece in pieces.pieces() {
        kept |= remember_custody_transition_in_txn(vault, wtxn, piece)?;
    }
    Ok(kept)
}

/// Whether this vault keeps a carrier of record `id` that still seals its
/// value: any that is not revoked, or does not decode.
pub(crate) fn holds_sealed_carrier_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(TRANSITIONS
        .get(&vault.store, txn, &HexId(*id))?
        .is_some_and(|held| {
            !CustodyPieces::decode(&held)
                .is_some_and(|held| held.lead().status == SecretCustodyStatus::Revoked)
        }))
}

/// Drops the carrier this vault keeps of record `id` while it still seals
/// the value: a revoke leaves at most the revoked carrier, byte-free (CALLS
/// CUSTODY_REVOKE_ERASE). Returns whether it dropped one.
pub(crate) fn drop_sealed_carrier_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if !holds_sealed_carrier_in_txn(vault, wtxn, id)? {
        return Ok(false);
    }
    TRANSITIONS.delete(&vault.store, wtxn, &HexId(*id))
}

/// Whether this vault holds `transition`, byte for byte, as its record's
/// latest: what it applied and kept before.
#[cfg(feature = "sync")]
pub(crate) fn holds_custody_carrier_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    transition: &CustodyTransition,
) -> Result<bool> {
    Ok(TRANSITIONS
        .get(&vault.store, txn, &HexId(transition.id))?
        .and_then(|held| CustodyPieces::decode(&held))
        .is_some_and(|held| held.pieces().contains(transition)))
}

/// The record id and record, value out, of the latest live transition this
/// vault holds under `name`: what an install the value was never sealed to
/// knows of a portable secret. Revoked ones are left out.
pub(crate) fn transition_named_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<Option<(EntityId, SecretCustodyRecord)>> {
    let mut found: Option<(CustodyTransition, SecretCustodyRecord)> = None;
    for (_, carrier) in TRANSITIONS.scan(&vault.store, txn)? {
        let Some(held) = CustodyPieces::decode(&carrier) else {
            continue;
        };
        let transition = held.lead().clone();
        let Ok(record) = transition.record() else {
            continue;
        };
        if record.name != name || transition.status == SecretCustodyStatus::Revoked {
            continue;
        }
        if found
            .as_ref()
            .is_none_or(|(held, _)| transition.order() > held.order())
        {
            found = Some((transition, record));
        }
    }
    Ok(found.map(|(transition, record)| (transition.id, record)))
}

/// Every transition this vault holds that decodes, its pieces together, in
/// `txn`.
#[cfg(feature = "sync")]
pub(crate) fn held_transitions_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<CustodyPieces>> {
    Ok(TRANSITIONS
        .scan(&vault.store, txn)?
        .into_iter()
        .filter_map(|(_, carrier)| CustodyPieces::decode(&carrier))
        .collect())
}

/// Every piece of every transition this vault holds that decodes.
pub(crate) fn custody_transitions(vault: &Vault) -> Result<Vec<CustodyTransition>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(TRANSITIONS
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .filter_map(|(_, carrier)| CustodyPieces::decode(&carrier))
        .flat_map(CustodyPieces::into_pieces)
        .collect())
}

impl CustodyTransition {
    /// Where this transition stands among the record's: its generation, then
    /// its status (active, suspended, revoked).
    pub(crate) fn order(&self) -> (u32, u8) {
        (self.generation, status_rank(self.status))
    }

    /// Whether this carrier replaces `other`, of the same record: a later
    /// [`Self::order`], or the same one signed later, as a rewrap is. Two
    /// transitions signed in the same second settle on the greater request,
    /// set, input, signer and body, the same on every machine and for every
    /// piece; a piece never replaces a sibling of its own transition.
    pub(crate) fn supersedes(&self, other: &Self) -> bool {
        self.identity() > other.identity()
    }

    /// Whether this transition stands under `fold` as it is now: whole
    /// ([`Self::verify_signed`]) and enacting an admitted custody request
    /// its named executor signed for (CALLS CUSTODY_PAYLOAD), or the owner's
    /// kit push (CALLS CUSTODY_KIT_PUSH).
    pub(crate) fn verify(&self, fold: &AuthorityFold) -> Result<()> {
        self.verify_signed(&fold.vault_id.ok_or_else(unsigned)?)?;
        let admitted = if self.request == [0; 32] {
            kit_push_admits(fold, self)
        } else {
            request_admits(fold, self)
        };
        if !admitted {
            return Err(unsigned());
        }
        Ok(())
    }
}

/// The causal evidence a request-bound transition stands on (CALLS
/// CUSTODY_PAYLOAD): its request counts in `fold` and is not refused, targets
/// its record, approves its generation and names its input; its status is
/// the change's; it is sealed under exactly the request's permits; and the
/// request's named executor, a live linked install, signed it. Whether a
/// recipient is mine is never asked: the owner permitted it.
fn request_admits(fold: &AuthorityFold, transition: &CustodyTransition) -> bool {
    match CUSTODY_PAYLOAD {
        CustodyPayload::RequestBoundOct1 => {
            let Some(request) = fold.counted_owner_work_request(&transition.request) else {
                return false;
            };
            // The owner's kit push names the kit request it recorded (FIX
            // 6053): no machine executed it.
            if request.kit_root().is_some() {
                return kit_request::kit_request_admits(fold, request, transition);
            }
            let OwnerWorkBody::Custody {
                change,
                generation,
                input,
                recipients,
                ..
            } = &request.work
            else {
                return false;
            };
            let status = match change {
                CustodyChange::Revoke => transition.status == SecretCustodyStatus::Revoked,
                CustodyChange::Register | CustodyChange::Rotate => {
                    transition.status == SecretCustodyStatus::Active
                }
                CustodyChange::Rewrap => transition.status != SecretCustodyStatus::Revoked,
            };
            let refused = fold
                .owner_work_result(&transition.request)
                .is_some_and(|answer| matches!(answer.outcome, OwnerWorkOutcome::Refused { .. }));
            request.act.target == transition.id
                && *generation == transition.generation
                && *input == transition.input
                && status
                && !refused
                && transition.piece_of(recipients)
                && owner_act_signer_admits(
                    fold.machine(request.executor),
                    &fold.roster,
                    &transition.signer,
                )
        }
    }
}

/// The one transition the owner's kit signs (CALLS CUSTODY_KIT_PUSH): it
/// names no request and no input, and the anchor of the root this vault pins
/// signed it.
fn kit_push_admits(fold: &AuthorityFold, transition: &CustodyTransition) -> bool {
    match CUSTODY_KIT_PUSH {
        CustodyKitPush::UnprofiledInstallOnly => {
            transition.input.is_none()
                && fold
                    .pinned_root
                    .as_ref()
                    .is_some_and(|root| root.anchor_key == transition.signer)
        }
    }
}

/// Whether this install may push with the owner's kit (CALLS
/// CUSTODY_KIT_PUSH): it has no live machine profile in the vault, so it
/// carries no owner act and holds for no request. Ordinary control never
/// reaches the seed (CALLS CUSTODY_ORDINARY_CONTROL_SEED).
fn kit_push_allowed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
) -> Result<bool> {
    match (CUSTODY_ORDINARY_CONTROL_SEED, CUSTODY_KIT_PUSH) {
        (CustodyOrdinaryControlSeed::Never, CustodyKitPush::UnprofiledInstallOnly) => {
            let Some(machine) = crate::identity::read_machine_id_in_txn(vault, txn)? else {
                return Ok(true);
            };
            Ok(fold.machine(machine).is_none_or(|folded| {
                folded.chains().any(|(_, chain)| chain.removed)
                    || !folded.chains().any(|(_, chain)| chain.is_live())
            }))
        }
    }
}

impl Vault {
    /// Pushes the current transition of the portable record `secret_ref`
    /// names, signed with the owner anchor of `seed`, the recovery root this
    /// vault pins, its value sealed to `recipients`, each a live linked
    /// install with an importable key (CALLS CUSTODY_KIT_PUSH): the owner's
    /// kit is his authority; the install carries no act. Only an install with
    /// no live machine profile may push, so ordinary control never signs
    /// with the seed (CALLS CUSTODY_ORDINARY_CONTROL_SEED); any other install
    /// rewraps the record as its own holder ([`Vault::rewrap_secret_as_owner`]).
    /// No origin is asked: the kit is the proof. The record keeps its
    /// generation, status and value.
    ///
    /// # Errors
    /// This install has a live machine profile; a proof that is no longer
    /// the live vault owner's; a seed whose root is not the root this vault
    /// pins; a name no record holds; a recipient that is no live linked
    /// install with an importable key, or none of them; the refusals of
    /// [`sign_custody_transition`]; storage errors.
    pub fn sign_custody_with_anchor(
        &self,
        owner: &crate::consent::AuthenticatedOwner,
        seed: &crate::world_keys::RecoveryRootSeed,
        secret_ref: &str,
        recipients: &[EntityId],
        at: u64,
    ) -> Result<bool> {
        let vault_id = {
            let rtxn = self.store.env.read_txn()?;
            self.authority_view_readonly_in_txn(&rtxn)?
                .vault_id
                .ok_or_else(unsigned)?
        };
        // The anchor is derived before the write transaction opens.
        let root = seed.public(&vault_id)?;
        let anchor = seed.anchor();
        let transition = self.with_write_txn(|wtxn| {
            let actor = owner.revalidate_as_vault_owner_in_txn(self, wtxn)?;
            let fold = self.authority_view_readonly_in_txn(wtxn)?;
            if !kit_push_allowed_in_txn(self, wtxn, &fold)? {
                return Err(Error::InvalidConfig(
                    "this install has a live machine profile, so it carries the owner's act: \
                     rewrap the secret with this install as its holder (`oneiron secrets \
                     rewrap`); the kit pushes only from an install with no profile"
                        .into(),
                ));
            }
            if fold.vault_id != Some(vault_id)
                || fold
                    .pinned_root
                    .as_ref()
                    .is_none_or(|pin| pin.id != root.id || pin.anchor_key != root.anchor_key)
            {
                return Err(Error::InvalidConfig(
                    "the seed's root is not the root this vault pins".into(),
                ));
            }
            let id = super::resolve_secret_ref_in_txn(&self.store, wtxn, secret_ref)?.ok_or_else(
                || {
                    Error::Secret(crate::error::SecretError::SecretRefNotFound {
                        name: secret_ref.to_owned(),
                    })
                },
            )?;
            let Some(record) = super::read_secret_custody_in_txn(&self.store, wtxn, &id)? else {
                return Ok(None);
            };
            let record = WipedRecord(record);
            let permits =
                super::control::permits::permits_for(&fold, recipients).map_err(|machine| {
                    Error::InvalidConfig(format!(
                        "recipient {} is not a linked install with an importable encryption key; \
                     nothing was written",
                        machine.to_hex()
                    ))
                })?;
            let keyed = super::control::permits::permitted_keys(&fold, &permits)
                .ok_or_else(|| refused("a recipient's key changed"))?;
            let keyed = if record.0.status == SecretCustodyStatus::Revoked {
                Vec::new()
            } else {
                keyed
            };
            // FIX 6053: the push records the custody request it enacts, under
            // the pinned kit's authority; a fault leaves it as before.
            let request = if keyed.is_empty() {
                [0; 32]
            } else {
                kit_request::record_kit_request_in_txn(
                    self,
                    wtxn,
                    &fold,
                    actor,
                    id,
                    record.0.rotation_generation,
                    &permits,
                    (&anchor, root.id),
                )
            };
            let enactment = Enactment {
                request,
                input: None,
                permits: &keyed,
            };
            let signed_at = signed_after_held_in_txn(self, wtxn, id, &record.0, at)?;
            let pieces =
                sign_custody_transition(&fold, &anchor, id, &record.0, enactment, signed_at)?;
            Ok(remember_custody_pieces_in_txn(self, wtxn, &pieces)?.then_some(pieces))
        })?;
        #[cfg(feature = "sync")]
        if transition.is_some() {
            self.refresh_custody_in_live_windows();
        }
        Ok(transition.is_some())
    }
}

/// A record whose value is wiped when it drops, on every path.
struct WipedRecord(SecretCustodyRecord);

impl Drop for WipedRecord {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0.value_bytes);
    }
}

/// What a transition did to this vault's custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CustodyApplied {
    /// The record was written at the transition's generation and status.
    Written,
    /// This vault holds the record at that generation and status, or later.
    Stale,
    /// The record stays as this vault holds it: it is local here (device
    /// bound, cross-vault or "this device only"), revoked, its name belongs to
    /// another live record, or its bindings are wider than this vault's floor.
    Kept,
    /// This machine holds no value the transition sealed to it.
    Unopened,
    /// An admitted revoke names the record's id, so this live transition is
    /// refused: a held portable record and its leases were revoked here, and
    /// nothing the transition carries is written or kept (WILL L04 row 04).
    /// So is one an erase fenced here, which never comes back (KS-6 part 2).
    Refused,
    /// The transition does not stand on this transaction's fold (CALLS
    /// CUSTODY_PAYLOAD): nothing it carries is written or kept.
    Unadmitted,
}

/// Writes the transition `group` carries whole into this vault's custody,
/// with `value` the one this machine opened from it, never from a piece
/// alone. The group is checked again against this transaction's own fold
/// first ([`CustodyPieces::verify`]). A generation never goes back, a
/// revoked record never comes back, and a record this vault keeps local
/// never takes a peer's transition. A rewrap at the generation and status
/// held changes the bindings alone, by its request (CALLS
/// CUSTODY_BIND_TRAVEL), or stays pending while the live floor here refuses
/// them (CALLS CUSTODY_REBIND_PENDING_FLOOR); so does a carrier that brings
/// the record (CALLS CUSTODY_CARRIER_PENDING_FLOOR). A revocation also
/// revokes the record's leases here and erases its value (CALLS
/// CUSTODY_REVOKE_ERASE).
///
/// An admitted revoke of the id in this transaction's fold is terminal (CALLS
/// CUSTODY_CONCURRENT_ACTIVE): a live transition of it is refused, and a held
/// portable record dies with its leases, though no revoked transition came.
pub(crate) fn apply_custody_transition_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    group: &CustodyPieces,
    value: Option<&[u8]>,
    at: u64,
) -> Result<CustodyApplied> {
    let transition = group.lead();
    if transition.status != SecretCustodyStatus::Revoked
        && super::control::custody_revoked_in_txn(vault, wtxn, &transition.id)?
    {
        super::control::settle_revoked_in_txn(vault, wtxn, &transition.id, at)?;
        return Ok(CustodyApplied::Refused);
    }
    // An erased credential never comes back by a transition (KS-6 part 2).
    if vault.store.credential_fenced_in_txn(wtxn, &transition.id) {
        return Ok(CustodyApplied::Refused);
    }
    let fold = vault.authority_view_readonly_in_txn(wtxn)?;
    if group.verify(&fold).is_err() {
        return Ok(CustodyApplied::Unadmitted);
    }
    let mut record = transition.record()?;
    let held =
        super::read_secret_custody_meta_in_txn(&vault.store, wtxn, &transition.id)?.map(|held| {
            (
                custody_portable(&held),
                held.status,
                held.rotation_generation,
            )
        });
    if let Some((portable, status, generation)) = held {
        if !portable || status == SecretCustodyStatus::Revoked {
            return Ok(CustodyApplied::Kept);
        }
        match (transition.generation, status_rank(transition.status))
            .cmp(&(generation, status_rank(status)))
        {
            std::cmp::Ordering::Less => return Ok(CustodyApplied::Stale),
            std::cmp::Ordering::Equal => {
                return rebind::rebind_held_in_txn(vault, wtxn, &fold, transition, &record, at);
            }
            std::cmp::Ordering::Greater => {}
        }
    }
    if transition.status == SecretCustodyStatus::Revoked {
        // Nothing is written for an id this vault never held: never an empty
        // record. The id's terminal knowledge is its admitted revoke request
        // on the main log, which every replica folds, not this carrier.
        if held.is_none() {
            return Ok(CustodyApplied::Stale);
        }
        crate::secret_rotation::revoke_custody_in_txn(
            vault,
            wtxn,
            &transition.id,
            crate::secret_rotation::RevokeCause::Revoked,
            at,
        )?;
        return Ok(CustodyApplied::Written);
    }
    let Some(value) = value else {
        return Ok(CustodyApplied::Unopened);
    };
    record.value_bytes = value.to_vec();
    if super::refuse_bindings_wider_than_live_floor(&vault.store, wtxn, &record).is_err()
        || !bind_synced_name_in_txn(
            &vault.store,
            wtxn,
            &record.name,
            &transition.id,
            transition.generation,
        )?
    {
        return Ok(CustodyApplied::Kept);
    }
    super::put_secret_custody_in_txn(vault, wtxn, &transition.id, &record, at)?;
    Ok(CustodyApplied::Written)
}

/// Active, then suspended, then revoked: a status only moves forward within a
/// generation.
fn status_rank(status: SecretCustodyStatus) -> u8 {
    status_byte(status)
}

fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!(
        "custody transition not signed: {reason}; nothing was written"
    ))
}
