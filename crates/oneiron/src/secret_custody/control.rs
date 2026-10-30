//! Custody control on the shared owner-work request (WILL L04 row 04): every
//! change to a portable secret's custody is the owner's request, carried by
//! a live linked install and done by the one install it names.
//!
//! An active change (register, rotate, rewrap) names its holder explicitly
//! and the recipients the owner permits to hold its bytes ([`permits`]). The
//! holder may be this install; it is never elected, and nobody takes over. A
//! register or rotate hands the holder its metadata and value as a protected
//! input sealed to the holder's key alone ([`input`]); the request names
//! only its ciphertext digest. When the recorder is the holder it executes
//! in the same commit ([`execute`]); any other holder opens the relayed
//! input on its pickup and does the same. Either way the effect, the
//! request-bound custody transition, the rotation receipt link and the
//! enacted result commit together, and the receipt says what is true:
//! recorded and awaiting the holder, enacted (committed by the holder, never
//! "delivered everywhere": no machine acknowledges a transition, so delivery
//! stays unknown), refused, or kept on this install and why.
//!
//! The owner's revoke reaches every replica as main-log metadata, with no
//! byte. The revoke door records a custody revoke request naming this
//! install, its carrier, as executor, and in the same writer transaction
//! revokes the record and its leases here, appends the enacted result and
//! writes the revoked transition bound to the request
//! ([`Vault::revoke_secret_as_owner`]). Every replica that folds the request
//! holds its id as terminal (`AuthorityFold::custody_revoked`): after an
//! authority catch-up and on the served tick it revokes a portable record it
//! holds under that id, with its leases (`Vault::settle_revoked_custody`); a
//! custody transition received for the id is refused in its committing
//! transaction, a value read or a lease refuses, and an archive restore
//! skips it. An id this vault never held stays absent: its knowledge is the
//! fold's, never an empty record. Nothing recalls an export or a use made
//! before the revoke arrived.
//!
//! No custody path refuses on location: the carrier is any live linked
//! install, `surface` is audit only, and the holder is whoever the owner
//! names.

mod doors;
mod execute;
pub(super) mod input;
mod manifest;
mod pending_revoke;
pub(super) mod permits;
mod revoked;
#[cfg(feature = "sync")]
mod roster;

use oneiron_authority::authority::CustodyRegisterCheck;
use zeroize::Zeroizing;

pub use self::doors::{CustodyCandidate, SealedCustodyChange, SecretCustodyView};
pub(crate) use self::execute::Material;
use self::input::{
    InputBinding, RelayedInput, input_digest, keep_witnessed_input_in_txn, request_witness_in_txn,
};
pub use self::manifest::CustodyManifestCheck;
pub(crate) use self::pending_revoke::erase_pending_revoke_actor_in_txn;
pub(crate) use self::revoked::{
    custody_revoked_in_txn, drop_revoked_copies_in_txn, refuse_revoked_use_in_txn,
    settle_revoked_in_txn,
};
use super::codec::{encode_bind_input, encode_register_input};
use crate::authority::{
    ActSurface, AuthorityEntryHash, AuthorityFold, CustodyChange, CustodyRecipientPermit,
    CustodyRequestAuthority, OwnerWorkBody, OwnerWorkOutcome, OwnerWorkRefusal, OwnerWorkRequest,
    invalid_authority,
};
use crate::error::{Error, Result, SecretError};
use crate::secret_rotation::RotationReceipt;
use crate::world_keys::{MachineSecret, OwnerWorkReceipt, OwnerWorkStatus, OwnerWorkUnassigned};
use crate::{EntityId, Vault};

/// Which install a custody request names to do its work (CALLS
/// CUSTODY_EXECUTOR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyExecutor {
    /// An active change goes to the holder it names, a live linked install
    /// with an encryption key that imports: never elected, and no takeover.
    /// A revoke goes to the install that records it, its carrier.
    ExplicitHolderOrRevokeCarrier,
}

const CUSTODY_EXECUTOR: CustodyExecutor = CustodyExecutor::ExplicitHolderOrRevokeCarrier;

/// What a custody request's enacted result claims (CALLS
/// CUSTODY_COMPLETION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyCompletion {
    /// Its executor committed the change here, with the result in the same
    /// commit: for a revoke, the record and its leases revoked here. Never
    /// that every replica holds it: replication is the sync's.
    CommitNotDelivery,
}

const CUSTODY_COMPLETION: CustodyCompletion = CustodyCompletion::CommitNotDelivery;

/// What a receipt says of the owner's other machines holding a change
/// (CALLS CUSTODY_REPLICATION_WITHOUT_ACK).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyReplicationWithoutAck {
    /// No machine acknowledges a transition it took, so delivery is
    /// reported as unknown: never "replicated everywhere".
    Unknown,
}

const CUSTODY_REPLICATION_WITHOUT_ACK: CustodyReplicationWithoutAck =
    CustodyReplicationWithoutAck::Unknown;

/// The install a custody request names as executor (CALLS
/// CUSTODY_EXECUTOR), or why none can be named.
pub(crate) fn custody_work_executor(
    fold: &AuthorityFold,
    change: CustodyChange,
    holder: Option<EntityId>,
    recorder: EntityId,
) -> std::result::Result<EntityId, OwnerWorkUnassigned> {
    match (CUSTODY_EXECUTOR, change) {
        // The one exception to the shared rule that the recorder is never
        // named while another install could do the work: a revoke needs no
        // byte, so the carrier that records it enacts it in the same commit.
        (CustodyExecutor::ExplicitHolderOrRevokeCarrier, CustodyChange::Revoke) => Ok(recorder),
        (
            CustodyExecutor::ExplicitHolderOrRevokeCarrier,
            CustodyChange::Register | CustodyChange::Rotate | CustodyChange::Rewrap,
        ) => holder
            .filter(|holder| permits::holder_key(fold, *holder).is_some())
            .ok_or(OwnerWorkUnassigned::NoCustodyHolder),
    }
}

/// The outcome an executor's result records once its custody change is
/// committed (CALLS CUSTODY_COMPLETION), with what a register's holder
/// checked the record against when its surface stated no `manifest_ref`
/// (FIX 5334).
fn enacted(check: Option<CustodyRegisterCheck>) -> OwnerWorkOutcome {
    match CUSTODY_COMPLETION {
        CustodyCompletion::CommitNotDelivery => OwnerWorkOutcome::Enacted { detail: check },
    }
}

/// Who the owner names for an active custody change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustodyPlan {
    /// The install that holds the value and does the change; `None` is this
    /// install.
    pub holder: Option<EntityId>,
    /// The installs he permits to hold its bytes, each a live linked install
    /// with an importable key, in any role. Empty: a register permits its
    /// holder alone, a rotate keeps the permits of the secret's live change,
    /// and a rewrap is refused. A machine he makes his is added by its
    /// holders' own rewrap (CALLS CUSTODY_ROSTER_REWRAP); any other linked
    /// machine only by his.
    pub recipients: Vec<EntityId>,
}

/// Why a change to a portable secret stays on this install, recorded for no
/// other machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyKeptHere {
    /// The record may not leave its device: device bound, cross-vault or
    /// "this device only".
    DeviceLocal,
    /// This install has no live machine profile to carry the owner's act,
    /// so no other machine learns of the change from here.
    NoCarrier,
    /// A revoke this install cannot carry yet, with no live machine profile
    /// or no install key loaded: it stands here, and its carry is pending
    /// until this install can sign (CALLS CUSTODY_REVOKE_PENDING_CARRY).
    CarryPending,
    /// This install, the holder, has no encryption key that imports, so no
    /// request can name it (CALLS CUSTODY_EXECUTOR).
    NoHolderKey,
}

impl CustodyKeptHere {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceLocal => "device_local",
            Self::NoCarrier => "no_carrier",
            Self::CarryPending => "carry_pending",
            Self::NoHolderKey => "no_holder_key",
        }
    }

    /// The words a surface shows.
    #[must_use]
    pub fn text(self) -> &'static str {
        match self {
            Self::DeviceLocal => "kept on this device: this secret never leaves it",
            Self::NoCarrier => {
                "kept on this install only: it has no live machine profile to carry your act \
                 to your other machines"
            }
            Self::NoHolderKey => {
                "kept on this install only: it has no encryption key to hold the secret for \
                 your other machines"
            }
            Self::CarryPending => {
                "revoked here; your other machines learn of it once this install can sign your \
                 act (it has no live machine profile yet, or its install key is not loaded)"
            }
        }
    }
}

/// Whether the owner's other machines hold a change yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyDelivery {
    /// A request was recorded or enacted: whether each permitted recipient
    /// holds it is not known here (CALLS CUSTODY_REPLICATION_WITHOUT_ACK).
    Unknown,
    /// Nothing was sent: the change stays on this install.
    NotSent,
}

impl CustodyDelivery {
    /// The wire tag.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::NotSent => "not_sent",
        }
    }
}

/// What the owner's change to a secret's custody did beyond this install:
/// the shared receipt of the custody request recorded for his machines, or
/// why it stays here, and what is known of its delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCustodyWork {
    /// The custody request: awaiting its holder, enacted (committed by the
    /// holder, never delivered everywhere) or refused, or naming no holder
    /// when nothing was recorded. `None` when the change stays here.
    pub work: Option<OwnerWorkReceipt>,
    /// Why the change stays on this install; `None` once recorded.
    pub kept_here: Option<CustodyKeptHere>,
    pub delivery: CustodyDelivery,
    /// For a register the owner's surface sealed without stating a
    /// `manifest_ref`, what its holder checked the record against when this
    /// install is the holder, else what this install attached for it: every
    /// manifest the vault publishes (CALLS CUSTODY_MANIFEST_UNSTATED_MULTI).
    /// A remote holder's own judgment reaches `work.manifest_check` with its
    /// signed result. `None` for any other change.
    pub manifest: Option<CustodyManifestCheck>,
}

impl SecretCustodyWork {
    pub(crate) fn kept(why: CustodyKeptHere) -> Self {
        Self {
            work: None,
            kept_here: Some(why),
            delivery: CustodyDelivery::NotSent,
            manifest: None,
        }
    }

    pub(crate) fn recorded(receipt: OwnerWorkReceipt) -> Self {
        let delivery = if receipt.request.is_some() {
            match CUSTODY_REPLICATION_WITHOUT_ACK {
                CustodyReplicationWithoutAck::Unknown => CustodyDelivery::Unknown,
            }
        } else {
            CustodyDelivery::NotSent
        };
        Self {
            work: Some(receipt),
            kept_here: None,
            delivery,
            manifest: None,
        }
    }

    /// The words a surface shows: the request's state, why no holder was
    /// named, or why the change stays here.
    #[must_use]
    pub fn text(&self) -> &'static str {
        match (&self.work, self.kept_here) {
            (Some(receipt), _) => receipt
                .unassigned
                .map_or_else(|| self.status_text(receipt), OwnerWorkUnassigned::text),
            (None, Some(why)) => why.text(),
            (None, None) => "not recorded",
        }
    }

    /// A recorded request's words: a register taken, or to be taken,
    /// without a manifest check says so, by this install's word or its
    /// holder's signed result (CALLS CUSTODY_MANIFEST_UNSTATED).
    fn status_text(&self, receipt: &OwnerWorkReceipt) -> &'static str {
        let unchecked = self
            .manifest
            .as_ref()
            .is_some_and(CustodyManifestCheck::unchecked)
            || receipt
                .manifest_check
                .as_ref()
                .is_some_and(CustodyRegisterCheck::unchecked);
        match (receipt.status, unchecked) {
            (OwnerWorkStatus::RecordedAwaitingHolder, true) => {
                "recorded, awaiting a holder; to be registered without a manifest check"
            }
            (OwnerWorkStatus::Enacted, true) => {
                "enacted by its holder; registered without a manifest check"
            }
            (status, _) => status.text(),
        }
    }
}

/// What the owner's revoke of a secret did: the rotation receipt of the
/// revoke here, and the shared receipt of the revoke recorded for his other
/// machines, or exactly why it stays here (FIX 4994).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRevoked {
    /// The record and every lease over it, revoked here.
    pub rotation: RotationReceipt,
    /// The custody revoke this install carried and enacted in the same
    /// commit: "enacted" says it committed here, never that every replica
    /// holds it yet (CALLS CUSTODY_COMPLETION). Kept here, with nothing
    /// recorded, as [`CustodyKeptHere::DeviceLocal`] for a record that stays
    /// on its device (device bound, cross-vault or "this device only"), or
    /// [`CustodyKeptHere::CarryPending`] when this install cannot carry the
    /// owner's act yet, with no live machine profile or no install key
    /// loaded: his other machines learn of it once this install can sign
    /// (CALLS CUSTODY_REVOKE_PENDING_CARRY).
    pub custody: SecretCustodyWork,
}

/// What the owner's rotation of a secret did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRotated {
    /// The rotation receipt, when this install rotated the record in this
    /// commit; `None` while another holder has the rotation to do.
    pub rotation: Option<RotationReceipt>,
    pub custody: SecretCustodyWork,
}

/// One active change a door records for a portable secret.
pub(crate) struct ActiveChange<'a> {
    pub(crate) change: CustodyChange,
    pub(crate) id: EntityId,
    /// The generation the change approves.
    pub(crate) generation: u32,
    pub(crate) plan: &'a CustodyPlan,
    /// What this install, when it is the holder, executes from.
    pub(crate) material: Material<'a>,
    /// The protected input the owner's surface sealed itself; `None` has the
    /// door seal `material` to the holder.
    pub(crate) sealed: Option<&'a [u8]>,
    /// The custody revision that surface showed, which its input binds.
    pub(crate) seen: Option<[u8; 32]>,
    /// The exact permits that surface bound; `None` takes the plan's.
    pub(crate) permits: Option<&'a [CustodyRecipientPermit]>,
}

/// What a door recorded.
pub(crate) struct Recorded {
    pub(crate) custody: SecretCustodyWork,
    /// The rotation receipt a rotate this install held wrote.
    pub(crate) rotation: Option<RotationReceipt>,
}

impl Recorded {
    fn kept(why: CustodyKeptHere) -> Self {
        Self {
            custody: SecretCustodyWork::kept(why),
            rotation: None,
        }
    }
}

fn refused(reason: impl Into<String>) -> Error {
    Error::InvalidConfig(format!("{}; nothing was written", reason.into()))
}

fn recipient_refused(machine: EntityId) -> Error {
    refused(format!(
        "recipient {} is not a linked install with an importable encryption key",
        machine.to_hex()
    ))
}

impl Vault {
    /// Mirrors a committed custody change into the live windows: its
    /// transition, or the input relayed to its holder.
    pub(crate) fn mirror_custody_change(&self, custody: &SecretCustodyWork) {
        #[cfg(feature = "sync")]
        if custody.work.is_some() {
            self.refresh_custody_in_live_windows();
        }
        #[cfg(not(feature = "sync"))]
        let _ = custody;
    }

    /// Records the owner's active custody change in the door's write
    /// transaction, carried by this install for `actor`, a live vault owner
    /// the caller checked in it: a custody request whose
    /// executor is the holder the plan names, this install by default, with
    /// the permits he gave and the digest of its protected input. When this
    /// install is the holder it executes the change in the same commit, and
    /// a refusal there refuses the transaction, so nothing is recorded that
    /// did not happen. Any other holder gets the input relayed. With no live
    /// machine profile here, or no importable key on this install as holder,
    /// nothing is recorded and the result says the change stays here; the
    /// door then keeps it locally.
    pub(crate) fn record_custody_change_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        actor: EntityId,
        surface: ActSurface,
        change: ActiveChange<'_>,
        at: u64,
    ) -> Result<Recorded> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        // The carrier's install key signs the request, and so a witness's
        // numbered parts (FIX 8088): no other key is looked up.
        let Some((machine, signing)) = self.owner_work_carrier_in_txn(txn, &fold)? else {
            return Ok(Recorded::kept(CustodyKeptHere::NoCarrier));
        };
        let holder = change.plan.holder.unwrap_or(machine);
        let Some(holder_key) = permits::holder_key(&fold, holder) else {
            if holder == machine {
                return Ok(Recorded::kept(CustodyKeptHere::NoHolderKey));
            }
            return Err(refused(
                "the holder named is not a linked install with an importable encryption key",
            ));
        };
        let permits = change_permits(&fold, &change, holder)?;
        // Every permitted install is kept, however many (FIX 7906): measured,
        // never refused; its transition carries them in pieces. The request
        // rides whole, so it also asks well before one sync frame (FIX 8087;
        // L04 09:40 (b)).
        crate::authority::measure_custody_permits(&self.store.limit_watch, &permits);
        let seen = fold.custody_work_revision(change.id);
        if change.seen.is_some_and(|stated| stated != seen) {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "the secret's custody changed since the surface read it; read it again",
            )));
        }
        let vault_id = fold.vault_id.ok_or_else(invalid_authority)?;
        let binding = InputBinding {
            vault_id,
            id: change.id,
            change: change.change,
            generation: change.generation,
            seen,
            holder,
            permits: &permits,
        };
        // A rewrap carries an input only for a bind (CALLS
        // CUSTODY_BIND_TRAVEL); a revoke never does.
        let envelope = match (change.change, &change.material, change.sealed) {
            (CustodyChange::Revoke, ..)
            | (CustodyChange::Rewrap, Material::Held | Material::Input(_), _) => None,
            (_, _, Some(sealed)) => Some(sealed.to_vec()),
            (_, material, None) => Some(binding.seal(&holder_key, &plaintext(material)?)?),
        };
        let input = envelope.as_deref().map(input_digest);
        // CALLS CUSTODY_RETRY: the same protected input again is the request
        // that already names it, never a second change.
        if let Some(input) = input
            && let Some((hash, _)) = fold.custody_heads(change.id).into_iter().find(|(_, live)| {
                matches!(&live.work, OwnerWorkBody::Custody { input: named, .. } if *named == Some(input))
            })
        {
            let receipt = OwnerWorkReceipt::of(&fold, hash).ok_or_else(invalid_authority)?;
            return Ok(Recorded {
                custody: SecretCustodyWork::recorded(receipt),
                rotation: None,
            });
        }
        let work = OwnerWorkBody::Custody {
            change: change.change,
            generation: change.generation,
            input,
            holder: Some(holder),
            recipients: permits,
            authority: CustodyRequestAuthority::Install,
        };
        let receipt =
            self.record_owner_work_for_in_txn(txn, actor, surface, change.id, seen, work)?;
        let Some(hash) = receipt.request_entry() else {
            return Ok(Recorded {
                custody: SecretCustodyWork::recorded(receipt),
                rotation: None,
            });
        };
        let mut rotation = None;
        let mut manifest = None;
        if let (Some(envelope), true) = (envelope, holder != machine || change.sealed.is_some()) {
            keep_witnessed_input_in_txn(
                self,
                txn,
                RelayedInput {
                    sealed_at: at,
                    request: hash,
                    witness: request_witness_in_txn(self, txn, &hash)?,
                    part: None,
                    envelope,
                },
                &signing,
            )?;
        }
        if holder == machine {
            let request = self
                .authority_view_readonly_in_txn(txn)?
                .owner_work_request(&hash)
                .cloned()
                .ok_or_else(invalid_authority)?;
            if let Some(done) =
                self.enact_custody_change_in_txn(txn, hash, &request, change.material, at)?
            {
                if let OwnerWorkOutcome::Refused { reason } = done.outcome {
                    return Err(refused(format!(
                        "this install, the holder, refused the change: {}",
                        reason.as_str()
                    )));
                }
                manifest = done
                    .manifest_check()
                    .cloned()
                    .map(CustodyManifestCheck::Judged);
                rotation = done.rotation;
                self.append_owner_work_result_in_txn(txn, hash, machine, done.outcome)?;
            }
        }
        let after = self.authority_view_readonly_in_txn(txn)?;
        Ok(Recorded {
            custody: SecretCustodyWork {
                manifest,
                ..SecretCustodyWork::recorded(receipt.refreshed(&after))
            },
            rotation,
        })
    }

    /// The pickup's arm for a custody request naming this install, signed as
    /// entry `hash`. A revoke is settled here, byte-free, and answered
    /// enacted: it is terminal from its admission (CALLS
    /// CUSTODY_CONCURRENT_ACTIVE), so its executor never refuses it. An
    /// active change whose secret an admitted revoke names is refused as
    /// stale; any other is executed from its protected input, opened with
    /// `secret`, or for a rewrap that carries none from the record held here
    /// ([`execute`]); an enacted register carries what this holder checked
    /// it against, signed in its result (FIX 5334). `None` leaves it pending:
    /// no secret, input or record, or part of a split input, here yet.
    pub(crate) fn custody_work_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        hash: AuthorityEntryHash,
        request: &OwnerWorkRequest,
        secret: Option<&MachineSecret>,
    ) -> Result<Option<OwnerWorkOutcome>> {
        let OwnerWorkBody::Custody { change, input, .. } = &request.work else {
            return Ok(None);
        };
        let id = request.act.target;
        let at = self.instant_in_txn(txn)?.secs();
        if *change == CustodyChange::Revoke {
            settle_revoked_in_txn(self, txn, &id, at)?;
            return Ok(Some(enacted(None)));
        }
        if fold.custody_revoked(&id) {
            return Ok(Some(OwnerWorkOutcome::Refused {
                reason: OwnerWorkRefusal::StaleRevision,
            }));
        }
        let material = match (change, input, secret) {
            (CustodyChange::Rewrap, None, _) => Material::Held,
            (_, _, Some(secret)) => Material::Input(secret),
            (_, _, None) => return Ok(None),
        };
        Ok(self
            .enact_custody_change_in_txn(txn, hash, request, material, at)?
            .map(|done| done.outcome))
    }
}

/// The permits a change records: the exact ones a sealing surface bound,
/// each still standing; the machines the plan names; or, when it names
/// none, the holder alone for a register and the permits of the secret's
/// one live active change for a rotate or a bind. Any other rewrap names
/// its own.
fn change_permits(
    fold: &AuthorityFold,
    change: &ActiveChange<'_>,
    holder: EntityId,
) -> Result<Vec<CustodyRecipientPermit>> {
    let permits = if let Some(bound) = change.permits {
        if permits::permitted_keys(fold, bound).is_none() {
            return Err(refused(
                "a recipient's permit no longer stands: its install was removed or its key changed",
            ));
        }
        bound.to_vec()
    } else if !change.plan.recipients.is_empty() {
        permits::permits_for(fold, &change.plan.recipients).map_err(recipient_refused)?
    } else {
        match (change.change, &change.material) {
            (CustodyChange::Rotate, _) | (CustodyChange::Rewrap, Material::Bindings(_)) => {
                let mut live: Vec<_> =
                    fold.custody_heads(change.id)
                        .into_iter()
                        .filter_map(|(_, request)| match &request.work {
                            OwnerWorkBody::Custody {
                                change:
                                    CustodyChange::Register
                                    | CustodyChange::Rotate
                                    | CustodyChange::Rewrap,
                                recipients,
                                ..
                            } => Some(recipients.clone()),
                            _ => None,
                        })
                        .collect();
                if live.len() == 1
                    && let Some(kept) = live.pop()
                {
                    kept
                } else {
                    vec![
                        permits::permit_for(fold, holder)
                            .ok_or_else(|| recipient_refused(holder))?,
                    ]
                }
            }
            (CustodyChange::Register, _) => {
                vec![permits::permit_for(fold, holder).ok_or_else(|| recipient_refused(holder))?]
            }
            (CustodyChange::Rewrap | CustodyChange::Revoke, _) => {
                return Err(refused("a rewrap names the installs it permits"));
            }
        }
    };
    let ascending = permits
        .windows(2)
        .all(|pair| pair[0].machine < pair[1].machine);
    if permits.is_empty() || !ascending {
        return Err(refused(
            "a custody change permits one or more installs, ascending by machine, one each",
        ));
    }
    Ok(permits)
}

/// The body a door seals to the holder: a register's whole record, value in
/// it, framed with its manifest's text when it has one; a rotate's new
/// value; a bind's bindings.
fn plaintext(material: &Material<'_>) -> Result<Zeroizing<Vec<u8>>> {
    match material {
        Material::Record(record, manifest) => encode_register_input(record, *manifest),
        Material::Value(value) => Ok(Zeroizing::new(value.to_vec())),
        Material::Bindings(bindings) => encode_bind_input(bindings).map(Zeroizing::new),
        Material::Input(_) | Material::Held => Err(invalid_authority()),
    }
}
