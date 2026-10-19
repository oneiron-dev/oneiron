//! The holder's arm for an active custody change (WILL L04 row 04): the
//! install a register, rotate or rewrap request names as executor does it,
//! in one writer transaction.
//!
//! It works from the protected input it opens with its own secret, or, as
//! the recorder that is its own holder, from what the owner handed it in
//! the request's own commit; a rewrap seals the value it holds, and a bind's
//! rewrap changes its bindings alone first (CALLS CUSTODY_BIND_TRAVEL). A
//! register opened from its input is checked against the manifest snapshot
//! it carries (CALLS CUSTODY_MANIFEST_RECHECK). Before any
//! write it rechecks, in its transaction: the request still counts and names
//! it, the act's owner is still a live vault owner, the secret's id is not
//! terminal, every permitted recipient still stands with the key he
//! permitted, and the record's id, generation, status, portability, name and
//! live floor take the change. The effect, the request-bound custody
//! transition, the rotation receipt and the output binding commit together,
//! and the pickup's enacted result joins them in the same commit. A missing
//! input, secret or record leaves the request pending; nothing is elected and
//! nobody takes over.

use zeroize::{Zeroize, Zeroizing};

use super::super::codec::{decode_bind_input, decode_register_input};
use super::super::doors::{
    put_secret_custody_in_txn, read_secret_custody_admission_in_txn, read_secret_custody_in_txn,
    refuse_bindings_wider_than_live_floor, register_secret_in_txn, resolve_secret_ref_in_txn,
};
use super::super::owner_door::recheck_manifest_snapshot_in_txn;
use super::super::transition::{Enactment, custody_portable, write_custody_transition_in_txn};
use super::super::types::{SecretBinding, SecretCustodyRecord, SecretCustodyStatus};
use super::input::{Attached, InputBinding, drop_input_in_txn, held_input_in_txn, split_attached};
use super::manifest::register_snapshot;
use super::permits::permitted_keys;
use crate::authority::{
    AuthorityEntryHash, AuthorityFold, CustodyChange, OwnerWorkBody, OwnerWorkOutcome,
    OwnerWorkRefusal, OwnerWorkRequest,
};
use crate::error::{Error, Result, SecretError};
use crate::secret_rotation::RotationReceipt;
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::world_keys::MachineSecret;
use crate::{EntityId, Vault};

/// What each custody request's executor committed, by the request's entry
/// hash: the digest of the transition it signed, then the rotation receipt
/// it wrote (zero for none). Written once, in the work's own commit.
const OUTPUTS: SideTable<[u8; 32], Vec<u8>, Raw> =
    SideTable::new(&side_table::SECRET_CUSTODY_OUTPUT);

/// How a custody request meets a retry (CALLS CUSTODY_RETRY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyRetry {
    /// One request is done once, at the generation it approves. Its result,
    /// or its committed output, is its answer before any mutation: a pickup
    /// that finds the output reconciles to enacted and writes nothing, so a
    /// rotation never runs twice. A surface that sends the same protected
    /// input again gets the request that names it; a fresh upload is a fresh
    /// request.
    SameRequestSameGeneration,
}

const CUSTODY_RETRY: CustodyRetry = CustodyRetry::SameRequestSameGeneration;

/// What an active change is executed from.
pub(crate) enum Material<'a> {
    /// A register's record, its value in it, with the text of the manifest
    /// its door resolved it from when there is one, as the owner handed them
    /// to the recorder that is its own holder, in the request's own commit.
    Record(&'a SecretCustodyRecord, Option<&'a str>),
    /// A rotate's new value, handed to the recorder that is its holder.
    Value(&'a [u8]),
    /// A bind's bindings, every one the record is to hold, handed to the
    /// recorder that is its holder (CALLS CUSTODY_BIND_TRAVEL).
    Bindings(&'a [SecretBinding]),
    /// The protected input the request names, opened here with this
    /// install's secret: the holder's pickup.
    Input(&'a MachineSecret),
    /// Nothing: a rewrap seals the value the holder holds.
    Held,
}

/// What the executor did with one request.
#[derive(Debug)]
pub(crate) struct Enacted {
    pub(crate) outcome: OwnerWorkOutcome,
    /// The rotation receipt a rotate wrote here, in this commit.
    pub(crate) rotation: Option<RotationReceipt>,
}

impl Enacted {
    fn done(rotation: Option<RotationReceipt>) -> Self {
        Self {
            outcome: super::enacted(),
            rotation,
        }
    }

    fn refused(reason: OwnerWorkRefusal) -> Self {
        Self {
            outcome: OwnerWorkOutcome::Refused { reason },
            rotation: None,
        }
    }
}

/// The rewrap a holder does: of which record, at which generation, and for
/// a bind the bindings it is to hold.
struct Rewrap {
    id: EntityId,
    generation: u32,
    bindings: Option<Vec<SecretBinding>>,
}

/// An input as the holder finds it.
enum Opened {
    /// Not here yet: the request stays pending.
    Missing,
    /// It does not open under the request's binding.
    Invalid,
    /// Its body, and what its recorder attached beside a sealed register's
    /// envelope, if anything.
    Body(Zeroizing<Vec<u8>>, Option<Attached>),
}

/// A record whose value is wiped when it drops, on every path.
struct Held(SecretCustodyRecord);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.value_bytes.zeroize();
    }
}

/// Whether request `request`'s executor committed its output here.
fn output_held_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    request: &AuthorityEntryHash,
) -> Result<bool> {
    Ok(OUTPUTS.get(store, txn, request)?.is_some())
}

/// Keeps what request `request`'s executor committed: its transition's
/// digest, and the rotation receipt's id when it wrote one.
fn put_output_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    request: &AuthorityEntryHash,
    transition: [u8; 32],
    receipt: Option<EntityId>,
) -> Result<()> {
    let mut row = Vec::with_capacity(48);
    row.extend_from_slice(&transition);
    row.extend_from_slice(&receipt.map_or([0; 16], |id| *id.as_bytes()));
    OUTPUTS.put(&vault.store, txn, request, &row)
}

impl Vault {
    /// Executes the active custody change `request`, signed as entry `hash`
    /// and naming this install as executor, in `txn`, from `material`, at
    /// `at`: the effect, its request-bound transition and its output
    /// binding, never its result, which the caller appends in the same
    /// commit. `None` leaves it pending: its input or the record it changes
    /// is not here yet. A revoke is not one: its carrier enacts it byte-free.
    pub(crate) fn enact_custody_change_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        hash: AuthorityEntryHash,
        request: &OwnerWorkRequest,
        material: Material<'_>,
        at: u64,
    ) -> Result<Option<Enacted>> {
        let OwnerWorkBody::Custody {
            change,
            generation,
            input,
            recipients,
            ..
        } = &request.work
        else {
            return Ok(None);
        };
        let id = request.act.target;
        match CUSTODY_RETRY {
            CustodyRetry::SameRequestSameGeneration => {
                if output_held_in_txn(&self.store, txn, &hash)? {
                    return Ok(Some(Enacted::done(None)));
                }
            }
        }
        let fold = self.authority_view_readonly_in_txn(txn)?;
        if fold.custody_revoked(&id) {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::StaleRevision)));
        }
        if !crate::policy_model::is_live_vault_owner_in_txn(self, txn, &request.act.owner)? {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::OwnerNotLive)));
        }
        let Some(keyed) = permitted_keys(&fold, recipients) else {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::RecipientChanged)));
        };
        let Some(vault_id) = fold.vault_id else {
            return Ok(None);
        };
        let binding = InputBinding {
            vault_id,
            id,
            change: *change,
            generation: *generation,
            seen: request.act.seen,
            holder: request.executor,
            permits: recipients,
        };
        let enactment = Enactment {
            request: hash,
            input: *input,
            permits: &keyed,
        };
        match change {
            CustodyChange::Register => {
                let record = match material {
                    Material::Record(record, _) => Held(record.clone()),
                    Material::Input(secret) => match self
                        .opened_input_in_txn(txn, &binding, *input, secret)?
                    {
                        Opened::Missing => return Ok(None),
                        Opened::Invalid => {
                            return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
                        }
                        Opened::Body(body, attached) => {
                            let Some((record, framed)) = decode_register_input(&body) else {
                                return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
                            };
                            let record = Held(record);
                            // The manifest the recorder sealed beside the
                            // record, the one it resolved for the
                            // manifest_ref a surface stated, which must be
                            // the record's, or the vault's current approved
                            // one for a surface that stated none.
                            let snapshot = match register_snapshot(framed, attached, &record.0) {
                                Ok(snapshot) => snapshot,
                                Err(refusal) => return Ok(Some(Enacted::refused(refusal))),
                            };
                            if let Some(refusal) = recheck_manifest_snapshot_in_txn(
                                &self.store,
                                txn,
                                &record.0,
                                snapshot.as_deref(),
                            )? {
                                return Ok(Some(Enacted::refused(refusal)));
                            }
                            record
                        }
                    },
                    Material::Value(_) | Material::Bindings(_) | Material::Held => {
                        return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
                    }
                };
                self.register_from_in_txn(txn, id, *generation, record, enactment, at)
            }
            CustodyChange::Rotate => {
                let value = match material {
                    Material::Value(value) => Zeroizing::new(value.to_vec()),
                    Material::Input(secret) => {
                        match self.opened_input_in_txn(txn, &binding, *input, secret)? {
                            Opened::Missing => return Ok(None),
                            Opened::Invalid | Opened::Body(_, Some(_)) => {
                                return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
                            }
                            Opened::Body(body, None) => body,
                        }
                    }
                    Material::Record(..) | Material::Bindings(_) | Material::Held => {
                        return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
                    }
                };
                self.rotate_from_in_txn(txn, id, *generation, &value, enactment, at)
            }
            CustodyChange::Rewrap => {
                // A rewrap that carries no input seals again what is held;
                // one that does is a bind (CALLS CUSTODY_BIND_TRAVEL).
                let bindings = match (input, material) {
                    (None, _) => None,
                    (Some(_), Material::Bindings(bindings)) => Some(bindings.to_vec()),
                    (Some(_), Material::Input(secret)) => {
                        let opened =
                            match self.opened_input_in_txn(txn, &binding, *input, secret)? {
                                Opened::Missing => return Ok(None),
                                Opened::Invalid | Opened::Body(_, Some(_)) => None,
                                Opened::Body(body, None) => decode_bind_input(&body),
                            };
                        let Some(bindings) = opened else {
                            return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
                        };
                        Some(bindings)
                    }
                    (Some(_), _) => {
                        return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
                    }
                };
                let rewrap = Rewrap {
                    id,
                    generation: *generation,
                    bindings,
                };
                self.rewrap_held_in_txn(txn, &fold, rewrap, enactment, at)
            }
            CustodyChange::Revoke => Ok(None),
        }
    }

    /// The input `digest` names, kept here, opened under `binding`.
    fn opened_input_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        binding: &InputBinding<'_>,
        digest: Option<[u8; 32]>,
        secret: &MachineSecret,
    ) -> Result<Opened> {
        let Some(digest) = digest else {
            return Ok(Opened::Invalid);
        };
        let Some(kept) = held_input_in_txn(&self.store, txn, &digest)? else {
            return Ok(Opened::Missing);
        };
        let Some((envelope, attached)) = split_attached(&kept.envelope) else {
            return Ok(Opened::Invalid);
        };
        Ok(binding
            .open(envelope, secret)
            .map_or(Opened::Invalid, |body| Opened::Body(body, attached)))
    }

    /// A register: a new portable record under the request's id, at the
    /// generation it approves, its name free here or reclaimed from a record
    /// revoked one generation below.
    fn register_from_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        generation: u32,
        mut record: Held,
        enactment: Enactment<'_>,
        at: u64,
    ) -> Result<Option<Enacted>> {
        if !custody_portable(&record.0) {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::SecretNotPortable)));
        }
        if record.0.status != SecretCustodyStatus::Active
            || record.0.rotation_generation != generation
            || record.0.value_bytes.is_empty()
        {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
        }
        if read_secret_custody_admission_in_txn(&self.store, txn, &id)?.is_some() {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::CustodyConflict)));
        }
        if let Some(named) = resolve_secret_ref_in_txn(&self.store, txn, &record.0.name)?
            && let Some(held) = read_secret_custody_admission_in_txn(&self.store, txn, &named)?
            && (held.status != SecretCustodyStatus::Revoked
                || held.rotation_generation.checked_add(1) != Some(generation))
        {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::CustodyConflict)));
        }
        match register_secret_in_txn(self, txn, &id, &mut record.0) {
            Ok(()) => {}
            Err(Error::Secret(SecretError::ManifestWidensFloor { .. })) => {
                return Ok(Some(Enacted::refused(OwnerWorkRefusal::WiderThanFloor)));
            }
            Err(Error::Secret(SecretError::InvalidSecretCustodyBody(_))) => {
                return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
            }
            Err(error) => return Err(error),
        }
        let transition = write_custody_transition_in_txn(self, txn, id, &record.0, enactment, at)?;
        self.close_out_in_txn(txn, enactment, transition.digest(), None)?;
        Ok(Some(Enacted::done(None)))
    }

    /// A rotate: the record this install holds at the generation below the
    /// one approved takes the new value, with its rotation receipt.
    fn rotate_from_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: EntityId,
        generation: u32,
        value: &[u8],
        enactment: Enactment<'_>,
        at: u64,
    ) -> Result<Option<Enacted>> {
        if value.is_empty() {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::InvalidInput)));
        }
        let Some(record) = read_secret_custody_in_txn(&self.store, txn, &id)? else {
            return Ok(None);
        };
        let record = Held(record);
        if let Some(refusal) = self.held_refusal_in_txn(txn, id, &record.0)? {
            return Ok(Some(Enacted::refused(refusal)));
        }
        if record.0.status != SecretCustodyStatus::Active {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::SecretNotActive)));
        }
        if record.0.rotation_generation >= generation {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::StaleRevision)));
        }
        if record.0.rotation_generation.saturating_add(1) < generation {
            return Ok(None);
        }
        let rotation = self.rotate_secret_in_txn(txn, &record.0.name, value, at)?;
        let after = Held(read_secret_custody_in_txn(&self.store, txn, &id)?.ok_or(
            Error::CorruptedIndex("secret custody record after its rotation"),
        )?);
        let transition = write_custody_transition_in_txn(self, txn, id, &after.0, enactment, at)?;
        self.close_out_in_txn(
            txn,
            enactment,
            transition.digest(),
            Some(rotation.receipt_id),
        )?;
        Ok(Some(Enacted::done(Some(rotation))))
    }

    /// A rewrap: the record this install holds, at the generation approved
    /// and not revoked, sealed again to the permitted recipients, its
    /// generation and status kept. A bind's rewrap first puts the record
    /// with its bindings alone changed, while it is active, its request is
    /// still one of the secret's live custody requests (a later request
    /// supersedes it) and the live floor admits them, in the same commit as
    /// the transition that carries them (CALLS CUSTODY_BIND_TRAVEL).
    fn rewrap_held_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        fold: &AuthorityFold,
        rewrap: Rewrap,
        enactment: Enactment<'_>,
        at: u64,
    ) -> Result<Option<Enacted>> {
        let Rewrap {
            id,
            generation,
            bindings,
        } = rewrap;
        let Some(record) = read_secret_custody_in_txn(&self.store, txn, &id)? else {
            return Ok(None);
        };
        let mut record = Held(record);
        if let Some(refusal) = self.held_refusal_in_txn(txn, id, &record.0)? {
            return Ok(Some(Enacted::refused(refusal)));
        }
        if record.0.status == SecretCustodyStatus::Revoked {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::SecretNotActive)));
        }
        if record.0.rotation_generation > generation {
            return Ok(Some(Enacted::refused(OwnerWorkRefusal::StaleRevision)));
        }
        if record.0.rotation_generation < generation {
            return Ok(None);
        }
        if let Some(bindings) = bindings {
            if record.0.status != SecretCustodyStatus::Active {
                return Ok(Some(Enacted::refused(OwnerWorkRefusal::SecretNotActive)));
            }
            if !fold
                .custody_heads(id)
                .iter()
                .any(|(hash, _)| *hash == enactment.request)
            {
                return Ok(Some(Enacted::refused(OwnerWorkRefusal::StaleRevision)));
            }
            record.0.bindings = bindings;
            if refuse_bindings_wider_than_live_floor(&self.store, txn, &record.0).is_err() {
                return Ok(Some(Enacted::refused(OwnerWorkRefusal::WiderThanFloor)));
            }
            put_secret_custody_in_txn(self, txn, &id, &record.0, at)?;
        }
        let transition = write_custody_transition_in_txn(self, txn, id, &record.0, enactment, at)?;
        self.close_out_in_txn(txn, enactment, transition.digest(), None)?;
        Ok(Some(Enacted::done(None)))
    }

    /// Why a record this install holds cannot take a change: it may not
    /// leave its device, another record holds its name, or the live floor no
    /// longer admits its bindings.
    fn held_refusal_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: EntityId,
        record: &SecretCustodyRecord,
    ) -> Result<Option<OwnerWorkRefusal>> {
        Ok(if !custody_portable(record) {
            Some(OwnerWorkRefusal::SecretNotPortable)
        } else if resolve_secret_ref_in_txn(&self.store, txn, &record.name)? != Some(id) {
            Some(OwnerWorkRefusal::CustodyConflict)
        } else if refuse_bindings_wider_than_live_floor(&self.store, txn, record).is_err() {
            Some(OwnerWorkRefusal::WiderThanFloor)
        } else {
            None
        })
    }

    /// The output binding of the request `enactment` names, and the input
    /// it consumed forgotten here.
    fn close_out_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        enactment: Enactment<'_>,
        transition: [u8; 32],
        receipt: Option<EntityId>,
    ) -> Result<()> {
        put_output_in_txn(self, txn, &enactment.request, transition, receipt)?;
        if let Some(digest) = enactment.input {
            drop_input_in_txn(self, txn, &digest)?;
        }
        Ok(())
    }
}
