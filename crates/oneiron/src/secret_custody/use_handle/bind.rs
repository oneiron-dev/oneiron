//! The owner binds a secret to an effector (OF-560): the door a handle with
//! no binding names, so the secret it holds can be used without being read.
//!
//! A binding names the effector that may use the secret, the most exposed
//! rung it may use it at, and what it grants. The owner proof is rechecked in
//! the transaction that stores the binding, and the binding may sit no higher
//! than the class's live floor. A portable record's binding travels (WILL L04
//! row 04, CALLS CUSTODY_BIND_TRAVEL): the door records a custody rewrap
//! whose protected input carries the record's new bindings, sealed to its
//! holder, this install, which changes them and signs the transition that
//! carries them to the machines the owner permits, in the same commit. A
//! record that stays on its device, or an install that carries no owner act
//! or holds no importable key, binds here alone, and the custody receipt
//! says why. A record an admitted revoke ended takes no binding. The Gate
//! record keeps the handle, the effector, the rung and the scopes, never the
//! value.

use super::super::codec::EFFECTOR_MAX_BYTES;
use super::super::control::{
    ActiveChange, CustodyKeptHere, CustodyPlan, Material, SecretCustodyWork,
    refuse_revoked_use_in_txn,
};
use super::super::doors::{refuse_bindings_wider_than_live_floor, resolve_secret_ref_in_txn};
use super::super::reveal::RevealTarget;
use super::super::storage_seal::{put_stored_custody_in_txn, read_stored_custody_in_txn};
use super::super::transition::custody_portable;
use super::super::types::{CustodyTier, SECRET_SCOPE_READ, SecretBinding, SecretCustodyStatus};
use super::{handle_record_in_txn, not_active, unknown};
use crate::authority::{ActSurface, CustodyChange};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord, Store};
use crate::vault::Vault;

/// The Gate reason code of an owner's binding.
pub const SECRET_BIND_REASON: &str = "gate.secret.owner_bind";

/// The Gate content kind of an owner's binding.
const SECRET_BIND_CONTENT_KIND: &str = "secret_bind";

/// How the owner's binding reaches the machines that hold its record (CALLS
/// CUSTODY_BIND_TRAVEL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyBindTravel {
    /// A portable record's bind is a custody rewrap whose protected input
    /// carries every binding the record is to hold, sealed to its holder
    /// (this install) and bound to its generation, the custody revision it
    /// saw, the holder and the permits of the secret's live change, as a
    /// register's input is. The holder changes the bindings alone, rechecks
    /// the live floor and commits the record, the transition and the enacted
    /// result together. A machine that already holds the record at that
    /// generation takes the bindings by the request they enact, never by the
    /// carrier's arrival or time, so a replay never applies again; its
    /// value, generation and a terminal revoke stay. A rewrap with no input
    /// only seals again, as before. A record that stays on its device binds
    /// here alone.
    InputBearingRewrap,
}

const CUSTODY_BIND_TRAVEL: CustodyBindTravel = CustodyBindTravel::InputBearingRewrap;

/// One binding the owner adds to a secret, or puts in place of the one it
/// holds for the same effector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBindRequest {
    /// The secret, by its handle or its custody name.
    pub target: RevealTarget,
    /// The effector that may use it, such as `connector:slack`.
    pub effector: String,
    /// The most exposed rung it may be used at.
    pub tier_ceiling: CustodyTier,
    /// What the binding grants; `read` lets the door hand the value over.
    pub scopes: Vec<String>,
}

impl SecretBindRequest {
    /// The scopes a binding grants when the owner names none: the one a
    /// door needs to present the value.
    #[must_use]
    pub fn default_scopes() -> Vec<String> {
        vec![SECRET_SCOPE_READ.to_owned()]
    }
}

/// What the binding left: the record's bindings and the receipts. No value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBound {
    pub secret_id: EntityId,
    /// The record's handle, such as `sc12`, or its name when it has none.
    pub handle: String,
    pub name: String,
    /// Every binding the record now holds.
    pub bindings: Vec<SecretBinding>,
    /// The Gate record that keeps the binding.
    pub receipt: GateDecisionId,
    /// The custody rewrap recorded for the owner's other machines, as a
    /// register's or a rotation's is, or why the binding stays here (CALLS
    /// CUSTODY_BIND_TRAVEL).
    pub custody: SecretCustodyWork,
}

impl Vault {
    /// Binds a secret to an effector on the vault owner's behalf, rechecking
    /// the owner proof in the committing transaction. A portable record's
    /// binding is a custody rewrap this install records and, as its holder,
    /// enacts in the same commit (CALLS CUSTODY_BIND_TRAVEL); a record that
    /// stays on its device, or an install that carries no owner act, binds
    /// here alone, and the custody receipt says which. The rewrap's owner act
    /// records `surface`, where his request reached this install: audit only
    /// (FIX 4650).
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is no longer
    /// the live owner's. [`SecretError::InvalidSecretCustodyBody`] for an
    /// empty or overlong effector. [`SecretError::SecretRefNotFound`] for no
    /// such secret; [`SecretError::SecretCustodyNotActive`] for one that is
    /// not active. [`SecretError::ManifestWidensFloor`] for a rung above the
    /// class's live floor. For a portable record, a refusal of this install
    /// as holder, and an install key that fails to load.
    pub fn bind_secret_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: ActSurface,
        request: &SecretBindRequest,
        at: u64,
    ) -> Result<SecretBound> {
        let effector = request.effector.trim();
        if effector.is_empty() || effector.len() > EFFECTOR_MAX_BYTES {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "a binding names its effector, at most 256 bytes",
            )));
        }
        // The install key signs a portable record's request and transition
        // in the writer below; a key that fails to load refuses here.
        self.load_install_signing_if_minted()?;
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &wtxn)?;
        if !crate::policy_model::is_live_vault_owner_in_txn(self, &wtxn, &actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "only the vault owner binds a secret",
            )));
        }
        let (handle, id) = target_in_txn(&self.store, &wtxn, &request.target)?;
        // The value stays as stored, never opened: a bind needs no custody
        // key (KS-6).
        let mut held =
            read_stored_custody_in_txn(&self.store, &wtxn, &id)?.ok_or_else(|| unknown(&handle))?;
        let rec = &mut held.record;
        refuse_revoked_use_in_txn(self, &wtxn, &id, rec.class, &handle)?;
        if rec.status != SecretCustodyStatus::Active {
            return Err(not_active(&handle));
        }
        let binding = SecretBinding {
            effector: effector.to_owned(),
            tier_ceiling: request.tier_ceiling,
            scopes: request.scopes.clone(),
        };
        match rec.bindings.iter_mut().find(|b| b.effector == effector) {
            Some(slot) => *slot = binding,
            None => rec.bindings.push(binding),
        }
        refuse_bindings_wider_than_live_floor(&self.store, &wtxn, rec)?;
        let custody = if custody_portable(rec) {
            let material = match CUSTODY_BIND_TRAVEL {
                CustodyBindTravel::InputBearingRewrap => Material::Bindings(&rec.bindings),
            };
            let recorded = self.record_custody_change_in_txn(
                &mut wtxn,
                actor,
                surface,
                ActiveChange {
                    change: CustodyChange::Rewrap,
                    id,
                    generation: rec.rotation_generation,
                    plan: &CustodyPlan::default(),
                    material,
                    sealed: None,
                    seen: None,
                    permits: None,
                },
                at,
            )?;
            // An install that carries no owner act, or holds no key, binds
            // here alone, and the receipt says so.
            if recorded.custody.kept_here.is_some() {
                put_stored_custody_in_txn(self, &mut wtxn, &id, &held, at)?;
            }
            recorded.custody
        } else {
            put_stored_custody_in_txn(self, &mut wtxn, &id, &held, at)?;
            SecretCustodyWork::kept(CustodyKeptHere::DeviceLocal)
        };
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at: crate::ports::recorded_at_in_txn(&self.store, &mut wtxn)?,
            outcome: "approved".into(),
            reason_codes: vec![SECRET_BIND_REASON.into()],
            receipt_reasons: Vec::new(),
            system_notices: crate::store::GateSystemNoticeRecord::receipt_details(
                SECRET_BIND_CONTENT_KIND,
                vec![
                    format!("handle:{handle}"),
                    format!("effector:{effector}"),
                    format!("rung:{}", request.tier_ceiling.as_u8()),
                    format!("scopes:{}", request.scopes.join(",")),
                ],
            ),
            actor_class: "human".into(),
            actor_ref: Some(actor.to_hex()),
            content_kind: SECRET_BIND_CONTENT_KIND.into(),
            policy_manifest_version: crate::gate::POLICY_SCHEMA_VERSION.into(),
            claim_id: None,
            grant_ref: None,
            diff_handle: id.as_bytes().to_vec(),
            read_frontier_hash: [0; 32],
            redacted_at: None,
        };
        self.store.append_gate_decision_in_txn(&mut wtxn, &record)?;
        let bound = SecretBound {
            secret_id: id,
            handle,
            name: held.record.name.clone(),
            bindings: held.record.bindings.clone(),
            receipt: decision_id,
            custody,
        };
        wtxn.commit()?;
        self.mirror_custody_change(&bound.custody);
        Ok(bound)
    }
}

/// The handle and record a bind request names, by its handle or its name.
fn target_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: &RevealTarget,
) -> Result<(String, EntityId)> {
    match target {
        RevealTarget::Handle(handle) => handle_record_in_txn(store, txn, handle),
        RevealTarget::Name(name) => {
            let id = resolve_secret_ref_in_txn(store, txn, name)?.ok_or_else(|| unknown(name))?;
            let handle = crate::ports::ShortIdStoreRead::port_short_id_reference(store, txn, &id)?
                .map_or_else(|| name.clone(), |(short, _)| short);
            Ok((handle, id))
        }
    }
}
