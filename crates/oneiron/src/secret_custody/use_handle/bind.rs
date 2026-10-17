//! The owner binds a secret to an effector (OF-560): the door a handle with
//! no binding names, so the secret it holds can be used without being read.
//!
//! A binding names the effector that may use the secret, the most exposed
//! rung it may use it at, and what it grants. The owner proof is rechecked in
//! the transaction that stores the binding, and the binding may sit no higher
//! than the class's live floor. A portable record's new bindings reach the
//! owner's other machines as a signed custody transition, as a rotation's
//! do. The Gate record keeps the handle, the effector, the rung and the
//! scopes, never the value.

use zeroize::Zeroize;

use super::super::doors::{
    put_secret_custody_in_txn, read_secret_custody_in_txn, refuse_bindings_wider_than_live_floor,
    resolve_secret_ref_in_txn,
};
use super::super::reveal::RevealTarget;
use super::super::transition::write_custody_transition_in_txn;
use super::super::types::{
    CustodyTier, SECRET_SCOPE_READ, SecretBinding, SecretCustodyRecord, SecretCustodyStatus,
};
use super::{handle_record_in_txn, not_active, unknown};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError, Result, SecretError};
use crate::store::{GATE_DECISION_LEDGER_VERSION, GateDecisionId, GateDecisionRecord};
use crate::vault::Vault;

/// The Gate reason code of an owner's binding.
pub const SECRET_BIND_REASON: &str = "gate.secret.owner_bind";

/// The Gate content kind of an owner's binding.
const SECRET_BIND_CONTENT_KIND: &str = "secret_bind";

/// The longest effector a binding names.
const EFFECTOR_MAX_BYTES: usize = 256;

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

/// What the binding left: the record's bindings and the receipt. No value.
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
}

impl Vault {
    /// Binds a secret to an effector on the vault owner's behalf, rechecking
    /// the owner proof in the committing transaction.
    ///
    /// # Errors
    /// [`GateError::ConsentOwnerNotAuthenticated`] when the proof is no longer
    /// the live owner's. [`SecretError::InvalidSecretCustodyBody`] for an
    /// empty or overlong effector. [`SecretError::SecretRefNotFound`] for no
    /// such secret; [`SecretError::SecretCustodyNotActive`] for one that is
    /// not active. [`SecretError::ManifestWidensFloor`] for a rung above the
    /// class's live floor.
    pub fn bind_secret_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        request: &SecretBindRequest,
        at: u64,
    ) -> Result<SecretBound> {
        let effector = request.effector.trim();
        if effector.is_empty() || effector.len() > EFFECTOR_MAX_BYTES {
            return Err(Error::Secret(SecretError::InvalidSecretCustodyBody(
                "a binding names its effector, at most 256 bytes",
            )));
        }
        let _ = self.load_install_signing_if_minted();
        let mut wtxn = self.store.env.write_txn()?;
        let actor = owner.revalidate_in_txn(self, &wtxn)?;
        if !crate::policy_model::is_live_vault_owner_in_txn(self, &wtxn, &actor)? {
            return Err(Error::Gate(GateError::ConsentOwnerNotAuthenticated(
                "only the vault owner binds a secret",
            )));
        }
        let (handle, id) = match &request.target {
            RevealTarget::Handle(handle) => handle_record_in_txn(&self.store, &wtxn, handle)?,
            RevealTarget::Name(name) => {
                let id = resolve_secret_ref_in_txn(&self.store, &wtxn, name)?
                    .ok_or_else(|| unknown(name))?;
                let handle = crate::ports::ShortIdStoreRead::port_short_id_reference(
                    &self.store,
                    &wtxn,
                    &id,
                )?
                .map_or_else(|| name.clone(), |(short, _)| short);
                (handle, id)
            }
        };
        let mut held = Held(
            read_secret_custody_in_txn(&self.store, &wtxn, &id)?.ok_or_else(|| unknown(&handle))?,
        );
        let rec = &mut held.0;
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
        put_secret_custody_in_txn(self, &mut wtxn, &id, rec, at)?;
        let transition = write_custody_transition_in_txn(self, &mut wtxn, id, rec, at)?;
        let decision_id = GateDecisionId::from_bytes(self.store.clock.ulid()?);
        let record = GateDecisionRecord {
            version: GATE_DECISION_LEDGER_VERSION,
            decision_id,
            created_at: crate::ports::recorded_at_in_txn(&self.store, &mut wtxn)?,
            outcome: "approved".into(),
            reason_codes: vec![SECRET_BIND_REASON.into()],
            receipt_reasons: vec![
                format!("handle:{handle}"),
                format!("effector:{effector}"),
                format!("rung:{}", request.tier_ceiling.as_u8()),
                format!("scopes:{}", request.scopes.join(",")),
            ],
            system_notices: Vec::new(),
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
            name: rec.name.clone(),
            bindings: rec.bindings.clone(),
            receipt: decision_id,
        };
        wtxn.commit()?;
        #[cfg(feature = "sync")]
        if transition.is_some() {
            self.refresh_custody_in_live_windows();
        }
        #[cfg(not(feature = "sync"))]
        let _ = transition;
        Ok(bound)
    }
}

/// The record a binding reads, its value wiped when the door is done with
/// it, on every path.
struct Held(SecretCustodyRecord);

impl Drop for Held {
    fn drop(&mut self) {
        self.0.value_bytes.zeroize();
    }
}
