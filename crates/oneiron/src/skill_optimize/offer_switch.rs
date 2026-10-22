//! An approved training offer's stock switch (OF-577; ARCH-0053
//! #training-offers: a switch binds now, with undo). The owner's switch
//! approval binds the offered stock model to the seat's role in the
//! transaction that records the answer, and keeps the whole binding it
//! replaced. Undo restores that binding only while the seat still holds the
//! one the switch bound: anything else moved it since, and undo would
//! overwrite that. An embedder seat's switch stages its binding through a
//! space move instead (O3b PR B; ARCH-0053 R13: search uses the old index
//! meanwhile): the binding applies at that move's swap, and undo goes through
//! the same staged binding.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{EvalSeat, OfferModelPin};
use crate::consent::AuthenticatedOwner;
use crate::deletion::names_no_actor;
use crate::embed::{BindingMoveState, BindingNotApplied, BindingSource};
use crate::llm::LlmCapability;
use crate::llm::manifest::{MODEL_ROLES, ModelBinding, ModelRole, read_manifest};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, ModelId, Result, Vault};

/// The switch one offer's approval applied, keyed by offer id.
const SWITCH: SideTable<EntityId, OfferSwitchReceipt, Named> =
    SideTable::new(&side_table::SKILL_OPTIMIZE_OFFER_SWITCH);

/// What an approved switch bound, and the binding it replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferSwitchReceipt {
    pub offer: EntityId,
    pub role: ModelRole,
    /// The whole binding the switch replaced; undo restores it.
    pub previous: ModelBinding,
    pub binding: ModelBinding,
    /// The asset the owner approved, at the revision the registry served.
    pub to: OfferModelPin,
    pub owner: SwitchOwner,
    pub at: u64,
    pub application: SwitchApplication,
    pub undone: Option<OfferSwitchUndo>,
}

/// Where a switch's binding stands: bound with the approval, or, for the
/// embedder seat, staged through a space move and applied at its swap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SwitchApplication {
    /// Bound in the approval's own write.
    Bound,
    /// Staged: the old binding and index serve while its candidate space
    /// fills, or until a declared space pins the model.
    Staged,
    /// The staged binding applied as its move swapped in.
    Applied { at: u64 },
    /// The staged binding never applied.
    NotApplied { at: u64, why: BindingNotApplied },
}

impl SwitchApplication {
    /// What a staged binding's `state` reads as here; `None` for an undo,
    /// which the receipt's own `undone` records.
    fn staged(state: &BindingMoveState) -> Option<Self> {
        match state {
            BindingMoveState::Waiting | BindingMoveState::Filling => Some(Self::Staged),
            BindingMoveState::Applied { at, .. } => Some(Self::Applied { at: *at }),
            BindingMoveState::NotApplied { at, why } => Some(Self::NotApplied {
                at: *at,
                why: why.clone(),
            }),
            BindingMoveState::Undone { .. } => None,
        }
    }
}

/// The owner's undo of a switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferSwitchUndo {
    pub owner: SwitchOwner,
    pub at: u64,
}

/// The owner a switch or its undo names: an actor, or no one once that
/// actor was erased (FIX 3520). It reads and writes as the actor's hex id,
/// or as [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchOwner {
    Actor(EntityId),
    Erased,
}

impl SwitchOwner {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// Makes this no one when it is `actor`; whether it was.
    pub(crate) fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for SwitchOwner {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for SwitchOwner {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.into())
}

/// The eval seat a model role's offers are for: the named seats for the
/// roles that serve them, and any other role its own named seat.
#[must_use]
pub fn model_role_seat(role: ModelRole) -> EvalSeat {
    match role {
        ModelRole::GenerativeReasoner => EvalSeat::Companion,
        ModelRole::RetrievalEmbedder => EvalSeat::Embedder,
        ModelRole::ExtractionEncoder => EvalSeat::ExtractionTagger,
        role => EvalSeat::Named(
            serde_json::to_value(role)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| format!("{role:?}")),
        ),
    }
}

/// The model role an offer's seat is, the inverse of [`model_role_seat`].
#[must_use]
pub fn seat_model_role(seat: &EvalSeat) -> Option<ModelRole> {
    MODEL_ROLES
        .into_iter()
        .find(|role| model_role_seat(*role) == *seat)
}

/// Binds the approved stock model to the seat's role, in the transaction
/// that records the owner's switch approval. The new binding keeps the old
/// one's slot, tier and disposition; the old model's narrower routes name
/// other models and do not carry over.
/// # Errors
/// A seat with no model role or no binding, a binding that is no longer the
/// offer's incumbent, an offered model the registry no longer serves at the
/// offered revision, a manifest the new binding does not validate in, or
/// storage errors.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply_switch_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owner: EntityId,
    offer: &EntityId,
    seat: &EvalSeat,
    from: &OfferModelPin,
    to: &OfferModelPin,
    at: u64,
) -> Result<OfferSwitchReceipt> {
    let role = seat_model_role(seat).ok_or(invalid("the offer's seat names no model role"))?;
    let mut manifest = read_manifest(&vault.store, txn)?.ok_or(invalid(
        "configure the model manifest before switching a seat",
    ))?;
    let previous = manifest
        .roles
        .get(&role)
        .cloned()
        .ok_or(invalid("the seat has no model binding to switch"))?;
    if previous.model.as_str() != from.model {
        return Err(invalid(
            "the seat moved since the offer was made; answer a newer offer",
        ));
    }
    let model = ModelId::new(to.model.clone())
        .map_err(|_| invalid("the offered model id does not parse"))?;
    let row = vault
        .model_registry_row_in_txn(txn, &model)?
        .ok_or(invalid("the offered model left the registry"))?;
    let served = row
        .backends()?
        .into_iter()
        .next()
        .map(|backend| backend.pin.serving_revision);
    if served.as_deref() != Some(to.revision.as_str()) {
        return Err(invalid(
            "the offered model's served revision changed since the offer was made",
        ));
    }
    let binding = ModelBinding {
        model,
        slot: previous.slot,
        tier: previous.tier.clone(),
        route_models: BTreeMap::new(),
        disposition: previous.disposition.clone(),
        reads_audio: previous.reads_audio && row.catalog.supports(&LlmCapability::AudioInput),
    };
    let application = if role == ModelRole::RetrievalEmbedder {
        let source = BindingSource::Offer {
            offer: *offer,
            owner: SwitchOwner::Actor(owner),
        };
        let pending = crate::embed::stage_embedder_binding_in_txn(
            vault,
            txn,
            source,
            Some(previous.clone()),
            binding.clone(),
        )?;
        SwitchApplication::staged(&pending.state).unwrap_or(SwitchApplication::Staged)
    } else {
        manifest.roles.insert(role, binding.clone());
        vault.write_model_manifest_in_txn(txn, &manifest, None, None)?;
        SwitchApplication::Bound
    };
    let receipt = OfferSwitchReceipt {
        offer: *offer,
        role,
        previous,
        binding,
        to: to.clone(),
        owner: SwitchOwner::Actor(owner),
        at,
        application,
        undone: None,
    };
    SWITCH.put(&vault.store, txn, offer, &receipt)?;
    Ok(receipt)
}

/// The vault owner's undo of an approved switch: the seat's role takes back
/// the binding the switch replaced. A staged embedder switch undoes through
/// its binding move: a pending binding is cancelled with its move, and an
/// applied one goes back with the slots its move swapped in.
/// # Errors
/// A caller who is not the vault owner, an offer whose approval bound no
/// switch, a switch already undone, a staged one that never applied, a seat
/// whose binding moved since the switch, a manifest the old binding no longer
/// validates in, or storage errors. An error writes nothing.
pub fn undo_training_offer_switch(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    offer: &EntityId,
    at: u64,
) -> Result<OfferSwitchReceipt> {
    let (receipt, setup) = vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let mut receipt = SWITCH
            .get(&vault.store, txn, offer)?
            .ok_or(invalid("the offer's approval bound no switch"))?;
        if receipt.undone.is_some() {
            return Err(invalid("the switch is already undone"));
        }
        let setup = if receipt.application == SwitchApplication::Bound {
            let mut manifest = read_manifest(&vault.store, txn)?
                .ok_or(invalid("the model manifest is gone; nothing to undo"))?;
            if manifest.roles.get(&receipt.role) != Some(&receipt.binding) {
                return Err(invalid(
                    "the seat's binding changed since the switch; undo would overwrite it",
                ));
            }
            manifest
                .roles
                .insert(receipt.role, receipt.previous.clone());
            vault.write_model_manifest_in_txn(txn, &manifest, None, None)?;
            None
        } else {
            let (state, rows) = crate::embed::undo_staged_binding_in_txn(vault, txn, offer, actor)?;
            if let Some(application) = SwitchApplication::staged(&state) {
                receipt.application = application;
            }
            Some(rows)
        };
        receipt.undone = Some(OfferSwitchUndo {
            owner: SwitchOwner::Actor(actor),
            at,
        });
        SWITCH.put(&vault.store, txn, offer, &receipt)?;
        Ok((receipt, setup))
    })?;
    // A move the undo ended hands its setup rows on once committed.
    if let Some(setup) = setup {
        vault.embedding_setup_committed(setup);
        vault.embedding_move_ended();
    }
    Ok(receipt)
}

/// Records a staged switch's binding `state` on its receipt, in the write
/// that moved it (O3b PR B).
/// # Errors
/// Storage errors.
pub(crate) fn settle_staged_switch_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    offer: &EntityId,
    state: &BindingMoveState,
) -> Result<()> {
    let Some(application) = SwitchApplication::staged(state) else {
        return Ok(());
    };
    if let Some(mut receipt) = SWITCH.get(&vault.store, txn, offer)?
        && receipt.application != application
    {
        receipt.application = application;
        SWITCH.put(&vault.store, txn, offer, &receipt)?;
    }
    Ok(())
}

/// Records the owner's undo of a staged switch's move on its receipt, in the
/// undo's write: the move's undo took the binding back with its slots.
/// # Errors
/// Storage errors.
pub(crate) fn undo_staged_switch_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    offer: &EntityId,
    actor: EntityId,
    at: u64,
) -> Result<()> {
    if let Some(mut receipt) = SWITCH.get(&vault.store, txn, offer)?
        && receipt.undone.is_none()
    {
        receipt.undone = Some(OfferSwitchUndo {
            owner: SwitchOwner::Actor(actor),
            at,
        });
        SWITCH.put(&vault.store, txn, offer, &receipt)?;
    }
    Ok(())
}

/// The switch an offer's approval applied, if any.
/// # Errors
/// Storage errors.
pub fn training_offer_switch(
    vault: &Vault,
    offer: &EntityId,
) -> Result<Option<OfferSwitchReceipt>> {
    let txn = vault.store.env.read_txn()?;
    SWITCH.get(&vault.store, &txn, offer)
}

/// Erasing `actor` from the switches (FIX 3520): each switch it approved or
/// undid keeps its bindings, asset, times and undo state and names no one.
/// A switch stays bound, since its approver's erase undoes nothing, and a
/// later undo takes the live owner's proof. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a switch row that cannot be read.
pub(crate) fn erase_switch_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut receipts = Vec::new();
    for (offer, mut receipt) in SWITCH.scan(&vault.store, wtxn)? {
        let approved = receipt.owner.forget(*actor);
        let undid = receipt
            .undone
            .as_mut()
            .is_some_and(|undo| undo.owner.forget(*actor));
        if approved || undid {
            receipts.push((offer, receipt));
        }
    }
    for (offer, receipt) in receipts {
        SWITCH.put(&vault.store, wtxn, &offer, &receipt)?;
    }
    Ok(())
}
