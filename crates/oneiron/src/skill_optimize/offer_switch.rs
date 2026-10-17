//! An approved training offer's stock switch (OF-577; ARCH-0053
//! #training-offers: a switch binds now, with undo). The owner's switch
//! approval binds the offered stock model to the seat's role in the
//! transaction that records the answer, and keeps the whole binding it
//! replaced. Undo restores that binding only while the seat still holds the
//! one the switch bound: anything else moved it since, and undo would
//! overwrite that.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{EvalSeat, OfferModelPin};
use crate::consent::AuthenticatedOwner;
use crate::llm::LlmCapability;
use crate::llm::manifest::{MODEL_ROLES, ModelBinding, ModelRole, read_manifest};
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
    pub owner: EntityId,
    pub at: u64,
    pub undone: Option<OfferSwitchUndo>,
}

/// The owner's undo of a switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferSwitchUndo {
    pub owner: EntityId,
    pub at: u64,
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
    manifest.roles.insert(role, binding.clone());
    vault.write_model_manifest_in_txn(txn, &manifest, None, None)?;
    let receipt = OfferSwitchReceipt {
        offer: *offer,
        role,
        previous,
        binding,
        to: to.clone(),
        owner,
        at,
        undone: None,
    };
    SWITCH.put(&vault.store, txn, offer, &receipt)?;
    Ok(receipt)
}

/// The vault owner's undo of an approved switch: the seat's role takes back
/// the binding the switch replaced.
/// # Errors
/// A caller who is not the vault owner, an offer whose approval bound no
/// switch, a switch already undone, a seat whose binding moved since the
/// switch, a manifest the old binding no longer validates in, or storage
/// errors. An error writes nothing.
pub fn undo_training_offer_switch(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    offer: &EntityId,
    at: u64,
) -> Result<OfferSwitchReceipt> {
    vault.with_write_txn_grouped(|txn| {
        let actor = owner.revalidate_in_txn(vault, txn)?;
        let mut receipt = SWITCH
            .get(&vault.store, txn, offer)?
            .ok_or(invalid("the offer's approval bound no switch"))?;
        if receipt.undone.is_some() {
            return Err(invalid("the switch is already undone"));
        }
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
        receipt.undone = Some(OfferSwitchUndo { owner: actor, at });
        SWITCH.put(&vault.store, txn, offer, &receipt)?;
        Ok(receipt)
    })
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
