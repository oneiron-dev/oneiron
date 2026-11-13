//! The engine writer a fitted section install lands under (Engine ruling
//! FIT-INSTALL-DESIGN = A; owner law ARCH-0053 "Everything installs;
//! permissions ask"). The install claim attests that the engine's
//! deterministic fit concluded Ready, so this one engine MACHINE writes it,
//! signed with the signer the host retained for it, not the offering actor.
//! The default manifest binds its actor ceiling row and its `generated`
//! source-trust row to this writer alone, as it does the scope summary
//! landing writer's.
//!
//! It grants nothing: the section's verb and lane requests still ask, the
//! offering actor stays named on the `skill.section_fit` receipt, and the
//! owner's revoke retracts the install. Only a [`ReadyFit`] reaches the
//! writer, and only a Ready fit outcome makes one. A vault whose host
//! provisioned no engine identities has no signer for it: the write door
//! refuses the unsigned MACHINE claim, the writer rolls back, and the offer
//! asks the owner as before.

use crate::entity_id::derived_domains::PLUGIN_SECTION_FIT_INSTALL_ACTOR;
use crate::registry::ENTITY_TYPE_MACHINE;
use crate::skill_hub::MarketplaceFit;
use crate::{EdgeActorClass, EntityId, Error, Result, TimeRange, Vault, WriteActor};

/// A fit that concluded Ready. Only [`ReadyFit::from_outcome`] makes one,
/// and only the fitted install's landing spends it.
pub(super) struct ReadyFit(());

impl ReadyFit {
    /// The guard for a Ready outcome; none for any other.
    pub(super) fn from_outcome(outcome: MarketplaceFit) -> Option<Self> {
        (outcome == MarketplaceFit::Ready).then_some(Self(()))
    }
}

/// The fit install writer's id: derived, so every device names the same one.
pub(crate) fn fit_install_writer_id() -> Result<EntityId> {
    EntityId::derive(PLUGIN_SECTION_FIT_INSTALL_ACTOR, &[])
}

/// The fit install writer's MACHINE row, put on first use. A row of another
/// type under its id refuses.
pub(crate) fn ensure_fit_install_writer_machine(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<EntityId> {
    let id = fit_install_writer_id()?;
    match vault.get_entity_type_in_txn(txn, &id)? {
        None => vault
            .batch_in()
            .put_internal(
                &id,
                ENTITY_TYPE_MACHINE,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"plugin section fit install writer",
            )
            .apply(txn)?,
        Some(ENTITY_TYPE_MACHINE) => {}
        Some(_) => {
            return Err(Error::InvariantViolation(
                "the plugin section fit install writer is unavailable",
            ));
        }
    }
    Ok(id)
}

/// The writer a Ready fit's install claim lands under.
pub(super) fn fit_install_writer(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
    _ready: &ReadyFit,
) -> Result<WriteActor> {
    Ok(WriteActor::new(
        ensure_fit_install_writer_machine(vault, txn, now)?,
        EdgeActorClass::System,
    ))
}
