//! The owner's doors over the vault default facet (ARCH-0022 #facets: "Every
//! vault has one default facet ... the owner may set another"; UNBUILT item
//! 10). A write with no active mask is born under it. The owner's reserved
//! [`PREDICATE_VAULT_DEFAULT_FACET`] claim holds it; with none, the owner's
//! `substrate` FACET is the default.
//!
//! The owner alone sets it (`vault.settings.default_facet.set`), under the
//! owner's proof, to a stored FACET, and a change records the owner's act in
//! the same commit. The read (`vault.settings.default_facet`) answers the
//! owner, or a holder of any `engine.controls` class, checked at the read,
//! as every dial read is (untangle 6.6f; S66F-READ = C).
//!
//! [`PREDICATE_VAULT_DEFAULT_FACET`]: crate::claim::PREDICATE_VAULT_DEFAULT_FACET

use serde::{Deserialize, Serialize};

use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::{Memory, MemoryResult};
use crate::policy_setting_doors::{PolicySetting, record_policy_setting_act_in_txn};
use crate::{EntityId, TimeRange, Vault, WriteActor};

/// The read verb's name, as a refusal names it.
const READ_VERB: &str = "vault.settings.default_facet";

/// The set verb's name, as a refusal names it.
const SET_VERB: &str = "vault.settings.default_facet.set";

/// The vault default facet: `vault.settings.default_facet`'s answer, and
/// `.set`'s input and answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefaultFacet {
    /// The FACET a write with no active mask is born under, as 32 hex.
    pub facet: EntityId,
}

impl Vault {
    /// The vault default facet under the owner's proof.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, and storage errors.
    pub fn default_facet_as_owner(&self, owner: &AuthenticatedOwner) -> Result<DefaultFacet> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        Ok(DefaultFacet {
            facet: self.default_facet_in_txn(&txn)?,
        })
    }

    /// The owner makes the stored FACET `setting.facet` the vault default;
    /// the next write with no active mask is born under it. The owner is
    /// revalidated in the writer. A change puts the owner's default-facet
    /// claim, superseding the one it replaces, and records the owner's act
    /// with the facet it replaces, in the same commit when `surface` names
    /// where the owner said so. The facet in force again writes and records
    /// nothing. Answers the default as it now reads.
    ///
    /// # Errors
    ///
    /// An id that is not a stored FACET (`InvalidFacet`), a proof that no
    /// longer holds, and storage errors.
    pub fn set_default_facet_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<ActSurface>,
        setting: DefaultFacet,
    ) -> Result<DefaultFacet> {
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let prior = DefaultFacet {
                facet: self.default_facet_in_txn(txn)?,
            };
            if setting != prior {
                let claim = self.store.clock.entity_id()?;
                let now = self.store.clock.now_recorded_at();
                self.put_default_facet_in_txn(
                    txn,
                    WriteActor::new(actor, EdgeActorClass::Human),
                    &claim,
                    setting.facet,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                )?;
                let signed = record_policy_setting_act_in_txn(
                    self,
                    txn,
                    PolicySetting::DefaultFacet,
                    actor,
                    surface,
                    &prior,
                    &setting,
                )?;
                // The signed record goes last, best effort (FIX 4624).
                if let Some(act) = signed {
                    self.record_policy_setting_op_in_txn(txn, act);
                }
            }
            Ok(setting)
        })
    }
}

/// The default facet for a holder of any `engine.controls` class, checked
/// at this read (S66F-READ = C). The vault's owner reads through its own
/// door, under its proof.
///
/// # Errors
///
/// A caller that holds no live grant naming an `engine.controls` class, and
/// storage errors.
pub fn default_facet_as_holder(vault: &Vault, reader: WriteActor) -> MemoryResult<DefaultFacet> {
    crate::federation::admit_substrate_read_by(
        vault,
        reader,
        READ_VERB,
        crate::federation::SubstrateRead::Dials,
    )?;
    Ok(DefaultFacet {
        facet: vault.default_facet()?,
    })
}

/// `vault.settings.default_facet` on a bound handle: the embedded owner
/// reads under its own proof, any other caller as a holder of an
/// `engine.controls` class.
///
/// # Errors
///
/// As [`default_facet_as_holder`], and storage errors.
pub fn read_default_facet(memory: &Memory<'_>) -> MemoryResult<DefaultFacet> {
    match memory.embedded_owner(READ_VERB) {
        Ok(owner) => Ok(memory.vault().default_facet_as_owner(&owner)?),
        Err(_) => default_facet_as_holder(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
        ),
    }
}

/// `vault.settings.default_facet.set` on the embedded owner's handle. The
/// owner's act records this install as where the owner said so.
///
/// # Errors
///
/// A handle that is not the vault owner's, an id the setter refuses, and
/// storage errors.
pub fn set_default_facet_embedded(
    memory: &Memory<'_>,
    input: DefaultFacet,
) -> MemoryResult<DefaultFacet> {
    Ok(memory.vault().set_default_facet_as_owner(
        &memory.embedded_owner(SET_VERB)?,
        Some(ActSurface::ThisInstall),
        input,
    )?)
}
