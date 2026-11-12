//! The owner's non-base world claim fraction (ARCH-0004 #world-scope: "The
//! non-base fraction is a budget knob, and the vault owner sets it"; FIX
//! WORLD-SHARE-FRACTION-NO-OWNER-DOOR). It is the most of a context pack's
//! claims that worlds other than base may hold, from 0 (base reality alone)
//! to 1 (no cap). One row holds it, and an absent row reads as
//! [`DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION`]. Every pack that partitions its
//! claims by world reads it, unless its caller names a fraction of its own.
//!
//! The owner alone sets it (`vault.settings.non_base_world_claim_fraction.set`),
//! under the owner's proof, and a change records the owner's act in the same
//! commit. The read (`vault.settings.non_base_world_claim_fraction`) answers
//! the owner, or a holder of any `engine.controls` class, checked at the read,
//! as every dial read is (untangle 6.6f; S66F-READ = C).

use serde::{Deserialize, Serialize};

use crate::authority::ActSurface;
use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::memory::{Memory, MemoryResult};
use crate::policy_setting_doors::{PolicySetting, record_policy_setting_act_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{Vault, WriteActor};

/// The share a pack gives worlds other than base while the owner has set
/// none: fiction takes at most half, so it never crowds base reality out
/// (ARCH-0004 / ARCH-0022).
pub const DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION: f32 = 0.5;

/// The read verb's name, as a refusal names it.
const READ_VERB: &str = "vault.settings.non_base_world_claim_fraction";

/// The set verb's name, as a refusal names it.
const SET_VERB: &str = "vault.settings.non_base_world_claim_fraction.set";

/// The owner's fraction. Key: ().
const FRACTION: SideTable<(), NonBaseWorldClaimFraction, Named> =
    SideTable::new(&side_table::NON_BASE_WORLD_CLAIM_FRACTION);

/// The non-base world claim fraction: `vault.settings.non_base_world_claim_fraction`'s
/// answer, and `.set`'s input and answer.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NonBaseWorldClaimFraction {
    /// The most of a context pack's claims that worlds other than base may
    /// hold, from 0 (base reality alone) to 1 (no cap): a partitioned pack
    /// keeps at most `floor(fraction times its emitted claims)` of them.
    pub fraction: f32,
}

impl NonBaseWorldClaimFraction {
    /// The fraction while the owner has set none.
    pub const DEFAULT: Self = Self {
        fraction: DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION,
    };

    /// Refuses a fraction below 0, above 1, or not a number.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] naming the fraction.
    pub fn validate(self) -> Result<()> {
        if (0.0..=1.0).contains(&self.fraction) {
            Ok(())
        } else {
            Err(Error::InvalidConfig(format!(
                "the non-base world claim fraction must be from 0 to 1, not {}",
                self.fraction
            )))
        }
    }
}

impl Default for NonBaseWorldClaimFraction {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The fraction in `txn`: the owner's row, or the default while there is none.
fn fraction_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<NonBaseWorldClaimFraction> {
    Ok(FRACTION.get(&vault.store, txn, &())?.unwrap_or_default())
}

impl Vault {
    /// The non-base world claim fraction in force: the owner's, or
    /// [`DEFAULT_NON_BASE_WORLD_CLAIM_FRACTION`] while the owner has set none.
    /// A context pack whose caller names no fraction reads it.
    ///
    /// # Errors
    ///
    /// Storage errors, and a stored row that does not decode.
    pub fn non_base_world_claim_fraction(&self) -> Result<NonBaseWorldClaimFraction> {
        let txn = self.store.env.read_txn()?;
        fraction_in_txn(self, &txn)
    }

    /// [`Self::non_base_world_claim_fraction`] under the owner's proof.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, and storage errors.
    pub fn non_base_world_claim_fraction_as_owner(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<NonBaseWorldClaimFraction> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        fraction_in_txn(self, &txn)
    }

    /// The owner sets the non-base world claim fraction; the next context
    /// pack reads it. The owner is revalidated in the writer. A change records
    /// the owner's act, with the fraction it replaces, in the same commit when
    /// `surface` names where the owner said so; a fraction equal to the one in
    /// force writes and records nothing. Answers the fraction as it now reads.
    ///
    /// # Errors
    ///
    /// A fraction that fails [`NonBaseWorldClaimFraction::validate`], a proof
    /// that no longer holds, and storage errors.
    pub fn set_non_base_world_claim_fraction(
        &self,
        owner: &AuthenticatedOwner,
        surface: Option<ActSurface>,
        setting: NonBaseWorldClaimFraction,
    ) -> Result<NonBaseWorldClaimFraction> {
        setting.validate()?;
        self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let prior = fraction_in_txn(self, txn)?;
            if setting != prior {
                FRACTION.put(&self.store, txn, &(), &setting)?;
                let signed = record_policy_setting_act_in_txn(
                    self,
                    txn,
                    PolicySetting::NonBaseWorldClaimFraction,
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

/// The fraction for a holder of any `engine.controls` class, checked at this
/// read (S66F-READ = C). The vault's owner reads through its own door, under
/// its proof.
///
/// # Errors
///
/// A caller that holds no live grant naming an `engine.controls` class, and
/// storage errors.
pub fn non_base_world_claim_fraction_as_holder(
    vault: &Vault,
    reader: WriteActor,
) -> MemoryResult<NonBaseWorldClaimFraction> {
    crate::federation::admit_substrate_read_by(
        vault,
        reader,
        READ_VERB,
        crate::federation::SubstrateRead::Dials,
    )?;
    Ok(vault.non_base_world_claim_fraction()?)
}

/// `vault.settings.non_base_world_claim_fraction` on a bound handle: the
/// embedded owner reads under its own proof, any other caller as a holder of
/// an `engine.controls` class.
///
/// # Errors
///
/// As [`non_base_world_claim_fraction_as_holder`], and storage errors.
pub fn read_non_base_world_claim_fraction(
    memory: &Memory<'_>,
) -> MemoryResult<NonBaseWorldClaimFraction> {
    match memory.embedded_owner(READ_VERB) {
        Ok(owner) => Ok(memory
            .vault()
            .non_base_world_claim_fraction_as_owner(&owner)?),
        Err(_) => non_base_world_claim_fraction_as_holder(
            memory.vault(),
            WriteActor::new(memory.actor(), memory.actor_class()),
        ),
    }
}

/// `vault.settings.non_base_world_claim_fraction.set` on the embedded owner's
/// handle. The owner's act records this install as where the owner said so.
///
/// # Errors
///
/// A handle that is not the vault owner's, a fraction the setter refuses, and
/// storage errors.
pub fn set_non_base_world_claim_fraction_embedded(
    memory: &Memory<'_>,
    input: NonBaseWorldClaimFraction,
) -> MemoryResult<NonBaseWorldClaimFraction> {
    Ok(memory.vault().set_non_base_world_claim_fraction(
        &memory.embedded_owner(SET_VERB)?,
        Some(ActSurface::ThisInstall),
        input,
    )?)
}
