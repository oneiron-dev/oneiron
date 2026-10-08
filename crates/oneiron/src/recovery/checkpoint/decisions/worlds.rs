//! Which worlds an executing principal may read: the owner grants and the
//! default its `claim_of` edges reach, as the world-authority fold reads them
//! at an instant.
use super::{Decision, held_by_both};
use crate::claim::ClaimSubject;
use crate::pipeline::{
    ActiveWorldSelection, PREDICATE_WORLD_ACCESS_ALLOWED_SET,
    PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET, WorldAuthoritySet,
};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::{EntityId, Result, Vault};
use std::collections::BTreeSet;

/// The worlds a principal may select and the ones a turn that selects none
/// reads: the intersection of every in-force owner grant its `claim_of`
/// edges reach, and the newest in-force default it wrote itself, which must
/// lie inside that intersection (`resolve_world_authority`).
pub(super) struct WorldSelections;

/// What a principal's world authority admits at one instant.
pub(super) struct WorldSelectionAuthority {
    /// Every world, base reality included, an explicit selection may name.
    allowed: WorldAuthoritySet,
    /// The worlds a turn that names none reads.
    default: WorldAuthoritySet,
}

impl Decision for WorldSelections {
    /// A principal, and an instant its authority is read at.
    type Subject = (EntityId, u64);
    type Answer = WorldSelectionAuthority;

    /// Every principal both vaults hold that a world-access claim in either
    /// vault names, at zero, now, and each bound of such a claim's validity,
    /// attached or not: the fold changes only where a claim comes into or
    /// goes out of force, so these instants stand for every other. A
    /// principal no such claim names is granted nothing in either vault, and
    /// one only one vault holds returns or leaves with the restore.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let mut principals = BTreeSet::new();
        for kind in [
            ENTITY_TYPE_AGENT_DEF,
            ENTITY_TYPE_PERSON,
            ENTITY_TYPE_MACHINE,
        ] {
            principals.extend(held_by_both(vaults, kind)?);
        }
        // The live vault's clock: both vaults are asked at the same instants.
        let now = vaults[0].now_recorded_at();
        let mut subjects = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for predicate in [
                PREDICATE_WORLD_ACCESS_ALLOWED_SET,
                PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET,
            ] {
                for (_, claim) in vault.claims_with_predicate_in_txn(&txn, predicate)? {
                    if let ClaimSubject::Entity(principal) = claim.subject
                        && principals.contains(&principal)
                    {
                        subjects.extend(
                            [Some(0), Some(now), claim.valid_from, claim.valid_to]
                                .into_iter()
                                .flatten()
                                .map(|at| (principal, at)),
                        );
                    }
                }
            }
        }
        Ok(subjects)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<WorldSelectionAuthority>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|(principal, at)| {
                let selection = ActiveWorldSelection {
                    agent_ref: *principal,
                    selected: None,
                };
                crate::pipeline::resolve_world_authority(&vault.store, &txn, &selection, *at)
                    .ok()
                    .map(|resolved| WorldSelectionAuthority {
                        allowed: resolved.allowed_set,
                        default: resolved.default_subset,
                    })
            })
            .collect())
    }

    fn loosens(live: &WorldSelectionAuthority, restored: &WorldSelectionAuthority) -> bool {
        !restored.allowed.is_subset_of(&live.allowed)
            || !restored.default.is_subset_of(&live.default)
    }

    /// A fold that fails admits no selection, explicit or default.
    fn refusal() -> Option<WorldSelectionAuthority> {
        Some(WorldSelectionAuthority {
            allowed: WorldAuthoritySet::default(),
            default: WorldAuthoritySet::default(),
        })
    }
}
