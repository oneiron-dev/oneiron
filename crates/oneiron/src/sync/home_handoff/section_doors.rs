//! A door for the integration tests (compiled only under `--cfg
//! oneiron_test_support`): one registered section carried from one vault to
//! another as a move carries it, through the section's own export, its wire
//! encoding and its adopt, without the election, the seal or the signed ack.

use super::registry::home_tables;
use super::table::TableAdopt;
use super::{HomeFence, HomeGeneration, HomeIdentity, HomeMove};
use crate::error::{Error, Result};
use crate::{EntityId, Vault};

/// Carries the section named `table_id` from `source` to `target`: exports
/// it in a read of `source`, checks its encoded rows decode, and adopts them
/// in one writer of `target` with the content of every actor part but those
/// of `withheld`, as if their keys did not open there. Whether the section
/// applied.
///
/// # Errors
///
/// `InvalidConfig` when this build registers no section `table_id`; the
/// section's own export, decode and adopt errors.
pub(crate) fn carry_section_for_doors(
    source: &Vault,
    target: &Vault,
    table_id: &str,
    withheld: &[EntityId],
) -> Result<bool> {
    let table = home_tables()
        .into_iter()
        .find(|table| table.table_id() == table_id)
        .ok_or_else(|| {
            Error::InvalidConfig(format!("a home move carries no section {table_id}"))
        })?;
    let identity = |node_id| -> Result<HomeIdentity> {
        Ok(HomeIdentity {
            machine: source.store.clock.entity_id()?,
            node_id,
        })
    };
    let fence = HomeFence::new(HomeMove {
        vault_id: [0; 32],
        source: identity(1)?,
        target: identity(2)?,
        generation: HomeGeneration {
            serial: 1,
            predecessor: None,
        },
        election_basis: [0; 32],
    });
    let exported = table.export(source, &source.store.env.read_txn()?, &fence)?;
    table.check(&exported.facts)?;
    let actors = exported
        .actors
        .into_iter()
        .filter(|(actor, _)| !withheld.contains(actor))
        .map(|(_, content)| content)
        .collect();
    let adopted =
        target.with_write_txn(|txn| table.adopt(target, txn, &fence, &exported.facts, actors))?;
    Ok(adopted == TableAdopt::Applied)
}
