//! Ownership of one current dependency-index registration.

use super::{SourceSpan, TombstoneStoreRead};
use crate::EntityId;
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::store::ManifestDbs;
use heed::{RoTxn, RwTxn};
use std::collections::BTreeSet;

#[derive(Default)]
struct Causes {
    ordinary: bool,
    forks: BTreeSet<EntityId>,
}

impl Causes {
    // One ordinary-registration byte, followed by exact fork identities.
    fn decode(raw: &[u8]) -> Result<Self> {
        let (ordinary, forks) = raw
            .split_first()
            .ok_or(Error::CorruptedIndex("dependency registration causes"))?;
        if *ordinary > 1 || forks.len() % 16 != 0 {
            return Err(Error::CorruptedIndex("dependency registration causes"));
        }
        let mut result = Self {
            ordinary: *ordinary == 1,
            forks: BTreeSet::new(),
        };
        for fork in forks.chunks_exact(16) {
            let id = EntityId::from_bytes(
                fork.try_into()
                    .map_err(|_| Error::CorruptedIndex("dependency fork cause"))?,
            )?;
            if !result.forks.insert(id) {
                return Err(Error::CorruptedIndex("duplicate dependency fork cause"));
            }
        }
        if result.is_empty() {
            return Err(Error::CorruptedIndex("empty dependency registration"));
        }
        Ok(result)
    }

    fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(1 + self.forks.len() * 16);
        raw.push(u8::from(self.ordinary));
        for fork in &self.forks {
            raw.extend_from_slice(fork.as_bytes());
        }
        raw
    }

    fn is_empty(&self) -> bool {
        !self.ordinary && self.forks.is_empty()
    }
}

fn keys(source: SourceSpan, dependent: &EntityId) -> (Vec<u8>, Vec<u8>) {
    let forward = [
        super::integrity::source_prefix(source).as_slice(),
        dependent.as_bytes(),
    ]
    .concat();
    let reverse = [
        super::regeneration::reverse_prefix(dependent).as_slice(),
        source.document.as_bytes(),
        &source.frontier.to_be_bytes(),
    ]
    .concat();
    (forward, reverse)
}

pub(super) fn record(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    source: SourceSpan,
    dependent: &EntityId,
    fork: Option<EntityId>,
) -> Result<()> {
    if source.document == *dependent {
        return Err(Error::InvariantViolation("self dependency"));
    }
    let visibility = store.port_deletion_state(txn, &source.document)?;
    if visibility.deleted || visibility.stale {
        return Err(Error::EntityNotFound);
    }
    let (forward, reverse) = keys(source, dependent);
    let admitted = store.vault_meta().get(txn, &forward)?.is_none();
    let mut causes = match store.vault_meta().get(txn, &reverse)? {
        Some(raw) => Causes::decode(&raw)?,
        None if admitted => Causes::default(),
        None => return Err(Error::CorruptedIndex("dependency registration pair")),
    };
    match fork {
        Some(fork) => {
            causes.forks.insert(fork);
        }
        None => causes.ordinary = true,
    }
    store.vault_meta().put(txn, &forward, &[])?;
    store.vault_meta().put(txn, &reverse, &causes.encode())?;
    if admitted {
        super::dependent_walk::settle_admitted_in_txn(store, txn, source, dependent)?;
    }
    Ok(())
}

/// Registers this exact generated fork without claiming an ordinary registration.
pub(crate) fn record_fork_dependency_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    dependent: &EntityId,
    source: &EntityId,
    fork: &EntityId,
) -> Result<()> {
    let raw = store
        .entities()
        .get(txn, source.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("dependency source header"))?;
    record(
        store,
        txn,
        SourceSpan {
            document: *source,
            frontier: header.learned_at,
        },
        dependent,
        Some(*fork),
    )
}

/// Retires only this fork's registrations, including superseded source versions.
/// Ordinary registrations and registrations owned by other forks remain.
pub(crate) fn remove_fork_dependencies_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    dependent: &EntityId,
    fork: &EntityId,
) -> Result<()> {
    for source in super::regeneration::sources_of(store, txn, dependent)? {
        let (forward, reverse) = keys(source, dependent);
        let mut causes = Causes::decode(
            &store
                .vault_meta()
                .get(txn, &reverse)?
                .ok_or(Error::CorruptedIndex("dependency registration pair"))?,
        )?;
        if !causes.forks.remove(fork) {
            continue;
        }
        if causes.is_empty() {
            store.vault_meta().delete(txn, &reverse)?;
            store.vault_meta().delete(txn, &forward)?;
        } else {
            store.vault_meta().put(txn, &reverse, &causes.encode())?;
        }
    }
    Ok(())
}
