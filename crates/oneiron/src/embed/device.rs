//! Which device and runtime computed a stored vector (ARCH-0036, owner
//! 2026-10-11). One model is one space on every device, so a device move never
//! re-embeds; the device is marked beside each vector instead, so one device's
//! vectors can be found and patched later without a migration. The mark sits
//! outside the space identity and every key or hash that decides it.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ports::RetrievalIndexInventory;
use crate::side_table::{self, Named, SideTable};
use crate::store::ManifestDbs;
use crate::{EntityId, Result, Vault};

/// Who computed the current vector. Key: id16. A vector with no row is
/// [`EmbeddingProvenance::unknown`].
const EMBEDDING_DEVICE: SideTable<EntityId, EmbeddingProvenance, Named> =
    SideTable::new(&side_table::EMBEDDING_DEVICE);

/// The family of device an embedding vector was computed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum EmbeddingDevice {
    Cpu,
    Cuda,
    Metal,
    /// Computed behind an endpoint the vault called; its device is not known
    /// to the vault.
    Remote,
    /// Not recorded: a vector written before provenance was, or one a caller
    /// supplied. A family a later build adds reads as this one.
    #[serde(other)]
    Unknown,
}

impl EmbeddingDevice {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
            Self::Metal => "metal",
            Self::Remote => "remote",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for EmbeddingDevice {
    type Err = String;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        [
            Self::Cpu,
            Self::Cuda,
            Self::Metal,
            Self::Remote,
            Self::Unknown,
        ]
        .into_iter()
        .find(|device| device.as_str() == name)
        .ok_or_else(|| format!("{name:?} is not cpu, cuda, metal, remote or unknown"))
    }
}

/// The device family and runtime that computed a vector: provenance only,
/// never part of the embedding space.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EmbeddingProvenance {
    pub device: EmbeddingDevice,
    /// The runtime's name and version (a local build), or the id of the
    /// endpoint that answered.
    pub runtime: String,
}

impl EmbeddingProvenance {
    #[must_use]
    pub fn new(device: EmbeddingDevice, runtime: impl Into<String>) -> Self {
        Self {
            device,
            runtime: runtime.into(),
        }
    }

    /// What a vector with no record reads as.
    #[must_use]
    pub fn unknown() -> Self {
        Self::new(EmbeddingDevice::Unknown, "unknown")
    }

    fn is_unknown(&self) -> bool {
        self.device == EmbeddingDevice::Unknown
    }
}

/// How many stored vectors one device and runtime computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EmbeddingProvenanceCount {
    pub device: EmbeddingDevice,
    pub runtime: String,
    pub vectors: u64,
}

/// Records who computed the vector just written for `id`, in the same
/// transaction; `None` or an unknown device leaves no row, so a vector a caller
/// supplied never keeps the mark of the one it replaced.
pub(crate) fn record_embedding_device_in_txn(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    provenance: Option<&EmbeddingProvenance>,
) -> Result<()> {
    match provenance.filter(|provenance| !provenance.is_unknown()) {
        Some(provenance) => EMBEDDING_DEVICE.put(store, txn, id, provenance),
        None => EMBEDDING_DEVICE.delete(store, txn, id).map(drop),
    }
}

/// Records in `to` the device `from` records for `id`'s vector: a room that
/// takes base's vector of a row takes the record that describes it.
pub(crate) fn copy_embedding_device_in_txn(
    from: &impl ManifestDbs,
    to: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let provenance = EMBEDDING_DEVICE.get(from, txn, id)?;
    record_embedding_device_in_txn(to, txn, id, provenance.as_ref())
}

/// Drops every row with the vectors they described, when the whole vector
/// table is cleared for a new space.
pub(crate) fn clear_all_embedding_devices_in_txn(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    EMBEDDING_DEVICE.delete_from(store, txn, &[]).map(drop)
}

impl Vault {
    /// Who computed `id`'s stored vector; `None` when it has none. A vector
    /// with no record reads as [`EmbeddingProvenance::unknown`].
    pub fn embedding_provenance(&self, id: &EntityId) -> Result<Option<EmbeddingProvenance>> {
        let txn = self.store.env.read_txn()?;
        if self
            .store
            .port_vector_with_raw(&txn, id, |_| Ok(()))?
            .is_none()
        {
            return Ok(None);
        }
        Ok(Some(
            EMBEDDING_DEVICE
                .get(&self.store, &txn, id)?
                .unwrap_or_else(EmbeddingProvenance::unknown),
        ))
    }

    /// Every stored vector, grouped by the device and runtime that computed
    /// it, in device then runtime order.
    pub fn embedding_provenance_counts(&self) -> Result<Vec<EmbeddingProvenanceCount>> {
        let mut counts = BTreeMap::<EmbeddingProvenance, u64>::new();
        self.for_each_vector_provenance(|_, provenance| {
            *counts.entry(provenance).or_default() += 1;
        })?;
        Ok(counts
            .into_iter()
            .map(|(provenance, vectors)| EmbeddingProvenanceCount {
                device: provenance.device,
                runtime: provenance.runtime,
                vectors,
            })
            .collect())
    }

    /// The ids of the stored vectors `device` computed, under `runtime` when
    /// one is named, in id order: what a later patch re-embeds.
    pub fn vectors_by_provenance(
        &self,
        device: EmbeddingDevice,
        runtime: Option<&str>,
    ) -> Result<Vec<EntityId>> {
        let mut ids = Vec::new();
        self.for_each_vector_provenance(|id, provenance| {
            if provenance.device == device
                && runtime.is_none_or(|runtime| runtime == provenance.runtime)
            {
                ids.push(id);
            }
        })?;
        Ok(ids)
    }

    fn for_each_vector_provenance(
        &self,
        mut visit: impl FnMut(EntityId, EmbeddingProvenance),
    ) -> Result<()> {
        let txn = self.store.env.read_txn()?;
        for id in crate::hnsw::collect_vector_ids(&self.store, &txn)? {
            let provenance = EMBEDDING_DEVICE
                .get(&self.store, &txn, &id)?
                .unwrap_or_else(EmbeddingProvenance::unknown);
            visit(id, provenance);
        }
        Ok(())
    }
}
