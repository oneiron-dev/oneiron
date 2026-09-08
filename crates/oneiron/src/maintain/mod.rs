mod attempt_lease;
mod builder;
mod hnsw_rebuild;
mod short_ids;
mod text_ops;

pub use self::builder::{MaintenanceBuilder, MaintenanceReport};
pub(crate) use self::hnsw_rebuild::{rebuild_hnsw_if_dropped, validate_rebuild_vector};

#[cfg(test)]
mod tests;

#[cfg(test)]
use self::hnsw_rebuild::*;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::batch::{ENTITY_METADATA_HEADER_LEN, encode_short_id_forward_key, parse_short_id_value};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::hnsw::{COUNT_KEY, LinkDiscipline, build_hnsw_graph_from_snapshot};
#[cfg(test)]
use xxhash_rust::xxh32::xxh32;
