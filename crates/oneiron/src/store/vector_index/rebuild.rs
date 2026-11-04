//! Validation of the stored key and vector bytes admitted by a rebuild.

use crate::Vault;
use crate::entity_id::{EntityId, parse_entity_id};
use crate::error::{Error, Result};
use crate::le_bytes_to_f32_vec;

pub(crate) fn validate_rebuild_vector(
    vault: &Vault,
    id_bytes: &[u8],
    vector_bytes: &[u8],
) -> Result<EntityId> {
    let id = parse_entity_id(id_bytes, ERR_VECTOR_KEY)?;
    let vector = le_bytes_to_f32_vec(vector_bytes, vault.config.dimensions)?;
    if vector.len() != vault.config.dimensions {
        return Err(Error::DimensionMismatch {
            expected: vault.config.dimensions,
            got: vector.len(),
        });
    }
    if let Some(error) = Error::invalid_vector_component(&vector) {
        return Err(error);
    }
    Ok(id)
}


const ERR_VECTOR_KEY: &str = "vector key";
