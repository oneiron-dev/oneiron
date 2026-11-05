//! The one store of exact publish requests (`ORIGIN_PUBLISH_REQUEST`, LIVE):
//! each request's row and, beside it, the pages of its review. A request
//! changes only by a compare-and-set on its state in one write transaction,
//! so two callers can never both take its one dispatch. An actor's erase
//! scrubs every act that names it and keeps the rest of the record; a
//! request row that does not decode is dropped there instead, never an
//! abort of the erase or restore.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// The domain of a request id an idempotency key fixes.
const ORIGIN_PUBLISH_REQUEST_ID_DOMAIN: &[u8] = b"oneiron:origin-publish-request:v1";

/// The longest idempotency key, in bytes.
pub const ORIGIN_PUBLISH_MAX_KEY_BYTES: usize = 128;

/// The WARN code of a request row an actor scrub dropped because it does
/// not decode (CALLS "FIX 6866 undecodable request on scrub").
pub const ORIGIN_PUBLISH_REQUEST_UNDECODABLE_DROPPED: &str =
    "origin_publish_request_undecodable_dropped";

/// Repo id, request id, then nothing for the request or a u64be page.
pub type PublishKey = (EntityId, EntityId, Vec<u8>);

pub fn request_key(repo_id: EntityId, request_id: EntityId) -> PublishKey {
    (repo_id, request_id, Vec::new())
}

pub fn page_key(repo_id: EntityId, request_id: EntityId, page: u64) -> PublishKey {
    (repo_id, request_id, page.to_be_bytes().to_vec())
}

/// The request id `key` fixes for one repository.
pub fn keyed_request_id(repo_id: &EntityId, key: &str) -> Result<EntityId> {
    crate::code_snapshot::ids::entity_id_from_hash_material(
        ORIGIN_PUBLISH_REQUEST_ID_DOMAIN,
        &[repo_id.as_bytes(), key.as_bytes()],
    )
}
