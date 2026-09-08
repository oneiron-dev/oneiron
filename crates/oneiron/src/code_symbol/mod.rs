mod codec;
mod keys;
mod rust_source;
mod storage;
mod text_diff;
mod types;
mod validate;

pub use self::codec::{
    CODE_SYMBOL_CHUNK_KEYS, CODE_SYMBOL_ENTITY_BODY_KEYS, CODE_SYMBOL_MANIFEST_BODY_KEYS,
    CODE_SYMBOL_REVISION_KEYS, decode_code_symbol_manifest, encode_code_symbol_manifest,
};
pub use self::keys::{code_symbol_entity_id, derive_symbol_fingerprint};
pub use self::rust_source::derive_code_symbol_graph_from_sources;
pub use self::storage::apply_code_symbol_anchor_transfer;
pub use self::text_diff::{
    derive_code_chunks_from_text_diff, derive_code_embedding_inputs_from_text_diff,
    embed_code_chunks,
};
pub use self::types::{
    CODE_SYMBOL_FINGERPRINT_LEN, CODE_SYMBOL_KIND_MAX_BYTES, CODE_SYMBOL_MANIFEST_MAX_CHUNKS,
    CODE_SYMBOL_MANIFEST_MAX_SYMBOLS, CODE_SYMBOL_NAME_MAX_BYTES,
    CODE_SYMBOL_SOURCE_SESSION_MAX_BYTES, CODE_SYMBOL_TEXT_HASH_LEN, CodeChunk, CodeEmbeddingInput,
    CodeEmbeddingVector, CodeSymbolBlame, CodeSymbolDefinition, CodeSymbolGraph,
    CodeSymbolGraphEdge, CodeSymbolManifest, CodeSymbolRevision, CodeSymbolSource,
};

#[cfg(test)]
pub(crate) use self::storage::delete_code_symbol_manifest_in_txn;

// The flat code_symbol.rs module used to provide these names to the sibling test
// module through `use super::*`: every code_symbol-internal item the tests name
// bare. After the directory split the seam re-imports them so `tests.rs`
// resolves exactly as it did before.
#[cfg(test)]
use self::{codec::*, keys::*};
#[cfg(test)]
use crate::code_artifact::decode_code_artifact_body;
#[cfg(test)]
use crate::codebase::RepoRef;
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::pipeline::ScoredEntity;

#[cfg(test)]
mod tests;
