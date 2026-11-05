//! The AGENT_DEF body codec's old paths: the codec lives in
//! `store::agent_definition_codec`, the legacy `sys.*` row map in
//! `store::agent_manifest`.

pub use crate::store::agent_definition_codec::{decode_agent_definition, encode_agent_definition};
pub(crate) use crate::store::agent_definition_codec::{
    validate_agent_definition_bytes, validate_agent_definition_update,
};
pub(crate) use crate::store::agent_manifest::legacy_logical_id_row;
