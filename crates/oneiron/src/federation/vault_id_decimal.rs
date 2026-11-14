//! A shared vault's id on the wire (OF-158): a decimal string, since a `u64`
//! past 2^53 does not survive a JavaScript number. Rust keeps the `u64`.
//!
//! `#[serde(with = "crate::federation::vault_id_decimal")]` on every field
//! that carries the id, beside `#[schemars(with = "String")]` where the type
//! derives a schema; the SDK generator's type inventory reads a `decimal` codec
//! as a string, so the generated TypeScript, Python and UniFFI types say so too.

#[doc(hidden)]
pub(crate) use oneiron_verb_wire::federation::vault_id_decimal::{deserialize, serialize};
