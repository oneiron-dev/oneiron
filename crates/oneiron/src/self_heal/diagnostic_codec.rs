//! MessagePack codec and validators for diagnostic event bodies, refs, and tokens.
pub use crate::store::diagnostic_record::diagnostic_codec::{
    decode_diagnostic_event_body, encode_diagnostic_event_body,
};
pub(super) use crate::store::diagnostic_record::diagnostic_codec::{
    decode_str, validate_diagnostic_event_body_bytes, validate_ref,
    validate_stored_diagnostic_event_body_bytes, validate_token,
};
