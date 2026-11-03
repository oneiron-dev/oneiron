//! MessagePack codec and validators for diagnostic event bodies, refs, and tokens.
pub use crate::store::diagnostic_record::diagnostic_codec::{
    encode_diagnostic_event_body, decode_diagnostic_event_body,
};
pub(super) use crate::store::diagnostic_record::diagnostic_codec::{
    validate_diagnostic_event_body_bytes, validate_stored_diagnostic_event_body_bytes, decode_str, validate_ref, validate_token,
};
