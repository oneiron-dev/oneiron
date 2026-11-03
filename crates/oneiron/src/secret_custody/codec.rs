//! Custody body codecs, defined with the store-layer record vocabulary.

pub(super) use crate::secret_record::codec::{
    BodyValue, EFFECTOR_MAX_BYTES, SECRET_CUSTODY_SEALED_VALUE_KEY, decode_bind_input,
    decode_custody_map, decode_register_input, encode_bind_input, encode_custody_map,
    encode_register_input, invalid_body,
};
pub(crate) use crate::secret_record::codec::{CUSTODY_SEAL_REASON, reject_secret_custody_byte};
pub use crate::secret_record::codec::{decode_secret_custody_body, encode_secret_custody_body};
