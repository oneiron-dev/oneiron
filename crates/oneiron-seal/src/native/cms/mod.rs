//! CMS/CAdES SignedData assembly and parsing with exact byte control (§7.3).
//!
//! Hand-assembled DER (GATE-1 amendment A3: the `cms` crate's builder feature
//! is deliberately unused) so the PAdES signed-attribute set, the RFC 5652
//! §5.4 universal-SET signature input, and DER canonicality checks are under
//! this crate's direct control.

mod assemble;
mod der;
mod oids;
mod parse;
mod policy;
#[cfg(test)]
mod tests;

use crate::error::{FatalCode, SealError, SealStage};

pub(super) fn cms_err() -> SealError {
    SealError::Fatal {
        stage: SealStage::CmsAssembly,
        code: FatalCode::CmsEncodingFailed,
    }
}

pub(crate) use self::assemble::{
    SignerMaterial, assemble_signed_attrs, attr_content_type_data, attr_message_digest,
    attr_signing_cert_v2, attr_ts_token, build_signed_data, issuer_and_serial,
};
pub(crate) use self::der::{DerReader, oid_tlv, sha256, tlv};
pub(crate) use self::oids::{
    OID_ATTR_CONTENT_TYPE, OID_ATTR_MESSAGE_DIGEST, OID_ATTR_SIGNING_CERT_V2, OID_ATTR_TS_TOKEN,
    OID_DATA, OID_SHA256, OID_SIGNED_DATA,
};
pub(crate) use self::parse::{
    ParsedCms, ParsedSignerInfo, parse_cms, signed_attrs_signature_input,
};
pub(crate) use self::policy::{
    cert_signature_algorithm, check_baseline_attrs, check_ess_binding, is_sha256_oid,
    parse_attribute, sig_alg_permitted, verify_signature_value,
};
// Re-exports only test code names (bare via `use super::*` in tests.rs,
// or via `cms::` paths in `#[cfg(test)]` fixture modules elsewhere).
#[cfg(test)]
pub(crate) use self::oids::{OID_CT_TST_INFO, OID_ECDSA_SHA256, OID_RSA_PSS, OID_SHA256_WITH_RSA};

// The flat cms.rs module provided these names to the sibling test module
// through `use super::*`: the one private helper the tests name bare.
// After the directory split the seam re-imports it so `tests.rs` resolves
// exactly as it did before.
#[cfg(test)]
use self::der::alg_id;
