//! What a test hands the hostile seal organ's evidence modes (feature
//! `hostile-organ-tests`): a timestamp authority it may mint tokens with, the
//! CRL its fetcher serves, and the validation material a mode appends by
//! hand. Keys and certificates are synthetic, made fresh by rcgen in each
//! test, and never leave the test's own processes. The fixture crosses as the
//! organ's fourth argument, hex of its MessagePack; both sides include this
//! one definition.

use oneiron_organ_protocol::ByteBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EvidenceFixture {
    /// The trusted timestamp authority: its P-256 secret scalar, and its
    /// certificate, issued under the test's anchor with a critical, sole
    /// id-kp-timeStamping EKU.
    pub(crate) tsa_key: ByteBuf,
    pub(crate) tsa_certificate: ByteBuf,
    /// A timestamp authority of the same shape that no anchor reaches.
    pub(crate) untrusted_tsa_key: ByteBuf,
    pub(crate) untrusted_tsa_certificate: ByteBuf,
    /// The fetcher's answer to every CRL request: the anchor's own CRL.
    pub(crate) crl: ByteBuf,
    /// What a mode that appends its own DSS revision writes in it.
    pub(crate) dss_certificates: Vec<ByteBuf>,
    pub(crate) dss_crls: Vec<ByteBuf>,
    pub(crate) dss_ocsps: Vec<ByteBuf>,
}
