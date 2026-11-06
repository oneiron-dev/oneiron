//! A result body read as it streams (FIX 3677 step 7, FIX 5392): the
//! reader the export snapshot carries, and where its bytes are. The code
//! run layer (`code_run::storage::records::bodies::reader`) opens it under a
//! read transaction and copies it checked against the body's length and
//! BLAKE3; the export snapshot holds one per clean result body.
use crate::result_body::ResultBodyPin;
use crate::store::BodyFile;

/// One result body as it streams ([`Vault::code_run_result_body_reader_in_txn`](crate::Vault::code_run_result_body_reader_in_txn)):
/// read once, through [`Self::copy_checked`].
pub(crate) struct CodeRunResultBodyReader<'t> {
    pub(crate) source: Source<'t>,
    pub(crate) len: u64,
    pub(crate) digest: [u8; 32],
    pub(crate) _pin: ResultBodyPin,
}

/// Where a streamed body's bytes are: its row, lent by the read
/// transaction (its tag first), or its file.
pub(crate) enum Source<'t> {
    Inline(std::borrow::Cow<'t, [u8]>),
    File(BodyFile),
}
