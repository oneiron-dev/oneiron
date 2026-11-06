//! File-backed expected widen bytes, compared before taking the acting writer.

use std::io::Read;

use super::{AuthenticatedOwner, ConsentReceipt, VerifiedSlip, validate_reference_shape};
use crate::{Result, Vault};

const COMPARE_CHUNK_BYTES: usize = 64 * 1024;

impl Vault {
    /// Declines a widen whose reference was decoded into a file. Credential
    /// validation still precedes the reference's existing hex64 shape.
    pub fn reject_widen_reader(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        mut reference: impl Read,
        reference_len: u64,
    ) -> Result<ConsentReceipt> {
        if let Some(credential) = credential {
            self.require_widen_holder_credential(owner, credential)?;
        }
        let mut bytes = [0; 64];
        if reference_len != bytes.len() as u64 {
            return Err(super::invalid_row());
        }
        reference.read_exact(&mut bytes)?;
        if reference.read(&mut [0; 1])? != 0 {
            return Err(super::invalid_row());
        }
        let reference = std::str::from_utf8(&bytes).map_err(|_| super::invalid_row())?;
        self.reject_widen_checked(owner, credential, reference)
    }

    /// Answers a widen whose JSON reference and delta were both streamed.
    /// The holder credential is checked before the reference's existing
    /// hex64 shape; no caller-sized reference string is materialized.
    pub fn accept_widen_readers(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        mut reference: impl Read,
        reference_len: u64,
        expected: impl Read,
        expected_len: u64,
    ) -> Result<ConsentReceipt> {
        if let Some(credential) = credential {
            self.require_widen_holder_credential(owner, credential)?;
        }
        let mut bytes = [0; 64];
        if reference_len != bytes.len() as u64 {
            return Err(super::invalid_row());
        }
        reference.read_exact(&mut bytes)?;
        if reference.read(&mut [0; 1])? != 0 {
            return Err(super::invalid_row());
        }
        let reference = std::str::from_utf8(&bytes).map_err(|_| super::invalid_row())?;
        validate_reference_shape(reference)?;
        self.accept_widen_reader(owner, credential, reference, expected, expected_len)
    }

    /// Answers a widen with incrementally decoded bytes. File reads happen
    /// outside every transaction; the acting writer rechecks the same frozen
    /// bytes, owner, holder credential, expiry and unresolved state.
    pub fn accept_widen_reader(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: &str,
        mut expected: impl Read,
        expected_len: u64,
    ) -> Result<ConsentReceipt> {
        if let Some(credential) = credential {
            self.require_widen_holder_credential(owner, credential)?;
        }
        validate_reference_shape(reference)?;
        let canonical = {
            let txn = self.store.env.read_txn()?;
            self.owned_widen_row_in_txn(&txn, owner, credential, reference)?
                .proposal
                .canonical_delta
        };
        let mut equal = expected_len == canonical.len() as u64;
        if equal {
            let mut buffer = [0; COMPARE_CHUNK_BYTES];
            for part in canonical.chunks(COMPARE_CHUNK_BYTES) {
                expected.read_exact(&mut buffer[..part.len()])?;
                if &buffer[..part.len()] != part {
                    equal = false;
                    break;
                }
            }
            if equal {
                equal = expected.read(&mut buffer[..1])? == 0;
            }
        }
        self.accept_widen_matching(owner, credential, reference, |current| {
            equal && current == canonical
        })
    }
}
