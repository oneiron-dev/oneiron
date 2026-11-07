//! File-backed expected widen bytes, compared before taking the acting writer.

use std::io::Read;

use super::{
    AuthenticatedOwner, ConsentReceipt, StoredProposal, VerifiedSlip, WIDEN_PROPOSALS,
    validate_reference_shape,
};
use crate::host_memory::{MachineMemory, MemoryLease, MemoryRefusal};
use crate::{Result, Vault};

const COMPARE_CHUNK_BYTES: usize = 64 * 1024;

struct CanonicalRead {
    row: StoredProposal,
    _memory: MemoryLease,
}

enum CanonicalPlan {
    Read(StoredProposal),
    Grew(u64),
}

// serde_json's fresh Vec<u8> has no sequence size hint. Rust 1.96 grows
// its payload 0 -> 8 -> 16 -> ...; a reallocation can hold old + new.
// Each pushed JSON number needs at least two source bytes, including its
// opening bracket or preceding comma, even when a later parse fails.
fn canonical_payload_peak(stored_len: usize) -> u64 {
    let elements = stored_len / 2;
    if elements == 0 {
        return 0;
    }
    let capacity = elements.max(8).next_power_of_two() as u64;
    if capacity == 8 {
        capacity
    } else {
        capacity + capacity / 2
    }
}

fn read_widen_reference(
    mut reference: impl Read,
    reference_len: u64,
    bytes: &mut [u8; 64],
) -> Result<&str> {
    if reference_len != bytes.len() as u64 {
        return Err(super::invalid_row());
    }
    reference.read_exact(bytes)?;
    if reference.read(&mut [0; 1])? != 0 {
        return Err(super::invalid_row());
    }
    std::str::from_utf8(bytes).map_err(|_| super::invalid_row())
}

fn widen_reader_matches(
    canonical: &[u8],
    mut expected: impl Read,
    expected_len: u64,
) -> Result<bool> {
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
    Ok(equal)
}

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
        reference: impl Read,
        reference_len: u64,
        expected: impl Read,
        expected_len: u64,
    ) -> Result<ConsentReceipt> {
        if let Some(credential) = credential {
            self.require_widen_holder_credential(owner, credential)?;
        }
        let mut bytes = [0; 64];
        let reference = read_widen_reference(reference, reference_len, &mut bytes)?;
        validate_reference_shape(reference)?;
        self.accept_widen_reader(owner, credential, reference, expected, expected_len)
    }

    /// The streamed accept with an allowance for the first stored canonical
    /// byte vector's payload and growth. Blocks on the shared process line;
    /// call from a dedicated worker, without transactions or memory leases.
    /// `stopped` ends a queued wait. Other native errors remain the inner
    /// result. An unchanged stored row reuses this decoded payload in the
    /// writer. Changed-row fallback payloads, row metadata and validation
    /// trees are not covered by this allowance.
    pub fn accept_widen_readers_admitted(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: impl Read,
        reference_len: u64,
        expected: impl Read,
        expected_len: u64,
        stopped: &dyn Fn() -> bool,
    ) -> std::result::Result<Result<ConsentReceipt>, MemoryRefusal> {
        let mut bytes = [0; 64];
        let checked = (|| {
            if let Some(credential) = credential {
                self.require_widen_holder_credential(owner, credential)?;
            }
            let reference = read_widen_reference(reference, reference_len, &mut bytes)?;
            validate_reference_shape(reference)?;
            Ok(reference)
        })();
        let reference = match checked {
            Ok(reference) => reference,
            Err(error) => return Ok(Err(error)),
        };
        let canonical =
            match self.admitted_widen_canonical(owner, credential, reference, stopped)? {
                Ok(canonical) => canonical,
                Err(error) => return Ok(Err(error)),
            };
        Ok(self.accept_widen_admitted_canonical_reader(
            owner,
            credential,
            reference,
            canonical,
            expected,
            expected_len,
        ))
    }

    fn accept_widen_admitted_canonical_reader(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: &str,
        mut canonical: CanonicalRead,
        expected: impl Read,
        expected_len: u64,
    ) -> Result<ConsentReceipt> {
        let equal = widen_reader_matches(
            &canonical.row.proposal.canonical_delta,
            expected,
            expected_len,
        )?;
        self.accept_widen_matching_reusing(
            owner,
            credential,
            reference,
            Some(&mut canonical.row),
            |_| equal,
        )
    }

    fn widen_canonical_peak_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: &str,
    ) -> Result<u64> {
        self.widen_answer_principal_in_txn(txn, owner, credential)?;
        let raw = WIDEN_PROPOSALS
            .get_borrowed(&self.store, txn, &reference.to_owned())?
            .ok_or_else(super::invalid_row)?;
        Ok(canonical_payload_peak(raw.len()))
    }

    fn admitted_widen_canonical(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: &str,
        stopped: &dyn Fn() -> bool,
    ) -> std::result::Result<Result<CanonicalRead>, MemoryRefusal> {
        let planned = (|| {
            if let Some(credential) = credential {
                self.require_widen_holder_credential(owner, credential)?;
            }
            validate_reference_shape(reference)?;
            let txn = self.store.env.read_txn()?;
            self.widen_canonical_peak_in_txn(&txn, owner, credential, reference)
        })();
        let mut budget = match planned {
            Ok(budget) => budget,
            Err(error) => return Ok(Err(error)),
        };
        loop {
            let mut memory = MachineMemory::process().lease_untimed(budget, stopped)?;
            let decoded = (|| {
                let txn = self.store.env.read_txn()?;
                let needed =
                    self.widen_canonical_peak_in_txn(&txn, owner, credential, reference)?;
                if needed > budget {
                    return Ok(CanonicalPlan::Grew(needed));
                }
                let row = self.owned_widen_row_in_txn(&txn, owner, credential, reference)?;
                Ok(CanonicalPlan::Read(row))
            })();
            match decoded {
                Err(error) => return Ok(Err(error)),
                Ok(CanonicalPlan::Grew(needed)) => {
                    // The transaction and raw borrow have ended. Release the
                    // entire old allowance before joining the line again;
                    // expected has not been read, so no rewind is needed.
                    drop(memory);
                    budget = needed;
                }
                Ok(CanonicalPlan::Read(row)) => {
                    memory.materialized(budget, row.proposal.canonical_delta.capacity() as u64);
                    return Ok(Ok(CanonicalRead {
                        row,
                        _memory: memory,
                    }));
                }
            }
        }
    }

    /// Answers a widen with incrementally decoded bytes. File reads happen
    /// outside every transaction; the acting writer rechecks the same frozen
    /// bytes, owner, holder credential, expiry and unresolved state.
    pub fn accept_widen_reader(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: &str,
        expected: impl Read,
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
        self.accept_widen_canonical_reader(
            owner,
            credential,
            reference,
            &canonical,
            expected,
            expected_len,
        )
    }

    fn accept_widen_canonical_reader(
        &self,
        owner: &AuthenticatedOwner,
        credential: Option<&VerifiedSlip>,
        reference: &str,
        canonical: &[u8],
        expected: impl Read,
        expected_len: u64,
    ) -> Result<ConsentReceipt> {
        let equal = widen_reader_matches(canonical, expected, expected_len)?;
        self.accept_widen_matching(owner, credential, reference, |current| {
            equal && current == canonical
        })
    }
}
