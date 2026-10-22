//! A credential's keys in the passes every custody client shares (KS-6,
//! FIX-LIST 5687 part 1): a head's publication, the census and a fork.
//!
//! Those passes ran before any credential key existed, so a fault reading,
//! listing or copying one never stops them (CALLS `KS-6 credential pass
//! faults`): it is warned by the credential's id and the error's kind, never
//! a byte, and that credential's keys stay where they are for the pass. A
//! head then carries none of them, so they stay in this machine's custody,
//! where every credential's stayed before, and the next head sealed reads
//! them again. A fork leaves one it cannot copy behind: the copy's row then
//! answers the typed `credential_leaf_unreadable` when it is opened (its
//! pending diagnostic), and the activation or restore goes on as it did.
//! A connector call's resume key (FIX 9157) goes the same way. Every other
//! kind's fault is the pass's own, exactly as before.

use crate::error::{Error, Result};

use super::files::LocalCustody;
use super::head::HeadEntry;
use super::identity::{CustodyId, CustodySubject};

/// What a shared pass does with a credential key's own fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyCredentialPassFault {
    /// Warned by key and kind; the credential's keys stay put for the pass.
    WarnAndKeepLocal,
}

const CUSTODY_CREDENTIAL_PASS_FAULT: CustodyCredentialPassFault =
    CustodyCredentialPassFault::WarnAndKeepLocal;

/// `error`, met on `subject`'s keys while doing `what`: absorbed, warned,
/// for a credential's subject; the pass's error for any other.
pub(super) fn forgone(subject: &CustodySubject, error: Error, what: &'static str) -> Result<()> {
    if !crate::store::credential_kind(subject.kind()) {
        return Err(error);
    }
    match CUSTODY_CREDENTIAL_PASS_FAULT {
        CustodyCredentialPassFault::WarnAndKeepLocal => {}
    }
    let credential = subject
        .item()
        .get(..16)
        .map(crate::entity_id::bytes_to_hex_lower)
        .unwrap_or_default();
    tracing::warn!(
        credential = %credential,
        kind = ?error.kind(),
        "a credential's custody keys stay where they are for this pass: {what}"
    );
    Ok(())
}

/// The head entry of live `id`: its key as custody holds it, or none for a
/// credential's key that does not read, kept local for this pass.
pub(super) fn head_entry(custody: &LocalCustody<'_>, id: &CustodyId) -> Result<Option<HeadEntry>> {
    match custody.read(id) {
        Ok(secret) => Ok(Some(HeadEntry {
            secret,
            id: id.clone(),
        })),
        Err(error) => {
            forgone(id.subject(), error, "its key did not read for a head").map(|()| None)
        }
    }
}

/// `step`, one write a fork makes for `id`: a credential's that fails
/// leaves that key behind, warned.
pub(super) fn fork_step(id: &CustodyId, step: Result<()>) -> Result<()> {
    match step {
        Err(error) => forgone(id.subject(), error, "a fork could not copy its key"),
        done => done,
    }
}
