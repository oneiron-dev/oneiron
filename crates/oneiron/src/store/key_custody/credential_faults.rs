//! Core half of `store::key_custody::credential_faults`: its store-layer items live in `oneiron_store::key_custody::credential_faults` and are
//! re-exported here; the items below stay in the engine.

pub(crate) use oneiron_store::key_custody::credential_faults::*;

use super::files::LocalCustody;
use super::head::HeadEntry;
use super::identity::{CustodyId, CustodyKind, CustodySubject};
use crate::error::{Error, Result};

/// `error`, met on `subject`'s keys while doing `what`: absorbed, warned,
/// for a credential's subject or the host issuer seed's; the pass's error
/// for any other.
pub(super) fn forgone(subject: &CustodySubject, error: Error, what: &'static str) -> Result<()> {
    // The escrow is best-effort (FIX-LIST 10770): the seed stays in this
    // machine's custody for the pass, and its install's slot keeps it.
    if subject.kind() == CustodyKind::HostIssuerSeed {
        tracing::warn!(
            kind = ?error.kind(),
            "the host issuer seed's custody entries stay where they are for this pass: {what}"
        );
        return Ok(());
    }
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
        "the custody keys stay where they are for this pass: {what}"
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
