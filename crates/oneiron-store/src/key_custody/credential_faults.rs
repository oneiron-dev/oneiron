//! A credential's keys in the passes every custody client shares (KS-6,
//! FIX-LIST 5687 part 1): a head's publication, the census and a fork.
//!
//! Those passes ran before any credential key existed, so a fault reading,
//! listing or copying one never stops them (CALLS `KS-6 credential pass
//! faults`): it is warned by the credential's id and the error's kind, never
//! a byte, and the custody keys stay where they are for the pass. A
//! head then carries none of them, so they stay in this machine's custody,
//! where every credential's stayed before, and the next head sealed reads
//! them again. A fork leaves one it cannot copy behind: the copy's row then
//! answers the typed `credential_leaf_unreadable` when it is opened (its
//! pending diagnostic), and the activation or restore goes on as it did.
//! A connector call's resume key (FIX 9157) goes the same way, and so does
//! the host issuer seed's escrow (FIX-LIST 10770), warned by the error's kind
//! alone. Every other kind's fault is the pass's own, exactly as before.

use oneiron_base::error::Error;
use oneiron_base::error::Result;

use crate::key_custody::identity::CustodyId;
use crate::key_custody::identity::CustodyKind;
use crate::key_custody::identity::CustodySubject;

/// What a shared pass does with a credential key's own fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyCredentialPassFault {
    /// Warned by key and kind; the credential's keys stay put for the pass.
    WarnAndKeepLocal,
}

pub const CUSTODY_CREDENTIAL_PASS_FAULT: CustodyCredentialPassFault =
    CustodyCredentialPassFault::WarnAndKeepLocal;
