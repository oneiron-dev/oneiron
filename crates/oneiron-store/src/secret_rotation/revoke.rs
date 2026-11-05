//! Revocation: terminal value death everywhere the vault reaches. The
//! record flips `Revoked` and its value at rest is erased (CALLS
//! CUSTODY_REVOKE_ERASE), every lease over its name flips `Revoked` with its
//! T2 file torn down, and a [`RotationKind::Revoked`] receipt lands.

use zeroize::Zeroize;

use crate::secret_record::SecretCustodyRecord;
use crate::secret_record::SecretCustodyStatus;
use crate::secret_record::write_records::StoredValue;
use crate::side_table::key::HexId;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::error::SecretError;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::secret_lease::SecretLeaseStatus;

/// What a revoke erases at rest (CALLS CUSTODY_REVOKE_ERASE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CustodyRevokeErase {
    /// The record's value bytes are wiped and it is put again with an empty
    /// value. Its metadata, its name index and its generation high-water
    /// stay, so its name is reclaimed one generation above. In the same
    /// commit the carrier this install keeps that still seals the value goes
    /// (a revoked carrier, byte-free, replaces it where this install carries
    /// the act) with every input kept for a request on it; its leases are
    /// revoked, value-free, and output digests, receipts and fingerprints
    /// stay. A record the owner ruled no secret keeps its bytes: the
    /// found-key screen reads them, so a later write does not mask that value
    /// again, and the ruling put the value back into its record's body. A
    /// record revoked before this erase gives up the bytes it still holds at
    /// its next settle or revoke (FIX 5272), with no backfill of its own.
    /// Nothing recalls an export, a checkpoint, a delivered copy or history a
    /// store retains: no physical shredding is claimed.
    ValueCarrierInputsExceptRuledNoSecret,
}

const CUSTODY_REVOKE_ERASE: CustodyRevokeErase =
    CustodyRevokeErase::ValueCarrierInputsExceptRuledNoSecret;

/// Why a record is revoked, which decides what of its value stays at rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeCause {
    /// The owner's revoke, or an admitted revoke settled or received here.
    Revoked,
    /// The owner ruled the found key it holds no secret.
    RuledNoSecret,
    /// The owner kept the found key's marked span as text by choice.
    KeptAsText,
}

/// Whether a revoke for `cause` erases the value at rest.
pub fn erases(cause: RevokeCause) -> bool {
    match (CUSTODY_REVOKE_ERASE, cause) {
        (CustodyRevokeErase::ValueCarrierInputsExceptRuledNoSecret, RevokeCause::Revoked) => true,
        (
            CustodyRevokeErase::ValueCarrierInputsExceptRuledNoSecret,
            RevokeCause::RuledNoSecret | RevokeCause::KeptAsText,
        ) => false,
    }
}
