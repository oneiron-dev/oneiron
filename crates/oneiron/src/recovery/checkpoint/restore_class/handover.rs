//! A checkpoint restore across a shared-vault owner handover (FIX 5765): the
//! exact rows a valid `OwnerHandover` names restore as the live vault holds
//! them, so the restore proceeds, the demotion stays in force and demoted
//! authority never comes back. The FEDERATION_GRANT rows it wrote, bodies and
//! shells, and the shells of the own-device grants it retired; and the five
//! shared-act families of the act and receipt it signed, each by its exact
//! canonical key, with the row's own act or receipt id, recipient and vault
//! matching. The image's pre-execution act record is one of them. Every other
//! membership, erase ask, creation, deletion and invitation row keeps its
//! class, and so does every row no valid handover names: a change no signed
//! handover proves still refuses as before.

use serde::Deserialize;

use super::{Class, LIVE};
use crate::EntityId;
use crate::authority::HandoverEvidence;
use crate::side_table as t;

/// The class of a FEDERATION_GRANT row a valid handover wrote or retired
/// (CALLS `FIX 5765 restore classes`): the live vault's.
pub(super) const HANDOVER_GRANT_RESTORE_CLASS: Class = LIVE;
/// The class of a shared-act row of the act or receipt a valid handover
/// signed (same CALLS row): the live vault's.
pub(super) const HANDOVER_ACT_RESTORE_CLASS: Class = LIVE;

/// What a restore does with a row no valid handover names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnprovenRestore {
    /// Its own class stands: a membership row that changed refuses.
    RefuseIfChanged,
}

/// The one rule for unproven rows (CALLS `FIX 5765 restore classes`).
pub(super) const HANDOVER_UNPROVEN_RESTORE: UnprovenRestore = UnprovenRestore::RefuseIfChanged;

/// What a restore does when the handover evidence does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EvidenceReadFailure {
    /// No row gains a class: every default stands.
    NoNewExemptions,
}

/// The one rule for a failed evidence read (CALLS `FIX 5765 evidence rule`).
pub(super) const HANDOVER_EVIDENCE_READ_FAILURE: EvidenceReadFailure =
    EvidenceReadFailure::NoNewExemptions;

/// The ids a shared-act row's stored body names, read alone.
#[derive(Deserialize)]
struct ActRowIds {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    act_id: Option<String>,
    #[serde(default)]
    receipt_id: Option<String>,
    #[serde(default)]
    recipient: Option<String>,
    #[serde(deserialize_with = "crate::federation::vault_id_decimal::deserialize")]
    vault_id: u64,
}

/// The handover evidence a restore classes rows by.
#[derive(Debug, Default)]
pub(super) struct HandoverRows {
    evidence: HandoverEvidence,
}

impl HandoverRows {
    /// The live vault's evidence; a read that fails adds no exemption
    /// ([`HANDOVER_EVIDENCE_READ_FAILURE`]).
    pub(super) fn read(current: &crate::Vault, txn: &heed::RoTxn<'_>) -> Self {
        match current.owner_handover_evidence_in_txn(txn) {
            Ok(evidence) => Self { evidence },
            Err(error) => match HANDOVER_EVIDENCE_READ_FAILURE {
                EvidenceReadFailure::NoNewExemptions => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "the owner handover evidence did not read; no row restores live by it"
                    );
                    Self::default()
                }
            },
        }
    }

    /// The class of FEDERATION_GRANT row `key`, a shell when `bodyless`,
    /// when a valid handover names it.
    pub(super) fn grant_class(&self, key: &[u8], bodyless: bool) -> Option<Class> {
        let id = EntityId::from_bytes(<[u8; 16]>::try_from(key).ok()?).ok()?;
        let named = self.evidence.affected_grants.contains(&id)
            || (bodyless && self.evidence.retired_own_device_grants.contains(&id));
        match HANDOVER_UNPROVEN_RESTORE {
            UnprovenRestore::RefuseIfChanged => named.then_some(HANDOVER_GRANT_RESTORE_CLASS),
        }
    }

    /// The class of `vault_meta` row `key` under the family declared at
    /// `prefix`, holding `value`, when it is one of the five shared-act rows
    /// of an act or receipt a valid handover signed.
    pub(super) fn act_class(&self, prefix: &[u8], key: &[u8], value: &[u8]) -> Option<Class> {
        let by_act = prefix == t::SHARED_ACT_RECORD.prefix
            || prefix == t::SHARED_ACT_EVENT.prefix
            || prefix == t::SHARED_ACT_MATURED.prefix;
        let by_receipt =
            prefix == t::SHARED_ACT_RECEIPT.prefix || prefix == t::SHARED_ACT_OUTCOME.prefix;
        if !(by_act || by_receipt) {
            return None;
        }
        let suffix = std::str::from_utf8(key.strip_prefix(prefix)?).ok()?;
        // A record or receipt is keyed by its id alone, a notice by its
        // recipient and then the id.
        let (recipient, id) =
            if prefix == t::SHARED_ACT_RECORD.prefix || prefix == t::SHARED_ACT_RECEIPT.prefix {
                (None, suffix)
            } else {
                let (recipient, id) = suffix.split_once(':')?;
                (Some(recipient), id)
            };
        // Exact canonical keys only: each id in the key is a 32-hex entity id
        // that round-trips; any other key keeps its class.
        if !canonical_id(id) || !recipient.is_none_or(canonical_id) {
            return None;
        }
        let signed = if by_act {
            self.evidence.acts.get(id)
        } else {
            self.evidence.receipts.get(id)
        }?;
        let row: ActRowIds = serde_json::from_slice(value).ok()?;
        let row_id = match (by_act, recipient) {
            (_, None) => row.id.as_deref(),
            (true, Some(_)) => row.act_id.as_deref(),
            (false, Some(_)) => row.receipt_id.as_deref(),
        };
        let named = row.vault_id == *signed
            && row_id == Some(id)
            && recipient.is_none_or(|recipient| row.recipient.as_deref() == Some(recipient));
        match HANDOVER_UNPROVEN_RESTORE {
            UnprovenRestore::RefuseIfChanged => named.then_some(HANDOVER_ACT_RESTORE_CLASS),
        }
    }
}

/// Whether `text` is an entity id in its one canonical spelling.
fn canonical_id(text: &str) -> bool {
    EntityId::from_hex(text).is_ok_and(|id| id.to_hex() == text)
}
