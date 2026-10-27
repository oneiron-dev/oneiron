//! What valid owner handovers name (FIX 5765): the exact grant ids a
//! shared-vault Owner change wrote and retired, and the shared act and
//! receipt it executed, as its signed `OwnerHandover` entry carries them. A
//! checkpoint restore across that change reads this to keep those rows as
//! the live vault holds them, so the demotion stays in force and demoted
//! authority never comes back.
//!
//! A handover counts only when the fold holds its entry valid, by hash (the
//! FIX 5732 rule); no held-back, stale or age condition is added. The rows
//! read are the resident ones and the bodies a verified adopted image
//! carries, each entry once.

use std::collections::{BTreeMap, BTreeSet};

use super::adopted_evidence::AdoptedEvidence;
use super::*;
use crate::EntityId;
use crate::error::Result;

/// The ids valid owner handovers name, across this vault's authority log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HandoverEvidence {
    /// Every grant a valid handover rewrote, minted or deleted.
    pub(crate) affected_grants: BTreeSet<EntityId>,
    /// Every own-device grant a valid handover retired.
    pub(crate) retired_own_device_grants: BTreeSet<EntityId>,
    /// The shared acts valid handovers executed: the signed act id, and the
    /// shared vault it names.
    pub(crate) acts: BTreeMap<String, u64>,
    /// Their execution receipts: the signed receipt id, and the shared
    /// vault it names.
    pub(crate) receipts: BTreeMap<String, u64>,
}

impl HandoverEvidence {
    fn add(&mut self, handover: &OwnerHandover) {
        self.affected_grants
            .extend(handover.affected_grants.iter().copied());
        self.retired_own_device_grants
            .extend(handover.retired_own_device_grants.iter().copied());
        if let Some(act) = &handover.act {
            self.acts.insert(act.clone(), handover.shared_vault);
        }
        self.receipts
            .insert(handover.receipt.clone(), handover.shared_vault);
    }
}

impl crate::Vault {
    /// The evidence of every owner handover the fold of `txn` holds valid,
    /// from the resident rows and an adopted image's carried bodies. A
    /// resident row that does not decode names nothing; a storage fault
    /// fails the read, and the restore reading it then adds no exemption.
    pub(crate) fn owner_handover_evidence_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
    ) -> Result<HandoverEvidence> {
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let mut evidence = HandoverEvidence::default();
        let mut seen = BTreeSet::new();
        let mut take = |hash: AuthorityEntryHash, entry: &AuthorityLogEntry| {
            if let AuthorityOp::OwnerHandover(handover) = &entry.op
                && seen.insert(hash)
                && fold.valid_entries.contains(&hash)
            {
                evidence.add(handover);
            }
        };
        for (_, body) in authority_log_rows_in_txn(&self.store, txn)? {
            let Ok(entry) = decode_authority_log_entry_body(&body) else {
                continue;
            };
            take(authority_entry_hash(&entry)?, &entry);
        }
        if let Some(adopted) = AdoptedEvidence::read_in_txn(&self.store, txn)? {
            for (hash, entry) in adopted.bodies() {
                take(*hash, entry);
            }
        }
        Ok(evidence)
    }
}
