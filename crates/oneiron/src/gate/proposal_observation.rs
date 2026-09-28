//! Actor-scoped, receipt-backed proposal observation; crossing only asks a question.

use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{
    EntityId, Result, Vault,
    error::{Error, ErrorKind},
    store::Store,
};
use serde::{Deserialize, Serialize};

/// Counter and the first policy threshold-crossing for one actor.
const COUNT: SideTable<EntityId, ActorCount, Named> =
    SideTable::new(&side_table::PROPOSAL_ACTOR_COUNT);
/// Latest receipt for one actor and proposal identity.
const RECEIPT: SideTable<ProposalKey, ProposalSubmissionReceipt, Named> =
    SideTable::new(&side_table::PROPOSAL_SUBMISSION);
/// Immutable receipt keyed by actor and monotonically increasing count.
const HISTORY: SideTable<HistoryKey, ProposalSubmissionReceipt, Named> =
    SideTable::new(&side_table::PROPOSAL_RECEIPT_HISTORY);

struct ProposalKey {
    actor: EntityId,
    proposal_ref: String,
}
impl SideKey for ProposalKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.actor.as_bytes());
        out.push(b':');
        out.extend_from_slice(self.proposal_ref.as_bytes());
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let actor = EntityId::from_bytes(bytes.get(..16)?.try_into().ok()?).ok()?;
        (bytes.get(16) == Some(&b':')).then_some(Self {
            actor,
            proposal_ref: String::from_utf8(bytes.get(17..)?.to_vec()).ok()?,
        })
    }
}
struct HistoryKey {
    actor: EntityId,
    count: u64,
}
impl SideKey for HistoryKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.actor.as_bytes());
        out.push(b':');
        out.extend_from_slice(&self.count.to_be_bytes());
    }
    fn decode_key(bytes: &[u8]) -> Option<Self> {
        (bytes.len() == 25 && bytes[16] == b':').then_some(Self {
            actor: EntityId::from_bytes(bytes[..16].try_into().ok()?).ok()?,
            count: u64::from_be_bytes(bytes[17..].try_into().ok()?),
        })
    }
}

/// The manifest row (or shipped fallback) behind the advisory threshold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalPolicySource {
    pub threshold: u64,
    pub deciding_row: Option<String>,
    pub precedence_row: Option<String>,
    pub shipped_default_precedence: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalSubmissionCheck {
    pub actor: String,
    pub count: u64,
    pub threshold: u64,
    pub policy_source: ProposalPolicySource,
    /// Engine-derived proposal identity that first crossed the threshold.
    pub proposal_ref: String,
}
impl ProposalSubmissionCheck {
    pub const KIND: &'static str = "proposal_submission_burst";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalSubmissionReceipt {
    pub actor: String,
    pub proposal_ref: String,
    pub count: u64,
    pub policy_source: ProposalPolicySource,
}

#[derive(Default, Serialize, Deserialize)]
struct ActorCount {
    count: u64,
    check: Option<ProposalSubmissionCheck>,
}

/// Preserve the pre-typed refusal for a malformed persisted receipt.
fn read_row<T>(result: Result<Option<T>>) -> Result<Option<T>> {
    result.map_err(|error| {
        if error.kind() == ErrorKind::SideTableRow {
            Error::CorruptedIndex("proposal observation")
        } else {
            error
        }
    })
}

/// Runs in the proposal's write transaction, after its admission checks. A
/// unchanged retry of the same proposal identity does not count twice. Each
/// changed body counts again, with an immutable receipt; a rolled-back
/// proposal cannot leave a counter, question, or receipt behind.
pub(crate) fn observe_submission_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    proposal_ref: &str,
    policy_source: ProposalPolicySource,
    revision_changed: bool,
) -> Result<()> {
    let rk = ProposalKey {
        actor,
        proposal_ref: proposal_ref.to_owned(),
    };
    if let Some(old) = read_row(RECEIPT.get(store, txn, &rk))? {
        if old.actor != actor.to_hex() || old.proposal_ref != proposal_ref {
            return Err(Error::CorruptedIndex(
                "proposal submission receipt identity",
            ));
        }
        if !revision_changed {
            return Ok(());
        }
    }
    let mut counter = read_row(COUNT.get(store, txn, &actor))?.unwrap_or_default();
    counter.count = counter.count.saturating_add(1);
    if counter.count > policy_source.threshold && counter.check.is_none() {
        counter.check = Some(ProposalSubmissionCheck {
            actor: actor.to_hex(),
            count: counter.count,
            threshold: policy_source.threshold,
            policy_source: policy_source.clone(),
            proposal_ref: proposal_ref.to_owned(),
        });
    }
    let receipt = ProposalSubmissionReceipt {
        actor: actor.to_hex(),
        proposal_ref: proposal_ref.to_owned(),
        count: counter.count,
        policy_source,
    };
    // The identity key is only the latest receipt; changed submissions append history.
    HISTORY.put(
        store,
        txn,
        &HistoryKey {
            actor,
            count: counter.count,
        },
        &receipt,
    )?;
    RECEIPT.put(store, txn, &rk, &receipt)?;
    COUNT.put(store, txn, &actor, &counter)?;
    Ok(())
}

impl Vault {
    /// The first typed OF-520 crossing for this actor, if any. Observation is
    /// local-only; it never travels on the replicated claim path.
    pub fn proposal_submission_check(
        &self,
        actor: &EntityId,
    ) -> Result<Option<ProposalSubmissionCheck>> {
        let txn = self.store.env.read_txn()?;
        let row = read_row(COUNT.get(&self.store, &txn, actor))?;
        Ok(row.and_then(|row| row.check))
    }

    /// Latest accounting receipt for this actor and proposal identity.
    pub fn proposal_submission_receipt(
        &self,
        actor: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<ProposalSubmissionReceipt>> {
        let txn = self.store.env.read_txn()?;
        read_row(RECEIPT.get(
            &self.store,
            &txn,
            &ProposalKey {
                actor: *actor,
                proposal_ref: proposal_ref.to_owned(),
            },
        ))
    }

    /// Immutable accounting receipt at this actor's submission count.
    pub fn proposal_submission_receipt_at(
        &self,
        actor: &EntityId,
        count: u64,
    ) -> Result<Option<ProposalSubmissionReceipt>> {
        let txn = self.store.env.read_txn()?;
        read_row(HISTORY.get(
            &self.store,
            &txn,
            &HistoryKey {
                actor: *actor,
                count,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_receipts_dedupe_retries_without_colliding_on_the_same_proposal_id() {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::open(dir.path(), crate::VaultConfig::device()).unwrap();
        let first = EntityId::now();
        let second = EntityId::now();
        for (actor, reference, changed) in [
            (first, "claim:one", true),
            (first, "claim:one", false),
            (second, "claim:one", true),
            (first, "claim:two", true),
            (first, "claim:three", true),
        ] {
            vault
                .with_write_txn(|txn| {
                    observe_submission_in_txn(
                        &vault.store,
                        txn,
                        actor,
                        reference,
                        ProposalPolicySource {
                            threshold: 1,
                            deciding_row: None,
                            precedence_row: None,
                            shipped_default_precedence: true,
                        },
                        changed,
                    )
                })
                .unwrap();
        }
        assert_eq!(
            vault
                .proposal_submission_receipt(&first, "claim:one")
                .unwrap()
                .unwrap()
                .count,
            1
        );
        assert_eq!(
            vault
                .proposal_submission_receipt(&second, "claim:one")
                .unwrap()
                .unwrap()
                .count,
            1
        );
        assert_eq!(
            vault
                .proposal_submission_receipt(&first, "claim:two")
                .unwrap()
                .unwrap()
                .count,
            2
        );
        let check = vault.proposal_submission_check(&first).unwrap().unwrap();
        assert_eq!(check.actor, first.to_hex());
        assert_eq!(check.count, 2);
        assert_eq!(check.proposal_ref, "claim:two");
        assert!(vault.proposal_submission_check(&second).unwrap().is_none());
    }
}
