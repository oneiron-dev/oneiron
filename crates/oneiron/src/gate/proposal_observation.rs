//! Actor-scoped, receipt-backed proposal observation; crossing only asks a question.

use crate::{EntityId, Result, Vault, error::Error, store::Store};
use serde::{Deserialize, Serialize};

const COUNT: &[u8] = b"proposal:actor_count:v1:";
const RECEIPT: &[u8] = b"proposal:submission:v1:";
const HISTORY: &[u8] = b"proposal:receipt:v1:";

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

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value)
        .map_err(|_| Error::InvariantViolation("proposal observation encode"))
}
fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    rmp_serde::from_slice(raw).map_err(|_| Error::CorruptedIndex("proposal observation"))
}
fn count_key(actor: &EntityId) -> Vec<u8> {
    [COUNT, actor.as_bytes()].concat()
}
fn receipt_key(actor: &EntityId, proposal_ref: &str) -> Vec<u8> {
    [RECEIPT, actor.as_bytes(), b":", proposal_ref.as_bytes()].concat()
}
fn history_key(actor: &EntityId, count: u64) -> Vec<u8> {
    [HISTORY, actor.as_bytes(), b":", &count.to_be_bytes()].concat()
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
    let rk = receipt_key(&actor, proposal_ref);
    if let Some(raw) = store.vault_meta.get(txn, &rk)? {
        let old: ProposalSubmissionReceipt = decode(&raw)?;
        if old.actor != actor.to_hex() || old.proposal_ref != proposal_ref {
            return Err(Error::CorruptedIndex(
                "proposal submission receipt identity",
            ));
        }
        if !revision_changed {
            return Ok(());
        }
    }
    let ck = count_key(&actor);
    let mut counter: ActorCount = store
        .vault_meta
        .get(txn, &ck)?
        .map(|raw| decode(&raw))
        .transpose()?
        .unwrap_or_default();
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
    let encoded = encode(&receipt)?;
    // The identity key is only the latest receipt. Never rewrite history when
    // a changed submission reuses an actor-owned claim ID.
    store
        .vault_meta
        .put(txn, &history_key(&actor, counter.count), &encoded)?;
    store.vault_meta.put(txn, &rk, &encoded)?;
    store.vault_meta.put(txn, &ck, &encode(&counter)?)?;
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
        let row: Option<ActorCount> = self
            .store
            .vault_meta
            .get(&txn, &count_key(actor))?
            .map(|raw| decode(&raw))
            .transpose()?;
        Ok(row.and_then(|row| row.check))
    }

    /// Latest accounting receipt for this actor and proposal identity.
    pub fn proposal_submission_receipt(
        &self,
        actor: &EntityId,
        proposal_ref: &str,
    ) -> Result<Option<ProposalSubmissionReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &receipt_key(actor, proposal_ref))?
            .map(|raw| decode(&raw))
            .transpose()
    }

    /// Immutable accounting receipt at this actor's submission count.
    pub fn proposal_submission_receipt_at(
        &self,
        actor: &EntityId,
        count: u64,
    ) -> Result<Option<ProposalSubmissionReceipt>> {
        let txn = self.store.env.read_txn()?;
        self.store
            .vault_meta
            .get(&txn, &history_key(actor, count))?
            .map(|raw| decode(&raw))
            .transpose()
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
