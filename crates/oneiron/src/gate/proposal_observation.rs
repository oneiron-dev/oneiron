//! Actor-scoped, receipt-backed proposal observation; crossing only asks a question.

use crate::{EntityId, Result, Vault, error::Error, store::Store};
use serde::{Deserialize, Serialize};

/// Default is above ordinary fleet volume. A trusted manifest may set a
/// different positive advisory threshold; it never becomes an admission cap.
pub(crate) const DEFAULT_PROPOSAL_CHECK_THRESHOLD: u64 = 1_000_000;
const COUNT: &[u8] = b"proposal:actor_count:v1:";
const RECEIPT: &[u8] = b"proposal:submission:v1:";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalSubmissionCheck {
    pub actor: String,
    pub count: u64,
    pub threshold: u64,
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

/// Runs in the proposal's write transaction, after its admission checks. A
/// retry of the same proposal identity does not count twice; a rolled-back
/// proposal cannot leave a counter, question, or receipt behind.
pub(crate) fn observe_submission_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    proposal_ref: &str,
    threshold: u64,
) -> Result<()> {
    let rk = receipt_key(&actor, proposal_ref);
    if let Some(raw) = store.vault_meta.get(txn, &rk)? {
        let old: ProposalSubmissionReceipt = decode(&raw)?;
        if old.actor != actor.to_hex() || old.proposal_ref != proposal_ref {
            return Err(Error::CorruptedIndex(
                "proposal submission receipt identity",
            ));
        }
        return Ok(());
    }
    let ck = count_key(&actor);
    let mut counter: ActorCount = store
        .vault_meta
        .get(txn, &ck)?
        .map(|raw| decode(&raw))
        .transpose()?
        .unwrap_or_default();
    counter.count = counter.count.saturating_add(1);
    if counter.count > threshold && counter.check.is_none() {
        counter.check = Some(ProposalSubmissionCheck {
            actor: actor.to_hex(),
            count: counter.count,
            threshold,
            proposal_ref: proposal_ref.to_owned(),
        });
    }
    store.vault_meta.put(
        txn,
        &rk,
        &encode(&ProposalSubmissionReceipt {
            actor: actor.to_hex(),
            proposal_ref: proposal_ref.to_owned(),
            count: counter.count,
        })?,
    )?;
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

    /// A committed proposal's accounting receipt, keyed by actor and engine id.
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
        for (actor, reference) in [
            (first, "claim:one"),
            (first, "claim:one"),
            (second, "claim:one"),
            (first, "claim:two"),
            (first, "claim:three"),
        ] {
            vault
                .with_write_txn(|txn| {
                    observe_submission_in_txn(&vault.store, txn, actor, reference, 1)
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
