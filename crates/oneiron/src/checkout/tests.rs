use super::*;

#[test]
fn checkout_result_identity_is_stable_and_domain_separated() {
    let id = CheckoutId([1; 16]);
    assert_eq!(
        checkout_result_identity(id, 7, "abc", "def"),
        checkout_result_identity(id, 7, "abc", "def")
    );
    assert_ne!(
        checkout_result_identity(id, 7, "abc", "def"),
        checkout_result_identity(id, 8, "abc", "def")
    );
}

#[test]
fn checkout_git_oid_requires_lowercase_sha1_hex() {
    assert!(GitOid::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_ok());
    assert!(GitOid::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_err());
}

#[test]
fn checkout_ttl_policy_is_pinned() {
    assert!(CheckoutTaskClass::Build.allows_ttl_reclaim());
    assert!(CheckoutTaskClass::Verify.allows_ttl_reclaim());
    assert!(!CheckoutTaskClass::Edit.allows_ttl_reclaim());
    assert!(!CheckoutTaskClass::Effect.allows_ttl_reclaim());
}

use crate::Vault;
use crate::config::VaultConfig;
use std::collections::HashMap;
use tempfile::TempDir;

fn vault() -> (Vault, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    (vault, dir)
}
fn id() -> CheckoutId {
    CheckoutId([7; 16])
}
fn task() -> crate::entity_id::EntityId {
    crate::entity_id::EntityId::from_bytes([1; 16]).unwrap()
}
fn request(class: CheckoutTaskClass, holder: &str, now: u64) -> CheckoutClaimRequest {
    CheckoutClaimRequest {
        checkout_id: id(),
        task_ref: task(),
        repo_ref: crate::codebase::RepoRef::parse(
            "github:owner/repo#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap(),
        holder_ref: holder.into(),
        task_class: class,
        ttl_secs: Some(10),
        now,
    }
}
#[derive(Default)]
struct Sink(Vec<CheckoutFactMutation>);
impl CheckoutFactSink for Sink {
    fn apply_checkout_fact(&mut self, m: CheckoutFactMutation) -> CheckoutResult<()> {
        self.0.push(m);
        Ok(())
    }
}
#[derive(Default)]
struct Live(HashMap<CheckoutId, CheckoutLivenessPulse>);
impl CheckoutLiveness for Live {
    fn publish(&mut self, p: CheckoutLivenessPulse) -> CheckoutResult<()> {
        self.0.insert(p.checkout_id, p);
        Ok(())
    }
    fn current(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(self.0.get(&id).cloned())
    }
    fn clear(&mut self, id: CheckoutId, epoch: u64) -> CheckoutResult<()> {
        if self.0.get(&id).is_some_and(|p| p.epoch == epoch) {
            self.0.remove(&id);
        }
        Ok(())
    }
}
struct Ops {
    inspection: CheckoutTeardownInspection,
}
impl CheckoutRepoOps for Ops {
    fn materialize(&self, _: &CheckoutLeaseAct) -> CheckoutResult<()> {
        Ok(())
    }
    fn inspect_teardown(
        &self,
        _: &CheckoutLeaseAct,
        _: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection> {
        Ok(self.inspection.clone())
    }
    fn collect(&self, _: &CheckoutLeaseAct) -> CheckoutResult<()> {
        Ok(())
    }
}

#[test]
fn checkout_epoch_fences_renew_and_settle() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
    let grant = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let stale = CheckoutLeaseFence {
        checkout_id: id(),
        epoch: 0,
        holder_ref: "one".into(),
    };
    assert!(matches!(
        s.renew(stale.clone(), 10, 101),
        Err(CheckoutError::StaleEpoch { .. })
    ));
    assert!(matches!(
        s.settle(CheckoutSettlementRequest {
            fence: stale,
            disposition: CheckoutSettlementDisposition::Select,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: 101
        }),
        Err(CheckoutError::StaleEpoch { .. })
    ));
    assert_eq!(grant.epoch, 1);
}

#[test]
fn checkout_ttl_reclaim_is_class_fenced_and_idempotent() {
    for class in [CheckoutTaskClass::Build, CheckoutTaskClass::Verify] {
        let (v, _d) = vault();
        let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
        s.claim(request(class, "one", 100)).unwrap();
        assert_eq!(
            s.reclaim_idempotent(id(), "two".into(), 111).unwrap().epoch,
            2
        );
        assert_eq!(
            s.reclaim_idempotent(id(), "two".into(), 111).unwrap().epoch,
            2
        );
    }
    for class in [CheckoutTaskClass::Edit, CheckoutTaskClass::Effect] {
        let (v, _d) = vault();
        let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
        s.claim(request(class, "one", 100)).unwrap();
        assert!(s.reclaim_idempotent(id(), "two".into(), 111).is_err());
    }
}

#[test]
fn checkout_settlement_is_consume_once() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let f = CheckoutLeaseFence {
        checkout_id: id(),
        epoch: g.epoch,
        holder_ref: "one".into(),
    };
    let first = s
        .settle(CheckoutSettlementRequest {
            fence: f.clone(),
            disposition: CheckoutSettlementDisposition::Select,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: 101,
        })
        .unwrap();
    assert!(matches!(
        s.settle(CheckoutSettlementRequest {
            fence: f,
            disposition: CheckoutSettlementDisposition::Apply,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: 102
        }),
        Err(CheckoutError::SettlementAlreadyWon)
    ));
    assert_eq!(
        first.result_identity,
        checkout_result_identity(id(), 1, "a", "b")
    );
}

#[test]
fn checkout_teardown_retains_for_missing_dirty_and_occupant() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let f = CheckoutLeaseFence {
        checkout_id: id(),
        epoch: g.epoch,
        holder_ref: "one".into(),
    };
    let ops = Ops {
        inspection: CheckoutTeardownInspection {
            observed_head: None,
            dirty: false,
            receipt_match: TeardownReceiptMatch::Match,
            occupant: None,
        },
    };
    assert!(matches!(
        s.teardown(f, None, &ops, 102).unwrap(),
        CheckoutTeardownOutcome::Retained {
            reason: CheckoutRetainReason::MissingPushedHeadReceipt,
            ..
        }
    ));
}
