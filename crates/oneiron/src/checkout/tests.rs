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
struct Live {
    pulses: HashMap<CheckoutId, CheckoutLivenessPulse>,
    enabled: bool,
}
impl Default for Live {
    fn default() -> Self {
        Self {
            pulses: HashMap::new(),
            enabled: true,
        }
    }
}
fn no_live() -> Live {
    Live {
        pulses: HashMap::new(),
        enabled: false,
    }
}
impl CheckoutLiveness for Live {
    fn publish(&mut self, p: CheckoutLivenessPulse) -> CheckoutResult<()> {
        self.pulses.insert(p.checkout_id, p);
        Ok(())
    }
    fn current(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(self
            .enabled
            .then(|| self.pulses.get(&id).cloned())
            .flatten())
    }
    fn clear(&mut self, id: CheckoutId, epoch: u64) -> CheckoutResult<()> {
        if self.pulses.get(&id).is_some_and(|p| p.epoch == epoch) {
            self.pulses.remove(&id);
        }
        Ok(())
    }
}
struct Ops {
    inspection: CheckoutTeardownInspection,
    inspect_calls: std::cell::Cell<u32>,
    collect_calls: std::cell::Cell<u32>,
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
        self.inspect_calls.set(self.inspect_calls.get() + 1);
        Ok(self.inspection.clone())
    }
    fn collect(&self, _: &CheckoutLeaseAct) -> CheckoutResult<()> {
        self.collect_calls.set(self.collect_calls.get() + 1);
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
        inspect_calls: std::cell::Cell::new(0),
        collect_calls: std::cell::Cell::new(0),
    };
    assert!(matches!(
        s.teardown(f, None, &ops, 102).unwrap(),
        CheckoutTeardownOutcome::Retained {
            reason: CheckoutRetainReason::MissingPushedHeadReceipt,
            ..
        }
    ));
}

fn fence(grant: &CheckoutLeaseGrant, holder: &str) -> CheckoutLeaseFence {
    CheckoutLeaseFence {
        checkout_id: id(),
        epoch: grant.epoch,
        holder_ref: holder.into(),
    }
}
fn inspection(
    dirty: bool,
    receipt_match: TeardownReceiptMatch,
    occupant: Option<&str>,
) -> CheckoutTeardownInspection {
    CheckoutTeardownInspection {
        observed_head: Some(GitOid::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap()),
        dirty,
        receipt_match,
        occupant: occupant.map(str::to_owned),
    }
}
fn receipt(epoch: u64) -> PushedHeadReceipt {
    PushedHeadReceipt {
        receipt_ref: "r".into(),
        observed_ref: "o".into(),
        pushed_head: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        checkout_id: id(),
        epoch,
    }
}
fn ops(i: CheckoutTeardownInspection) -> Ops {
    Ops {
        inspection: i,
        inspect_calls: std::cell::Cell::new(0),
        collect_calls: std::cell::Cell::new(0),
    }
}

#[test]
fn checkout_teardown_fences_wrong_holder_and_epoch_before_effects() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
    for f in [
        CheckoutLeaseFence {
            checkout_id: id(),
            epoch: 0,
            holder_ref: "one".into(),
        },
        fence(&g, "other"),
    ] {
        assert!(matches!(
            s.teardown(f, Some(&receipt(g.epoch)), &o, 102),
            Err(CheckoutError::StaleEpoch { .. })
        ));
    }
    assert_eq!(o.inspect_calls.get(), 0);
    assert_eq!(o.collect_calls.get(), 0);
}

#[test]
fn checkout_reclaim_refuses_before_expiry_and_retained_leases() {
    for class in [CheckoutTaskClass::Build, CheckoutTaskClass::Verify] {
        let (v, _d) = vault();
        let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
        let g = s.claim(request(class, "one", 100)).unwrap();
        assert!(matches!(
            s.reclaim_idempotent(id(), "two".into(), 109),
            Err(CheckoutError::StaleEpoch { .. })
        ));
        let o = ops(inspection(true, TeardownReceiptMatch::Match, None));
        assert!(matches!(
            s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 111)
                .unwrap(),
            CheckoutTeardownOutcome::Retained {
                reason: CheckoutRetainReason::DirtyOrUncertain,
                ..
            }
        ));
        assert!(matches!(
            s.reclaim_idempotent(id(), "two".into(), 111),
            Err(CheckoutError::StaleEpoch { .. })
        ));
    }
}

#[test]
fn checkout_teardown_retains_live_mismatch_and_uncertain() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
    assert!(matches!(
        s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 102)
            .unwrap(),
        CheckoutTeardownOutcome::Retained {
            reason: CheckoutRetainReason::LiveOccupant,
            ..
        }
    ));
    assert_eq!(
        s.get(id()).unwrap().unwrap().state,
        CheckoutLeaseState::Retained
    );
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    for match_kind in [
        TeardownReceiptMatch::Mismatch,
        TeardownReceiptMatch::Uncertain,
    ] {
        let o = ops(inspection(false, match_kind, None));
        let outcome = s
            .teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 102)
            .unwrap();
        assert!(matches!(
            outcome,
            CheckoutTeardownOutcome::Retained {
                reason: CheckoutRetainReason::ReceiptMismatch
                    | CheckoutRetainReason::DirtyOrUncertain,
                ..
            }
        ));
    }
}

#[test]
fn checkout_collects_clean_matching_receipt_and_removes_lease() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
    assert!(matches!(
        s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 102)
            .unwrap(),
        CheckoutTeardownOutcome::Collected { .. }
    ));
    assert_eq!(o.collect_calls.get(), 1);
    assert_eq!(s.get(id()).unwrap(), None);
}

#[test]
fn checkout_settlement_facts_retry_and_release() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let settle_request = |d| CheckoutSettlementRequest {
        fence: fence(&g, "one"),
        disposition: d,
        observed_ref: "a".into(),
        result_ref: "b".into(),
        now: 101,
    };
    let first = s
        .settle(settle_request(CheckoutSettlementDisposition::Select))
        .unwrap();
    let retry = s
        .settle(settle_request(CheckoutSettlementDisposition::Select))
        .unwrap();
    assert_eq!(first.receipt_id, retry.receipt_id);
    assert!(matches!(
        s.settle(settle_request(CheckoutSettlementDisposition::Apply)),
        Err(CheckoutError::SettlementAlreadyWon)
    ));
    let (facts, _) = s.into_parts();
    assert!(matches!(
        facts.0.as_slice(),
        [
            CheckoutFactMutation::Claimed { .. },
            CheckoutFactMutation::Settled { .. }
        ]
    ));
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    s.settle(CheckoutSettlementRequest {
        fence: fence(&g, "one"),
        disposition: CheckoutSettlementDisposition::Release,
        observed_ref: "a".into(),
        result_ref: "b".into(),
        now: 101,
    })
    .unwrap();
    let (facts, _) = s.into_parts();
    assert!(matches!(
        facts.0.last(),
        Some(CheckoutFactMutation::Released { .. })
    ));
}

#[test]
fn checkout_codec_rejects_invalid_data_and_liveness_is_not_durable() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let a = s.get(id()).unwrap().unwrap();
    let bytes = encode_act(&a).unwrap();
    assert_eq!(decode_act(&bytes).unwrap(), a);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_act(&trailing).is_err());
    let mut value = rmpv::decode::read_value(&mut std::io::Cursor::new(&bytes)).unwrap();
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("lease codec is a map")
    };
    entries[0].1 = rmpv::Value::from(2);
    let mut bad_schema = Vec::new();
    rmpv::encode::write_value(&mut bad_schema, &value).unwrap();
    assert!(decode_act(&bad_schema).is_err());
    let txn = v.store.env.read_txn().unwrap();
    let raw = v
        .store
        .vault_meta
        .get(&txn, &lease_key(id()))
        .unwrap()
        .unwrap();
    assert_eq!(decode_act(&raw).unwrap(), a);
    assert!(!String::from_utf8_lossy(&raw).contains("observed_at"));
    assert!(CheckoutId::from_bytes([0; 16]).is_err());
    let receipt = CheckoutSettlementReceipt {
        receipt_id: [2; 32],
        checkout_id: id(),
        epoch: g.epoch,
        result_identity: [3; 32],
        disposition: CheckoutSettlementDisposition::Apply,
        result_ref: "x".into(),
        settled_at: 100,
    };
    let encoded = encode_receipt(&receipt).unwrap();
    assert_eq!(decode_receipt(&encoded).unwrap(), receipt);
}

#[test]
fn checkout_reclaim_preserves_ttl_and_identity_is_pinned() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    s.claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let a = s.reclaim_idempotent(id(), "two".into(), 111).unwrap();
    let b = s.reclaim_idempotent(id(), "three".into(), 122).unwrap();
    assert_eq!(
        a.lease_expires_at.unwrap() - 111,
        b.lease_expires_at.unwrap() - 122
    );
    assert_eq!(
        checkout_result_identity(id(), 7, "abc", "def"),
        [
            18, 249, 115, 199, 178, 170, 213, 48, 121, 82, 103, 191, 171, 201, 26, 22, 31, 53, 133,
            179, 197, 1, 198, 204, 57, 215, 195, 83, 33, 106, 145, 205
        ]
    );
}
