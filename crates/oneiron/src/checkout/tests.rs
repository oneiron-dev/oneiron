use super::*;

#[test]
fn checkout_result_identity_is_stable_and_domain_separated() {
    let id = CheckoutId::from_bytes([1; 16]).unwrap();
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
    CheckoutId::from_bytes([7; 16]).unwrap()
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
    fail_current: std::cell::Cell<u32>,
}
impl Default for Live {
    fn default() -> Self {
        Self {
            pulses: HashMap::new(),
            enabled: true,
            fail_current: std::cell::Cell::new(0),
        }
    }
}
fn no_live() -> Live {
    Live {
        pulses: HashMap::new(),
        enabled: false,
        fail_current: std::cell::Cell::new(0),
    }
}
impl CheckoutLiveness for Live {
    fn publish(&mut self, p: CheckoutLivenessPulse) -> CheckoutResult<()> {
        self.pulses.insert(p.checkout_id, p);
        Ok(())
    }
    fn current(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        if self.fail_current.get() > 0 {
            self.fail_current.set(self.fail_current.get() - 1);
            return Err(CheckoutError::Invalid("liveness port unavailable"));
        }
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
    collect_fails: std::cell::Cell<u32>,
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
        if self.collect_fails.get() > 0 {
            self.collect_fails.set(self.collect_fails.get() - 1);
            return Err(CheckoutError::RepoOps("collect failed".into()));
        }
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
        collect_fails: std::cell::Cell::new(0),
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
        collect_fails: std::cell::Cell::new(0),
    }
}
fn pulse(epoch: u64, holder: &str) -> CheckoutLivenessPulse {
    CheckoutLivenessPulse {
        checkout_id: id(),
        epoch,
        holder_ref: holder.into(),
        observed_at: 101,
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
    // H1 repair: only a FOREIGN pulse is a live occupant, so this case now
    // installs another holder's pulse for the same checkout. It previously
    // relied on the holder's own claim pulse, which pinned the self-retain bug.
    let (facts, mut live) = s.into_parts();
    live.pulses.insert(id(), pulse(g.epoch, "two"));
    let mut s = CheckoutLeaseService::new(&v, facts, live);
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
    for match_kind in [
        TeardownReceiptMatch::Mismatch,
        TeardownReceiptMatch::Uncertain,
    ] {
        let (v, _d) = vault();
        let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
        let g = s
            .claim(request(CheckoutTaskClass::Build, "one", 100))
            .unwrap();
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
        observed_ref: "o".into(),
        result_ref: "x".into(),
        settled_at: 100,
    };
    let encoded = encode_receipt(&receipt).unwrap();
    let golden_v1 = vec![
        137, 174, 115, 99, 104, 101, 109, 97, 95, 118, 101, 114, 115, 105, 111, 110, 1, 171, 99,
        104, 101, 99, 107, 111, 117, 116, 95, 105, 100, 196, 16, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 165, 101, 112, 111, 99, 104, 1, 175, 114, 101, 115, 117, 108, 116, 95, 105,
        100, 101, 110, 116, 105, 116, 121, 196, 32, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 171, 100, 105, 115, 112, 111, 115, 105,
        116, 105, 111, 110, 165, 97, 112, 112, 108, 121, 172, 111, 98, 115, 101, 114, 118, 101,
        100, 95, 114, 101, 102, 161, 111, 170, 114, 101, 115, 117, 108, 116, 95, 114, 101, 102,
        161, 120, 170, 115, 101, 116, 116, 108, 101, 100, 95, 97, 116, 100, 170, 114, 101, 99, 101,
        105, 112, 116, 95, 105, 100, 196, 32, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    ];
    assert_eq!(encoded, golden_v1);
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
    let (facts, _) = s.into_parts();
    assert_eq!(facts.0.len(), 3); // claimed plus the two epoch-changing reclaims
    assert_eq!(
        checkout_result_identity(id(), 7, "abc", "def"),
        [
            18, 249, 115, 199, 178, 170, 213, 48, 121, 82, 103, 191, 171, 201, 26, 22, 31, 53, 133,
            179, 197, 1, 198, 204, 57, 215, 195, 83, 33, 106, 145, 205
        ]
    );
}

#[test]
fn checkout_settlement_keys_are_tuple_scoped_and_all_dispositions_survive() {
    for disposition in [
        CheckoutSettlementDisposition::Select,
        CheckoutSettlementDisposition::Apply,
        CheckoutSettlementDisposition::Release,
        CheckoutSettlementDisposition::Discard,
    ] {
        let (v, _d) = vault();
        let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
        let g = s
            .claim(request(CheckoutTaskClass::Build, "one", 100))
            .unwrap();
        let r = s
            .settle(CheckoutSettlementRequest {
                fence: fence(&g, "one"),
                disposition,
                observed_ref: "observed".into(),
                result_ref: "result".into(),
                now: 101,
            })
            .unwrap();
        assert_eq!(
            s.settle(CheckoutSettlementRequest {
                fence: fence(&g, "one"),
                disposition,
                observed_ref: "observed".into(),
                result_ref: "result".into(),
                now: 101,
            })
            .unwrap(),
            r
        );
    }

    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let first = s
        .settle(CheckoutSettlementRequest {
            fence: fence(&g, "one"),
            disposition: CheckoutSettlementDisposition::Select,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: 101,
        })
        .unwrap();
    let second = s
        .settle(CheckoutSettlementRequest {
            fence: fence(&g, "one"),
            disposition: CheckoutSettlementDisposition::Discard,
            observed_ref: "c".into(),
            result_ref: "d".into(),
            now: 102,
        })
        .unwrap();
    assert_ne!(first.result_identity, second.result_identity);
    assert!(matches!(
        s.settle(CheckoutSettlementRequest {
            fence: fence(&g, "one"),
            disposition: CheckoutSettlementDisposition::Apply,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: 102,
        }),
        Err(CheckoutError::SettlementAlreadyWon)
    ));
}

#[test]
fn checkout_teardown_retains_mismatched_receipts_and_settlement_survives_collection() {
    for mut pushed in [
        None,
        Some(receipt(1)),
        Some(PushedHeadReceipt {
            checkout_id: CheckoutId::from_bytes([8; 16]).unwrap(),
            ..receipt(1)
        }),
    ] {
        let (v, _d) = vault();
        let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
        let g = s
            .claim(request(CheckoutTaskClass::Build, "one", 100))
            .unwrap();
        if let Some(r) = &mut pushed
            && r.checkout_id == id()
        {
            r.epoch = g.epoch + 1;
        }
        let outcome = s
            .teardown(
                fence(&g, "one"),
                pushed.as_ref(),
                &ops(inspection(false, TeardownReceiptMatch::Match, None)),
                102,
            )
            .unwrap();
        assert!(matches!(
            outcome,
            CheckoutTeardownOutcome::Retained {
                reason: CheckoutRetainReason::MissingPushedHeadReceipt
                    | CheckoutRetainReason::ReceiptMismatch,
                ..
            }
        ));
    }

    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let settled = s
        .settle(CheckoutSettlementRequest {
            fence: fence(&g, "one"),
            disposition: CheckoutSettlementDisposition::Select,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: 101,
        })
        .unwrap();
    let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
    assert!(matches!(
        s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 102)
            .unwrap(),
        CheckoutTeardownOutcome::Collected { .. }
    ));
    assert_eq!(s.get(id()).unwrap(), None);
    let txn = v.store.env.read_txn().unwrap();
    let raw = v
        .store
        .vault_meta
        .get(
            &txn,
            &settlement_key(id(), g.epoch, settled.result_identity),
        )
        .unwrap()
        .unwrap();
    assert_eq!(decode_receipt(&raw).unwrap(), settled);
    let (facts, live) = s.into_parts();
    assert_eq!(facts.0.len(), 3);
    assert!(live.pulses.is_empty());
}

#[test]
fn checkout_reclaim_rejects_empty_holder_and_regressing_times() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    assert!(matches!(
        s.reclaim_idempotent(id(), String::new(), 111),
        Err(CheckoutError::Invalid("checkout holder empty"))
    ));
    assert!(matches!(
        s.renew(fence(&g, "one"), 10, 99),
        Err(CheckoutError::Invalid("checkout time regressed"))
    ));
    assert!(matches!(
        s.reclaim_idempotent(id(), "two".into(), 99),
        Err(CheckoutError::Invalid("checkout time regressed"))
    ));
    assert!(matches!(
        s.settle(CheckoutSettlementRequest {
            fence: fence(&g, "one"),
            disposition: CheckoutSettlementDisposition::Select,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: 99
        },),
        Err(CheckoutError::Invalid("checkout time regressed"))
    ));
    assert!(matches!(
        s.teardown(
            fence(&g, "one"),
            Some(&receipt(g.epoch)),
            &ops(inspection(false, TeardownReceiptMatch::Match, None)),
            99
        ),
        Err(CheckoutError::Invalid("checkout time regressed"))
    ));
}

#[test]
fn checkout_teardown_own_pulse_does_not_self_retain_enabled_liveness_happy_path_collects() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
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
    let (facts, live) = s.into_parts();
    assert!(matches!(
        facts.0.last(),
        Some(CheckoutFactMutation::Released { .. })
    ));
    assert!(live.pulses.is_empty());
}

#[test]
fn checkout_teardown_retains_only_for_foreign_pulses_and_occupants() {
    for foreign in [pulse(1, "two"), pulse(2, "one")] {
        let (v, _d) = vault();
        let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
        let g = s
            .claim(request(CheckoutTaskClass::Build, "one", 100))
            .unwrap();
        let (facts, mut live) = s.into_parts();
        live.pulses.insert(id(), foreign);
        let mut s = CheckoutLeaseService::new(&v, facts, live);
        let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
        assert!(matches!(
            s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 102)
                .unwrap(),
            CheckoutTeardownOutcome::Retained {
                reason: CheckoutRetainReason::LiveOccupant,
                ..
            }
        ));
        assert_eq!(o.collect_calls.get(), 0);
    }
    for (occupant, collects) in [("two", false), ("one", true)] {
        let (v, _d) = vault();
        let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
        let g = s
            .claim(request(CheckoutTaskClass::Build, "one", 100))
            .unwrap();
        let i = inspection(false, TeardownReceiptMatch::Match, Some(occupant));
        let o = ops(i);
        let outcome = s
            .teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 102)
            .unwrap();
        let collected = matches!(outcome, CheckoutTeardownOutcome::Collected { .. });
        assert_eq!(collected, collects);
    }
}

#[test]
fn checkout_teardown_transient_retain_then_retry_collects() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
    assert!(matches!(
        s.teardown(fence(&g, "one"), None, &o, 102).unwrap(),
        CheckoutTeardownOutcome::Retained {
            reason: CheckoutRetainReason::MissingPushedHeadReceipt,
            ..
        }
    ));
    let state = s.get(id()).unwrap().unwrap().state;
    assert_eq!(state, CheckoutLeaseState::Retained);
    assert!(matches!(
        s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 103)
            .unwrap(),
        CheckoutTeardownOutcome::Collected { .. }
    ));
    assert_eq!(o.collect_calls.get(), 1);
    assert_eq!(s.get(id()).unwrap(), None);
}

#[test]
fn checkout_teardown_liveness_port_error_is_retryable_not_poisoned() {
    let (v, _d) = vault();
    let live = Live {
        fail_current: std::cell::Cell::new(1),
        ..Live::default()
    };
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), live);
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
    assert!(matches!(
        s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 102),
        Err(CheckoutError::Invalid("liveness port unavailable"))
    ));
    let state = s.get(id()).unwrap().unwrap().state;
    assert_ne!(state, CheckoutLeaseState::Settling);
    assert_eq!(state, CheckoutLeaseState::Active);
    assert!(matches!(
        s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 103)
            .unwrap(),
        CheckoutTeardownOutcome::Collected { .. }
    ));
    assert_eq!(o.inspect_calls.get(), 2);
    assert_eq!(s.get(id()).unwrap(), None);
}

#[test]
fn checkout_teardown_resumes_settling_after_collect_failure_without_reinspecting() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), Live::default());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
    o.collect_fails.set(1);
    assert!(matches!(
        s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 102),
        Err(CheckoutError::RepoOps(_))
    ));
    let state = s.get(id()).unwrap().unwrap().state;
    assert_eq!(state, CheckoutLeaseState::Settling);
    assert!(matches!(
        s.teardown(fence(&g, "one"), Some(&receipt(g.epoch)), &o, 103)
            .unwrap(),
        CheckoutTeardownOutcome::Collected { .. }
    ));
    assert_eq!(o.inspect_calls.get(), 1);
    assert_eq!(o.collect_calls.get(), 2);
    assert_eq!(s.get(id()).unwrap(), None);
    let (facts, live) = s.into_parts();
    assert!(matches!(
        facts.0.last(),
        Some(CheckoutFactMutation::Released { .. })
    ));
    assert!(live.pulses.is_empty());
}

/// Tears the fenced lease down to collection, pinning that the lease row is gone.
fn collect(s: &mut CheckoutLeaseService<'_, Sink, Live>, g: &CheckoutLeaseGrant, now: u64) {
    assert!(matches!(
        s.teardown(
            fence(g, &g.holder_ref),
            Some(&receipt(g.epoch)),
            &ops(inspection(false, TeardownReceiptMatch::Match, None)),
            now,
        )
        .unwrap(),
        CheckoutTeardownOutcome::Collected { .. }
    ));
    assert_eq!(s.get(id()).unwrap(), None);
}
fn tombstone(v: &Vault) -> Option<u64> {
    let txn = v.store.env.read_txn().unwrap();
    v.store
        .vault_meta
        .get(&txn, &tombstone_key(id()))
        .unwrap()
        .map(|raw| decode_tombstone(&raw).unwrap())
}

#[test]
fn checkout_reclaimed_id_after_teardown_seeds_next_epoch_and_kills_old_fence() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let first = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    assert_eq!(first.epoch, 1);
    collect(&mut s, &first, 102);
    assert_eq!(tombstone(&v), Some(1));

    // Same checkout id, same holder: the freed namespace must NOT reissue epoch 1.
    let second = s
        .claim(request(CheckoutTaskClass::Build, "one", 103))
        .unwrap();
    assert_eq!(second.epoch, 2);
    let stale = fence(&first, "one");
    assert!(matches!(
        s.renew(stale.clone(), 10, 104),
        Err(CheckoutError::StaleEpoch {
            held: 2,
            presented: 1
        })
    ));
    assert!(matches!(
        s.settle(CheckoutSettlementRequest {
            fence: stale.clone(),
            disposition: CheckoutSettlementDisposition::Select,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: 104,
        }),
        Err(CheckoutError::StaleEpoch {
            held: 2,
            presented: 1
        })
    ));
    let o = ops(inspection(false, TeardownReceiptMatch::Match, None));
    assert!(matches!(
        s.teardown(stale, Some(&receipt(1)), &o, 104),
        Err(CheckoutError::StaleEpoch {
            held: 2,
            presented: 1
        })
    ));
    assert_eq!(o.collect_calls.get(), 0);
    assert_eq!(s.get(id()).unwrap().unwrap().epoch, 2);
}

#[test]
fn checkout_relifecycled_id_settles_identical_tuple_without_cross_lifecycle_collision() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let settle = |s: &mut CheckoutLeaseService<'_, Sink, Live>,
                  g: &CheckoutLeaseGrant,
                  d,
                  now|
     -> CheckoutResult<CheckoutSettlementReceipt> {
        s.settle(CheckoutSettlementRequest {
            fence: fence(g, "one"),
            disposition: d,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now,
        })
    };

    let first = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    let r1 = settle(&mut s, &first, CheckoutSettlementDisposition::Select, 101).unwrap();
    assert_eq!(
        r1.result_identity,
        checkout_result_identity(id(), 1, "a", "b")
    );
    collect(&mut s, &first, 102);

    // Identical (observed, result) tuple and identical disposition, new lifecycle:
    // the settlement is keyed by the new epoch, so it wins a fresh receipt.
    let second = s
        .claim(request(CheckoutTaskClass::Build, "one", 103))
        .unwrap();
    assert_eq!(second.epoch, 2);
    let r2 = settle(&mut s, &second, CheckoutSettlementDisposition::Select, 104).unwrap();
    assert_eq!(
        r2.result_identity,
        checkout_result_identity(id(), 2, "a", "b")
    );
    assert_ne!(r1.result_identity, r2.result_identity);
    assert_ne!(r1.receipt_id, r2.receipt_id);
    assert_eq!(r2.epoch, 2);
    collect(&mut s, &second, 105);

    // Same tuple, DIFFERENT disposition, third lifecycle: no cross-lifecycle
    // AlreadyWon, because the prior receipts live under prior epochs.
    let third = s
        .claim(request(CheckoutTaskClass::Build, "one", 106))
        .unwrap();
    assert_eq!(third.epoch, 3);
    let r3 = settle(&mut s, &third, CheckoutSettlementDisposition::Apply, 107).unwrap();
    assert_eq!(r3.disposition, CheckoutSettlementDisposition::Apply);
    // Within the third lifecycle consume-once still holds.
    assert!(matches!(
        settle(&mut s, &third, CheckoutSettlementDisposition::Discard, 108),
        Err(CheckoutError::SettlementAlreadyWon)
    ));

    // Every prior receipt row remains durable history and still decodes.
    let txn = v.store.env.read_txn().unwrap();
    for (epoch, expected) in [(1, &r1), (2, &r2), (3, &r3)] {
        let raw = v
            .store
            .vault_meta
            .get(&txn, &settlement_key(id(), epoch, expected.result_identity))
            .unwrap()
            .unwrap();
        assert_eq!(&decode_receipt(&raw).unwrap(), expected);
    }
    drop(txn);
    let (facts, _) = s.into_parts();
    let settled: Vec<u64> = facts
        .0
        .iter()
        .filter_map(|f| match f {
            CheckoutFactMutation::Settled { epoch, .. } => Some(*epoch),
            _ => None,
        })
        .collect();
    assert_eq!(settled, vec![1, 2, 3]);
}

#[test]
fn checkout_tombstone_row_is_absent_until_teardown_and_codec_is_pinned() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    let g = s
        .claim(request(CheckoutTaskClass::Build, "one", 100))
        .unwrap();
    // A live lease already blocks re-claim, so no tombstone exists before the
    // first teardown frees the namespace.
    assert_eq!(tombstone(&v), None);
    collect(&mut s, &g, 102);

    let txn = v.store.env.read_txn().unwrap();
    let raw = v
        .store
        .vault_meta
        .get(&txn, &tombstone_key(id()))
        .unwrap()
        .unwrap()
        .to_vec();
    drop(txn);
    assert_eq!(decode_tombstone(&raw).unwrap(), 1);
    assert_eq!(raw, encode_tombstone(1).unwrap());
    assert!(tombstone_key(id()).starts_with(CHECKOUT_TOMBSTONE_KEY_PREFIX));
    assert_eq!(
        tombstone_key(id()),
        format!("checkout:tombstone:v1:{}", id()).into_bytes()
    );

    let mut value = rmpv::decode::read_value(&mut std::io::Cursor::new(&raw)).unwrap();
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("tombstone codec is a map")
    };
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0.as_str(), Some("schema_version"));
    assert_eq!(entries[1].0.as_str(), Some("max_epoch"));
    // Fail-closed: trailing bytes and an unknown schema version are corrupt,
    // never a silent "no tombstone".
    let mut trailing = raw;
    trailing.push(0);
    assert!(decode_tombstone(&trailing).is_err());
    entries[0].1 = rmpv::Value::from(2);
    let mut bad_schema = Vec::new();
    rmpv::encode::write_value(&mut bad_schema, &value).unwrap();
    assert!(decode_tombstone(&bad_schema).is_err());
}

#[test]
fn checkout_ttl_reclaimed_epoch_is_tombstoned_and_next_claim_resumes_above_it() {
    let (v, _d) = vault();
    let mut s = CheckoutLeaseService::new(&v, Sink::default(), no_live());
    assert_eq!(
        s.claim(request(CheckoutTaskClass::Build, "one", 100))
            .unwrap()
            .epoch,
        1
    );
    let reclaimed = s.reclaim_idempotent(id(), "two".into(), 111).unwrap();
    assert_eq!(reclaimed.epoch, 2);
    // The reclaim wrote no tombstone; the delete records the whole lifecycle.
    assert_eq!(tombstone(&v), None);
    collect(&mut s, &reclaimed, 112);
    assert_eq!(tombstone(&v), Some(2));
    assert_eq!(
        s.claim(request(CheckoutTaskClass::Build, "one", 113))
            .unwrap()
            .epoch,
        3
    );
}
