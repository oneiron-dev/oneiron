//! FIX 22391 CHECKOUT-RENEW: a teardown that retains a checkout leaves its
//! holder the fence, and the holder clears the retain cause and drives
//! teardown again. Meanwhile the unexpired Retained lease settles, and it must
//! renew as well. A Settling lease and an expired one stay refused.
//!
//! The lease service is public, so these tests drive it directly, with
//! in-test fact, liveness and repo ports.

use std::cell::Cell;
use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::checkout::lease::{
    CheckoutClaimRequest, CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutId,
    CheckoutLeaseAct, CheckoutLeaseFence, CheckoutLeaseGrant, CheckoutLeaseService,
    CheckoutLeaseState, CheckoutLiveness, CheckoutLivenessPulse, CheckoutRepoOps, CheckoutResult,
    CheckoutRetainReason, CheckoutSettlementDisposition, CheckoutSettlementRequest,
    CheckoutTaskClass, CheckoutTeardownInspection, CheckoutTeardownOutcome, GitOid,
    PushedHeadReceipt, TeardownReceiptMatch,
};
use oneiron::codebase::RepoRef;
use oneiron::{EntityId, Vault, VaultConfig};
use tempfile::TempDir;

const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HOLDER: &str = "one";
const LEASE_SECS: u64 = 3_600;

fn vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("the vault opens");
    // Bound as (_d, v): v drops before _d removes the LMDB files.
    (dir, vault)
}

fn id() -> CheckoutId {
    CheckoutId::from_bytes([7; 16]).expect("a checkout id")
}

fn fence(grant: &CheckoutLeaseGrant) -> CheckoutLeaseFence {
    CheckoutLeaseFence {
        checkout_id: id(),
        epoch: grant.epoch,
        holder_ref: HOLDER.into(),
    }
}

struct Facts;
impl CheckoutFactSink for Facts {
    fn apply_checkout_fact(&mut self, _: CheckoutFactMutation) -> CheckoutResult<()> {
        Ok(())
    }
}

/// No liveness pulse is ever seen, so teardown judges the checkout by its
/// receipt and its tree alone.
struct NoLiveness;
impl CheckoutLiveness for NoLiveness {
    fn publish(&mut self, _: CheckoutLivenessPulse) -> CheckoutResult<()> {
        Ok(())
    }
    fn current(&self, _: CheckoutId) -> CheckoutResult<Option<CheckoutLivenessPulse>> {
        Ok(None)
    }
    fn clear(&mut self, _: CheckoutId, _: u64) -> CheckoutResult<()> {
        Ok(())
    }
}

/// A clean tree at the pushed head whose collection fails `collect_fails`
/// times before it succeeds.
struct Repo {
    collect_fails: Cell<u32>,
}
impl CheckoutRepoOps for Repo {
    fn materialize(&self, _: &CheckoutLeaseAct) -> CheckoutResult<()> {
        Ok(())
    }
    fn inspect_teardown(
        &self,
        _: &CheckoutLeaseAct,
        _: &PushedHeadReceipt,
    ) -> CheckoutResult<CheckoutTeardownInspection> {
        Ok(CheckoutTeardownInspection {
            observed_head: Some(GitOid::parse(HEAD).expect("a git oid")),
            dirty: false,
            receipt_match: TeardownReceiptMatch::Match,
            occupant: None,
        })
    }
    fn collect(&self, _: &CheckoutLeaseAct) -> CheckoutResult<()> {
        if self.collect_fails.get() > 0 {
            self.collect_fails.set(self.collect_fails.get() - 1);
            return Err(CheckoutError::RepoOps("collect failed".into()));
        }
        Ok(())
    }
}

type Leases<'a> = CheckoutLeaseService<'a, Facts, NoLiveness>;

/// Claims the checkout for [`HOLDER`] with an hour's lease. Answers the grant
/// and the first second every lease door accepts: the doors compare `now`
/// with the lease's `claimed_at`, which the vault's own clock stamps.
fn claim(leases: &mut Leases<'_>) -> (CheckoutLeaseGrant, u64) {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs();
    let grant = leases
        .claim(CheckoutClaimRequest {
            checkout_id: id(),
            task_ref: EntityId::from_bytes([1; 16]).expect("a task id"),
            repo_ref: RepoRef::parse(&format!("github:owner/repo#{HEAD}")).expect("a repo ref"),
            holder_ref: HOLDER.into(),
            task_class: CheckoutTaskClass::Build,
            ttl_secs: Some(LEASE_SECS),
            now: wall,
        })
        .expect("the claim lands");
    let claimed_at = lease(leases).claimed_at;
    let start = wall.max(claimed_at);
    assert!(
        start + 10 < wall + LEASE_SECS,
        "the vault clock ({claimed_at}) is within the lease of the wall clock ({wall})"
    );
    (grant, start)
}

fn lease(leases: &Leases<'_>) -> CheckoutLeaseAct {
    leases
        .get(id())
        .expect("the lease reads")
        .expect("the lease exists")
}

/// Tears the checkout down with no pushed-head receipt, which retains it.
fn retain(leases: &mut Leases<'_>, grant: &CheckoutLeaseGrant, now: u64) {
    let repo = Repo {
        collect_fails: Cell::new(0),
    };
    let outcome = leases
        .teardown(fence(grant), None, &repo, now)
        .expect("the teardown answers");
    assert!(
        matches!(
            outcome,
            CheckoutTeardownOutcome::Retained {
                reason: CheckoutRetainReason::MissingPushedHeadReceipt,
                ..
            }
        ),
        "a teardown with no receipt retains the checkout, got {outcome:?}"
    );
    assert_eq!(lease(leases).state, CheckoutLeaseState::Retained);
}

#[test]
fn checkout_retained_state_can_renew_then_settle() {
    let (_d, v) = vault();
    let mut leases = Leases::new(&v, Facts, NoLiveness);
    let (grant, t) = claim(&mut leases);
    retain(&mut leases, &grant, t + 1);

    let renewed = leases
        .renew(fence(&grant), 50, t + 2)
        .expect("an unexpired Retained checkout renews under its fence");
    assert_eq!(renewed.epoch, grant.epoch);
    assert_eq!(renewed.lease_expires_at, Some(t + 52));
    let after = lease(&leases);
    assert_eq!(
        after.state,
        CheckoutLeaseState::Retained,
        "a renewal keeps the state"
    );
    assert_eq!(after.updated_at, t + 2);

    let receipt = leases
        .settle(CheckoutSettlementRequest {
            fence: fence(&grant),
            disposition: CheckoutSettlementDisposition::Select,
            observed_ref: "a".into(),
            result_ref: "b".into(),
            now: t + 3,
        })
        .expect("the renewed Retained checkout settles");
    assert_eq!(receipt.epoch, grant.epoch);
    assert_eq!(lease(&leases).state, CheckoutLeaseState::Settled);
}

#[test]
fn settling_and_expired_checkouts_still_refuse_renewal() {
    // An expired Retained lease: the renewal keeps the expiry guard.
    let (_d, v) = vault();
    let mut leases = Leases::new(&v, Facts, NoLiveness);
    let (grant, t) = claim(&mut leases);
    retain(&mut leases, &grant, t + 1);
    let expiry = grant.lease_expires_at.expect("the lease has an expiry");
    let refused = leases.renew(fence(&grant), 50, expiry);
    assert!(
        matches!(refused, Err(CheckoutError::StaleEpoch { .. })),
        "an expired Retained checkout does not renew, got {refused:?}"
    );
    assert_eq!(lease(&leases).lease_expires_at, Some(expiry));

    // A Settling lease: collection was authorised under the fence, and its
    // first collection failed, so the lease stays Settling.
    let (_d2, v2) = vault();
    let mut leases = Leases::new(&v2, Facts, NoLiveness);
    let (grant, t) = claim(&mut leases);
    let receipt = PushedHeadReceipt {
        receipt_ref: "r".into(),
        observed_ref: "o".into(),
        pushed_head: HEAD.into(),
        checkout_id: id(),
        epoch: grant.epoch,
    };
    let repo = Repo {
        collect_fails: Cell::new(1),
    };
    let collected = leases.teardown(fence(&grant), Some(&receipt), &repo, t + 1);
    assert!(
        matches!(collected, Err(CheckoutError::RepoOps(_))),
        "the first collection fails, got {collected:?}"
    );
    assert_eq!(lease(&leases).state, CheckoutLeaseState::Settling);
    let refused = leases.renew(fence(&grant), 50, t + 2);
    assert!(
        matches!(refused, Err(CheckoutError::StaleEpoch { .. })),
        "a Settling checkout does not renew, got {refused:?}"
    );
    assert_eq!(lease(&leases).state, CheckoutLeaseState::Settling);
}
