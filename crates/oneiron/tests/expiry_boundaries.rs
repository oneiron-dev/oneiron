//! UC-12 PR 3: the expiry rule is written once (`oneiron_store::expiry`) and
//! each site keeps its verdict at the boundary second. A lease or row is dead
//! from its `expires_at` second on. This file pins that second, one second
//! before it and one after, through public doors of the sites that moved onto
//! the rule:
//! - a checkout lease's renewal (`require_unexpired`) and its TTL reclaim
//!   (`reclaim_in_txn`);
//! - a voice grant offer's confirmation and its prune.
//!
//! Green on main and on the head, with the same verdicts (stored-change path
//! keep: the sites' comparisons did not change).
//!
//! `cargo test --locked -p oneiron --all-features --test expiry_boundaries`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::checkout::lease::{
    CheckoutClaimRequest, CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutId,
    CheckoutLeaseFence, CheckoutLeaseGrant, CheckoutLeaseService, CheckoutLiveness,
    CheckoutLivenessPulse, CheckoutResult, CheckoutTaskClass,
};
use oneiron::codebase::RepoRef;
use oneiron::consent::{AudienceBound, DisclosureClass, DisclosureEnvelope, GrantBound};
use oneiron::genui::ConsentSurface;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EntityId, Vault, VaultConfig};
use tempfile::TempDir;

const HEAD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HOLDER: &str = "one";
const LEASE_SECS: u64 = 100;
const T0: u64 = 1_800_000_000;
/// `genui/voice_offer.rs`' `OFFER_LIFETIME_SECONDS`.
const OFFER_SECS: u64 = 600;

fn vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().expect("a temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("the vault opens");
    // Bound as (_d, v): v drops before _d removes the LMDB files.
    (dir, vault)
}

fn checkout_id() -> CheckoutId {
    CheckoutId::from_bytes([7; 16]).expect("a checkout id")
}

fn fence(grant: &CheckoutLeaseGrant) -> CheckoutLeaseFence {
    CheckoutLeaseFence {
        checkout_id: checkout_id(),
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

type Leases<'a> = CheckoutLeaseService<'a, Facts, NoLiveness>;

/// Claims a Build checkout (a class that allows a TTL reclaim) for
/// [`HOLDER`] with a [`LEASE_SECS`] lease, at the wall second, which every
/// probe below follows: the lease doors refuse a `now` before the vault's own
/// `claimed_at` stamp. Answers the grant and its expiry.
fn claim(leases: &mut Leases<'_>) -> (CheckoutLeaseGrant, u64) {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is past the epoch")
        .as_secs();
    let grant = leases
        .claim(CheckoutClaimRequest {
            checkout_id: checkout_id(),
            task_ref: EntityId::from_bytes([1; 16]).expect("a task id"),
            repo_ref: RepoRef::parse(&format!("github:owner/repo#{HEAD}")).expect("a repo ref"),
            holder_ref: HOLDER.into(),
            task_class: CheckoutTaskClass::Build,
            ttl_secs: Some(LEASE_SECS),
            now: wall,
        })
        .expect("the claim lands");
    let expiry = grant.lease_expires_at.expect("the lease has an expiry");
    assert_eq!(expiry, wall + LEASE_SECS, "the claim's expiry is now + ttl");
    let claimed_at = leases
        .get(checkout_id())
        .expect("the lease reads")
        .expect("the lease exists")
        .claimed_at;
    assert!(
        claimed_at < expiry - 1,
        "the vault clock ({claimed_at}) is within the lease of the wall clock ({wall})"
    );
    (grant, expiry)
}

/// A lease is dead at its expiry second: a renewal there and after is
/// refused; one second before, it renews.
#[test]
fn a_checkout_lease_renews_until_one_second_before_its_expiry() {
    let (_d, v) = vault();
    let mut leases = Leases::new(&v, Facts, NoLiveness);
    let (grant, expiry) = claim(&mut leases);
    for now in [expiry + 1, expiry] {
        let refused = leases.renew(fence(&grant), LEASE_SECS, now);
        assert!(
            matches!(refused, Err(CheckoutError::StaleEpoch { .. })),
            "a lease does not renew at expiry + {}, got {refused:?}",
            now - expiry
        );
    }
    let renewed = leases
        .renew(fence(&grant), LEASE_SECS, expiry - 1)
        .expect("a lease renews one second before its expiry");
    assert_eq!(renewed.epoch, grant.epoch);
    assert_eq!(renewed.lease_expires_at, Some(expiry - 1 + LEASE_SECS));
}

/// A TTL reclaim takes a lease from its expiry second on; one second before,
/// the holder still holds it.
#[test]
fn a_checkout_lease_is_reclaimed_from_its_expiry_second_on() {
    let (_d, v) = vault();
    let mut leases = Leases::new(&v, Facts, NoLiveness);
    let (grant, expiry) = claim(&mut leases);
    let refused = leases.reclaim_idempotent(checkout_id(), "two".into(), expiry - 1);
    assert!(
        matches!(refused, Err(CheckoutError::StaleEpoch { .. })),
        "a live lease is not reclaimed one second before its expiry, got {refused:?}"
    );
    let reclaimed = leases
        .reclaim_idempotent(checkout_id(), "two".into(), expiry)
        .expect("a lease is reclaimed at its expiry second");
    assert_eq!(
        reclaimed.epoch,
        grant.epoch + 1,
        "the reclaim takes a new epoch"
    );
    assert_eq!(reclaimed.lease_expires_at, Some(expiry + LEASE_SECS));
}

fn disclosure_bound() -> GrantBound {
    GrantBound::disclosure(
        AudienceBound::singleton("contact:friend").expect("an audience"),
        DisclosureClass::new("private").expect("a class"),
        DisclosureEnvelope::new(["named-set:friends".to_owned()]).expect("an envelope"),
    )
    .expect("a disclosure bound")
}

/// A voice grant offer is dead at its expiry second: it confirms one second
/// before, is refused there, and the prune takes it from that second on.
#[test]
fn a_voice_offer_confirms_until_one_second_before_its_expiry() {
    let clock = ManualClock::new(T0);
    let dir = tempfile::tempdir().expect("vault directory");
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
    let actor = vault.ensure_embedded_owner_actor().expect("owner actor");
    let owner = vault
        .authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    let bound = disclosure_bound();
    let offer = |segment: &str| {
        vault
            .offer_voice_disclosure_grant(
                actor,
                "principal:owner",
                "call-voice-offer",
                segment,
                &bound,
            )
            .expect("the offer is issued")
    };
    let early = offer("segment-early");
    let late = offer("segment-late");
    assert_eq!(early.expires_at, T0 + OFFER_SECS);
    assert_eq!(late.expires_at, T0 + OFFER_SECS);
    let expiry = early.expires_at;

    clock.set(expiry - 1);
    assert_eq!(
        vault.prune_expired_voice_grant_offers().expect("the prune"),
        0,
        "no offer is pruned one second before its expiry"
    );
    vault
        .confirm_voice_grant_offer(
            &owner,
            &early.grant_offer_nonce,
            bound.clone(),
            ConsentSurface::Dashboard,
        )
        .expect("an offer confirms one second before its expiry");

    clock.set(expiry);
    assert!(
        vault
            .confirm_voice_grant_offer(
                &owner,
                &late.grant_offer_nonce,
                bound.clone(),
                ConsentSurface::Dashboard,
            )
            .is_err(),
        "an offer is refused at its expiry second"
    );
    assert_eq!(
        vault.prune_expired_voice_grant_offers().expect("the prune"),
        1,
        "the prune takes the offer at its expiry second"
    );
    clock.set(expiry + 1);
    assert_eq!(
        vault.prune_expired_voice_grant_offers().expect("the prune"),
        0,
        "nothing is left to prune"
    );
}
