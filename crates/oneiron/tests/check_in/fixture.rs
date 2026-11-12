//! The P2.2 check-in tests' shared fixture (`check_in_pending_handle.rs`,
//! `check_in_rung_waits.rs`): a vault on a clock the test moves, people who
//! answer, and an open request.
#![allow(dead_code)]

use std::sync::Arc;

use oneiron::check_in::{
    ActClass, CheckInMode, CheckInScope, HolderKind, OpenPendingCheckIn, PendingCheckIn,
    RungHolder, RungMembers, WaitReason,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::receipt::{ReceiptKind, ReceiptQuery, ReceiptRecord};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;

/// The instant every test opens at.
pub(crate) const T0: u64 = 1_790_000_000;
pub(crate) const HOUR: u64 = 60 * 60;
pub(crate) const DAY: u64 = 24 * HOUR;
/// The effect every request is over.
pub(crate) const DIGEST: [u8; 32] = [0x5e; 32];

pub(crate) struct Fixture {
    pub(crate) vault: Vault,
    pub(crate) clock: Arc<ManualClock>,
    dir: tempfile::TempDir,
}

impl Fixture {
    pub(crate) fn open() -> Self {
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = open_on(&dir, &clock);
        Self { vault, clock, dir }
    }

    /// The same vault, closed and opened again on the same clock.
    pub(crate) fn reopen(self) -> Self {
        let Self { vault, clock, dir } = self;
        drop(vault);
        let vault = open_on(&dir, &clock);
        Self { vault, clock, dir }
    }

    pub(crate) fn at(&self, now: u64) {
        self.clock.set(now);
    }

    /// A live person and their proof.
    pub(crate) fn person(&self) -> (EntityId, AuthenticatedOwner) {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .expect("person row");
        let proof = self
            .vault
            .authenticate_owner(id, &id.to_hex(), true, GateDecisionId::now())
            .expect("person proof");
        (id, proof)
    }

    /// The vault owner's proof, for the Owner's manifest install.
    pub(crate) fn owner(&self) -> AuthenticatedOwner {
        let owner = self.vault.ensure_embedded_owner_actor().expect("owner");
        self.vault
            .authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())
            .expect("owner proof")
    }

    /// Installs an Owner manifest whose only row beside the header is
    /// `check_in`.
    pub(crate) fn install_check_in_row(&self, check_in: serde_json::Value) {
        let policy = serde_json::json!({
            "schema_version": "1.2",
            "pack_id": "check-in-rung-waits",
            "pack_version": "1.0.0",
            "min_engine_version": "0.0.0",
            "defaults": {},
            "rules": [],
            "actor_ceilings": [],
            "check_in": check_in,
        });
        self.try_install(&policy)
            .expect("the owner installs the row");
    }

    pub(crate) fn try_install(&self, policy: &serde_json::Value) -> oneiron::error::Result<()> {
        self.vault.install_owner_policy_manifest(
            &self.owner(),
            EntityId::now(),
            rmp_serde::to_vec_named(policy).expect("encode"),
            self.vault.now_recorded_at(),
        )
    }

    pub(crate) fn row(&self, id: &EntityId) -> PendingCheckIn {
        self.vault
            .pending_check_in(id)
            .expect("read")
            .expect("the pending check-in is stored")
    }

    /// Every `check_in` receipt of `id`, in the order they were written.
    pub(crate) fn receipts(&self, id: &EntityId) -> Vec<ReceiptRecord> {
        let mut query = ReceiptQuery::new(100);
        query.kinds = [ReceiptKind::CheckIn].into();
        query.job_ref = Some(id.to_hex());
        let mut receipts = self.vault.receipts(query).expect("receipts");
        receipts.sort_by_key(|receipt| receipt.receipt_id.clone());
        receipts
    }

    /// Every `check_in` receipt in the vault.
    pub(crate) fn every_receipt(&self) -> Vec<ReceiptRecord> {
        let mut query = ReceiptQuery::new(100);
        query.kinds = [ReceiptKind::CheckIn].into();
        self.vault.receipts(query).expect("receipts")
    }

    /// The outcomes of `id`'s receipts, in order.
    pub(crate) fn outcomes(&self, id: &EntityId) -> Vec<String> {
        self.receipts(id)
            .into_iter()
            .map(|receipt| receipt.outcome)
            .collect()
    }
}

fn open_on(dir: &tempfile::TempDir, clock: &Arc<ManualClock>) -> Vault {
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    Vault::open(dir.path(), config).expect("open vault")
}

/// An `AlwaysAsk` request by `asker` for `act`, at the vault scope.
pub(crate) fn request(asker: EntityId, act: ActClass) -> OpenPendingCheckIn {
    OpenPendingCheckIn {
        asker,
        grant_ref: "grant:asker".to_owned(),
        verb: "vault.agents.spawn".to_owned(),
        act,
        scope: CheckInScope::default(),
        effect_digest: DIGEST,
        mode: CheckInMode::AlwaysAsk,
        reason: WaitReason::AlwaysAsk,
        asker_wait_secs: None,
        until: None,
        undo_plan: None,
        delay_window: None,
    }
}

/// A rung of these people.
pub(crate) fn people(ids: &[EntityId]) -> RungMembers {
    RungMembers::Holders(
        ids.iter()
            .map(|&principal| RungHolder {
                principal,
                kind: HolderKind::Person,
            })
            .collect(),
    )
}
