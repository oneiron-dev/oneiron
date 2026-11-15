//! UC-12 PR 1 (FIX SLACK-INSTALL-ROWS-NEVER-SWEPT): the pending Slack install
//! table gets the sweep its module doc promised. `hold_slack_install` was its
//! only writer and `take_slack_install` its only reader, and a take deletes
//! only the state it is asked for. So a state that was held and never
//! redeemed stayed in the table for good, though every take already read it
//! as absent from its `expires_at` second on.
//!
//! Now each hold first deletes every row that reads as absent at its `now`
//! (`expires_at <= now`, the instant the take treats as lapsed). Red at the
//! scratch head (this test and its door, without the sweep): the two lapsed
//! states stay in the table. Guards (pass at both heads): a take still reads
//! a lapsed state as absent and redeems a live one.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test slack_install_sweep`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::authority::ActSurface;
use oneiron::consent::AuthenticatedOwner;
use oneiron::secret_custody::{CustodyClass, CustodyTier};
use oneiron::skill_hub::pack_catalog::SlackInstallHold;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::test_doors::slack_install_rows::pending_slack_install_states;
use oneiron::{Vault, VaultConfig};

const T0: u64 = 1_800_000_000;

/// One personal vault on a manual recording clock, and its owner's proof.
/// The vault drops before its directory.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    proof: AuthenticatedOwner,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::default();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            clock,
            proof,
            _dir: dir,
        }
    }

    /// Holds one install under `state`, redeemable for `ttl_secs` from the
    /// clock's current second.
    fn hold(&self, state: &str, ttl_secs: u64) {
        self.vault
            .hold_slack_install(SlackInstallHold {
                owner: &self.proof,
                state,
                surface: ActSurface::ThisInstall,
                source: None,
                client_id: "slack-client",
                redirect_url: "https://example.invalid/slack/redirect",
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T0Doored,
                ttl_secs,
            })
            .expect("the install is held");
    }

    fn states(&self) -> Vec<String> {
        pending_slack_install_states(&self.vault).expect("the pending states")
    }
}

/// Three held states; two lapse (one well before the next hold, one at that
/// hold's exact second), and the next hold deletes both. The live one stays
/// and still redeems.
#[test]
fn a_hold_deletes_every_state_that_reads_as_lapsed() {
    let fixture = Fixture::open();
    fixture.hold("state-a", 10);
    fixture.hold("state-b", 20);
    fixture.hold("state-c", 3_600);
    assert_eq!(fixture.states(), ["state-a", "state-b", "state-c"]);

    // `state-a` lapsed at T0 + 10; `state-b` lapses at exactly T0 + 20, the
    // second a take already reads it as absent.
    fixture.clock.set(T0 + 20);
    fixture.hold("state-d", 3_600);
    assert_eq!(
        fixture.states(),
        ["state-c", "state-d"],
        "the hold at T0 + 20 deletes the two states that read as lapsed at T0 + 20"
    );

    // The live states still redeem, once.
    let redeemed = fixture
        .vault
        .take_slack_install("state-c")
        .expect("the take")
        .expect("a live state redeems");
    assert_eq!(redeemed.client_id, "slack-client");
    assert_eq!(fixture.states(), ["state-d"]);
}

/// Guard (green at both heads): a take reads a lapsed state as absent at its
/// `expires_at` second and deletes it, and a state one second short of it
/// still redeems.
#[test]
fn a_take_reads_a_state_as_absent_from_its_expiry_second() {
    let fixture = Fixture::open();
    fixture.hold("state-lapsed", 10);
    fixture.hold("state-live", 11);
    fixture.clock.set(T0 + 10);
    assert!(
        fixture
            .vault
            .take_slack_install("state-lapsed")
            .expect("the take")
            .is_none(),
        "a state reads as absent at its expires_at second"
    );
    assert!(
        fixture
            .vault
            .take_slack_install("state-live")
            .expect("the take")
            .is_some(),
        "a state one second before its expires_at still redeems"
    );
    assert!(fixture.states().is_empty(), "each take deletes its row");
}
