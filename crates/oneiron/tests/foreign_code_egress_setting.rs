//! Restriction census C23 (RESTRICTION-WAVE-4; owner 16 Nov 00:44: a restriction that is not a
//! correctness fix ships as a good default plus an owner opt-out): the owner's
//! `code_sandbox.foreign.execute_code_egress` decides the network a foreign `execute_code` run
//! is lent, read live at each run.
//!
//! - with no row, the run is lent no network: every connect, datagram and fetch is refused with
//!   the words it has today, and the owner's `false` row reads the same;
//! - the owner's `true` row lends the run the host's egress proxy, so a DNS datagram the run
//!   sends stands (the proxy answers port 53 itself and opens no socket here), and clearing the
//!   row refuses it again.
//!
//! Red on the PR's base: there the foreign door lends no network whatever the owner set, so the
//! datagram is refused with the row on.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test foreign_code_egress_setting`.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use oneiron::authority::MachineRole;
use oneiron::code_sandbox::foreign::foreign_code_egress;
use oneiron::consent::AuthenticatedOwner;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_container::{EgressRelay, HttpRequest};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::Value;

const KEY: &str = "code_sandbox.foreign.execute_code_egress";
const REFUSED: &str = "foreign code has no network grant";
const T0: u64 = 1_790_000_000;

struct Fixture {
    vault: Arc<Vault>,
    _clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
    owner_proof: AuthenticatedOwner,
}

impl Fixture {
    /// A rooted vault with its install enrolled and its embedded owner bound, opened owned.
    fn rooted() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let clock = ManualClock::new(T0);
        let keystore = Arc::new(MemoryKeystore::new());
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Arc::new(Vault::open_owned(dir.path(), config).expect("owned vault"));
        vault.install_device_keystore(Arc::<MemoryKeystore>::clone(&keystore));
        vault.prepare_install_signing().expect("install signing");
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        vault.ensure_host_root_slip(&issuer).expect("host root");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("serving install profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        let owner_proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        Self {
            vault,
            _clock: clock,
            _dir: dir,
            owner_proof,
        }
    }

    /// The owner sets the key's vault row to `value`, or clears it with `None`.
    fn owner_sets(&self, value: Option<bool>) {
        let outcome = self
            .vault
            .set_setting(
                SettingCaller::Owner(&self.owner_proof),
                SetSetting {
                    key: KEY.to_owned(),
                    item: None,
                    scope: SettingScope::Vault,
                    mode: SettingMode::Value,
                    value: value.map(Value::Bool),
                    expected_revision: None,
                    why: None,
                    check_in_ref: None,
                },
            )
            .expect("the owner's change");
        assert!(
            matches!(outcome, SetSettingOutcome::Applied { .. }),
            "FIXTURE: the owner's change did not apply: {outcome:?}"
        );
    }

    /// The network a new foreign run of this vault is lent.
    fn lent(&self) -> Arc<dyn EgressRelay> {
        foreign_code_egress(&self.vault, EntityId::now()).expect("the run's egress")
    }
}

/// A public resolver's DNS port: a datagram there is a name lookup.
fn resolver() -> SocketAddr {
    "9.9.9.9:53".parse().expect("resolver address")
}

fn assert_refused(result: std::io::Result<()>, call: &str) {
    let Err(error) = result else {
        panic!("{call}: a run lent no network is refused");
    };
    assert_eq!(error.kind(), ErrorKind::PermissionDenied, "{call}: {error}");
    assert_eq!(error.to_string(), REFUSED, "{call}");
}

/// Every network call of a run lent no network is refused, with today's words.
fn assert_no_network(egress: &dyn EgressRelay) {
    assert_refused(egress.authorize_datagram(resolver()), "authorize_datagram");
    assert_refused(egress.datagram(resolver(), b"q").map(|_| ()), "datagram");
    assert_refused(
        egress
            .connect("9.9.9.9:443".parse().expect("address"))
            .map(|_| ()),
        "connect",
    );
    assert_refused(
        egress
            .fetch(HttpRequest {
                url: "https://example.com/".to_owned(),
                method: "GET".to_owned(),
                headers: Vec::new(),
                body: Vec::new(),
                follow_redirects: false,
            })
            .map(|_| ()),
        "fetch",
    );
}

#[test]
fn a_foreign_run_is_lent_no_network_until_the_owner_opens_it() {
    let fixture = Fixture::rooted();
    assert_no_network(&*fixture.lent());
    fixture.owner_sets(Some(false));
    assert_no_network(&*fixture.lent());
}

#[test]
fn the_owner_opening_foreign_egress_lets_a_run_look_up_a_name() {
    let fixture = Fixture::rooted();
    fixture.owner_sets(Some(true));
    fixture
        .lent()
        .authorize_datagram(resolver())
        .expect("with the owner's row on, the run's DNS datagram stands");
    fixture.owner_sets(None);
    assert_no_network(&*fixture.lent());
}
