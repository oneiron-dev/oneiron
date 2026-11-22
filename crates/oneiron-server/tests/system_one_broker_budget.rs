//! L9-19 (ARCH-0036 #decision-deadline part 4), #7827 review round 2: a
//! System One seat whose key is a vault secret sends through the credential
//! broker, which reads the key at the custody door on a blocking worker once
//! the broker is reached. That wait is spent from the call: the server's
//! `budget_ms`, the broker header's digest of the body and the reply's wait
//! are read once the key is in hand, and a call whose time ran out during the
//! read is never sent.
//!
//! Each case drives the public seat over the broker leg serve builds for a
//! `key_secret` binding (`oneiron_server::test_doors::system_one_leg`), on
//! the same-user broker child (the built `oneiron-broker` binary) and the
//! vault's real custody door, slowed by a fixed wait, against a local TLS
//! fake server.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support,oneiron-broker/test-support --test system_one_broker_budget`
#![cfg(all(unix, oneiron_test_support))]

use std::sync::Arc;
use std::time::Duration;

use oneiron::llm::decision::{
    AnswerContract, DecisionClass, DecisionQuestion, RemoteDecisionSeat, SeatPhase, SeatRequest,
};
use oneiron::secret_custody::{CustodyTier, SECRET_SCOPE_READ, SecretBinding};
use oneiron::{
    BudgetLease, EntityId, HostingPrivacyPosture, LlmError, RetryableLlmError, Vault, VaultConfig,
};
use oneiron_broker::testing::{FakeProvider, FakeReply};
use oneiron_llm::systemone::SystemOneSeat;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{BROKER_EFFECTOR, KeyDoor, VaultKeyDoor};
use oneiron_server::test_doors::system_one_leg::system_one_broker_leg;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// The vault secret the seat's key is registered under.
const HANDLE: &str = "system-one-seat-key";
/// How long the custody door takes to release the key.
const KEY_READ: Duration = Duration::from_millis(600);

/// The vault's custody door, which waits [`KEY_READ`] before each read, as a
/// door busy on its blocking worker does.
struct SlowDoor {
    door: VaultKeyDoor,
}

impl KeyDoor for SlowDoor {
    fn check(&self, name: &str) -> anyhow::Result<()> {
        self.door.check(name)
    }

    fn read(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        std::thread::sleep(KEY_READ);
        self.door.read(name)
    }
}

struct Fixture {
    fake: FakeProvider,
    seat: SystemOneSeat,
    _vault_dir: tempfile::TempDir,
    _files: tempfile::TempDir,
}

/// A server's answer to the one-question call.
fn answered() -> Value {
    json!({
        "model": "jev-1.13.0",
        "answers": {"decision": {"type": "noul", "noul": 0.9}},
        "usage": {"input_tokens": 3, "output_tokens": 1},
    })
}

/// A seat whose server takes a native budget, its key the vault secret
/// [`HANDLE`] behind a [`SlowDoor`], sending through the broker child to a
/// fake that answers [`answered`].
fn fixture() -> Fixture {
    let fake = FakeProvider::start(FakeReply::json(200, &answered()));
    let files = tempfile::tempdir().expect("fixture dir");
    let ca = files.path().join("ca.pem");
    std::fs::write(&ca, fake.ca_pem()).expect("ca");
    let vault_dir = tempfile::tempdir().expect("vault dir");
    let vault = Arc::new(Vault::open(vault_dir.path(), VaultConfig::default()).expect("vault"));
    vault
        .register_test_secret(
            HANDLE,
            b"system-one-test-key",
            vec![SecretBinding {
                effector: BROKER_EFFECTOR.to_owned(),
                tier_ceiling: CustodyTier::T0Doored,
                scopes: vec![SECRET_SCOPE_READ.to_owned()],
            }],
            1_700_000_000,
        )
        .expect("register the key");
    let keys: Arc<dyn KeyDoor> = Arc::new(SlowDoor {
        door: VaultKeyDoor::new(vault),
    });
    let config = ModelsConfig::from_toml(
        &format!(
            "[broker]\nprogram = \"{program}\"\nextra_roots = [\"{ca}\"]\n",
            program = env!("CARGO_BIN_EXE_oneiron-broker"),
            ca = ca.display(),
        ),
        None,
    )
    .expect("models config");
    let seat = SystemOneSeat::with_transport(
        format!("{}/v1/systemone", fake.origin()),
        "jev".to_owned(),
        "1.13.0".to_owned(),
        system_one_broker_leg(keys, &config.broker, HANDLE),
    )
    .expect("a valid seat")
    .with_native_budget(true);
    Fixture {
        fake,
        seat,
        _vault_dir: vault_dir,
        _files: files,
    }
}

fn request() -> SeatRequest {
    SeatRequest {
        question: DecisionQuestion {
            id: EntityId::now(),
            version: 1,
            text: "Caller-owned question with criteria".into(),
            class: DecisionClass::Judgment,
            contract: AnswerContract::Noul,
            accept_type: false,
        },
        state: json!({"unit":{"value":"example"}}),
        score_levels: Vec::new(),
        posture: HostingPrivacyPosture::Hosted,
        remote_opt_in: false,
        phase: SeatPhase::Background,
        images: Vec::new(),
        audio: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_out_of_time_once_its_key_is_read_is_never_sent() {
    let fixture = fixture();
    let lease = BudgetLease::for_test("seat");
    // 300 ms left; the key read alone takes 600.
    let error = fixture
        .seat
        .ask(request(), &lease, Duration::from_millis(300))
        .await
        .err()
        .expect("a call out of time once its key is read is no answer");
    assert!(
        matches!(error, LlmError::Retryable(RetryableLlmError::Timeout)),
        "the call timed out: {error:?}"
    );
    assert!(
        fixture.fake.seen().is_empty(),
        "nothing reached the server: {:?}",
        fixture.fake.seen()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_budget_is_what_is_left_once_the_key_is_read() {
    let fixture = fixture();
    let lease = BudgetLease::for_test("seat");
    fixture
        .seat
        .ask(request(), &lease, Duration::from_secs(5))
        .await
        .expect("the seat answers");
    let seen = fixture.fake.seen();
    assert_eq!(seen.len(), 1, "one request reached the server");
    let body: Value = serde_json::from_slice(&seen[0].body).expect("one JSON object");
    let budget = body["budget_ms"].as_u64().expect("a budget");
    assert!(
        budget <= 4_400,
        "the key read's 600 ms are spent from the server's budget: {budget}"
    );
}
