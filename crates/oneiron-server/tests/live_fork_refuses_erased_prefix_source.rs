//! A live compaction fork never resends a row erased since its call went
//! out (FIX-LIST ERASE-SERVED-KV-CACHE-OUTLIVES-SOURCE).
//!
//! A live fork (FIX 4465 C) carries a run's latest answered call byte for
//! byte, and every call of its flight sends that prefix again, so the
//! provider's prompt cache, keyed by those bytes, is warmed again with it.
//! The prefix was read from the rows its host witnessed (`prefix_sources`,
//! FIX 9463). After a privacy erase of one of them, that warm copy still
//! holds the erased row's words, where a clean rebuild of the request would
//! not.
//!
//! Each case binds a rooted vault whose one provider is a local
//! OpenAI-compatible model, code mode's compaction live under a prompt
//! package that holds the self-writer frame, and stores two CLAIMs about one
//! PERSON: one the owner then erases (GDPR erase), one that stays. The run's
//! live request holds the words of both and was read from both. In tests 1 and 2 nothing is
//! sent to the provider: the doors stop at the request a call would send.
//!
//! Test 1, a flight's call (`house_live_fork_request`): before the erase the
//! fork's call is built and holds the erased row's words (guard). After it,
//! the same fork sends nothing and says `live_fork_stale`, while a fork of
//! the clean rebuild (the kept row's words, read from that row alone) is
//! still built and holds none of the erased words. On main the stale fork's
//! call is built, erased words and all (RED).
//!
//! Test 2, the breakpoint (`house_live_fork_bind`), under the self row with
//! its source forced to the live fork, for a run with no live call its host
//! admits: before the erase the bind gets past the prefix's checks and is
//! refused as `LiveRungUnbound` (guard). After it the prefix is refused
//! first, as `LiveForkStale`. On main it still says `LiveRungUnbound` (RED).
//!
//! Test 3, a pass's call (`house_pass`), on a window the host read from
//! two CLAIMs, one of which the owner then erases (REVIEW-9900 P1 2: under
//! `auto` a stale fork's flight falls back to the cheap writer, which sent
//! the same in-memory window): the pass is refused before anything is sent,
//! while a pass of a window read from the kept row alone reaches the provider
//! (guard). Every call of a pass, its retries and waits too, asks the same
//! (REVIEW-9900 P1 1). On the round-1 head the stale window is sent (RED).
//! So is a window whose ids the caller only asserted, as an executor's are
//! (`window_read_from_sources` false): the receipt names none of them, but
//! the freshness asks still read each (REVIEW-9900 round 2); on the round-2
//! head it is sent (RED).
//!
//! Tests 4 to 6 (FIX-LIST ERASE-SERVED-KV-CACHE-REVIEW-RETRY-TEST) erase the
//! row after the call's first checks passed, where only a later ask stops it.
//!
//! Test 4, a cooldown's resend (REVIEW-9900 round 1): the provider, reached
//! through the credential broker as in test 5, refuses each pass's first
//! send for its rate, with a one-second reset. A pass of live rows waits it
//! out and is answered by its resend, each send reading the provider's key
//! (guard). For a window read from two CLAIMs, the owner erases one after
//! the first send went out; the provider holds its refusal until the erase
//! has committed, so the ladder meets the erase whenever it next asks, right
//! after the refusal or in a slice of its wait (REVIEW-9949 round 2). The
//! pass is refused for it, nothing more reaches the provider, and the resend
//! never reads the key: the ladder stops it before it goes out, not only the
//! transport's release after the key read (REVIEW-9949 round 1).
//!
//! Test 5, a brokered send (REVIEW-9900 round 2 P1 1): the one provider's
//! key is a vault secret, sent through the credential broker child against
//! the broker's TLS fake provider. The owner erases a row the window was
//! read from while the call reads that key, after the ladder's last ask:
//! the pass is refused and the provider sees nothing. A pass of live rows on
//! the same route then reaches it and is answered (guard).
//!
//! Test 6, a summary withdrawn since (REVIEW-9900 round 2 P1 3): a fork's
//! prefix was read from an epoch SUMMARY derived from one TURN. The owner
//! erases the TURN; the SUMMARY stands, marked stale and scrubbed, never a
//! deleted shell. The fork's call is then `live_fork_stale`.
//!
//! On a scratch head with those asks taken out (the ladder's `may_send`
//! always yes, no dispatch release on the run, `source_rows_withdrawn`
//! reading deleted shells only), tests 4 to 6 fail and tests 1 to 3 pass
//! (RED). With only the ladder's `may_send` taken out, test 4 alone fails:
//! its resend reads the key before the release refuses it (RED).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron-broker/test-support --test
//! live_fork_refuses_erased_prefix_source`.

#![allow(clippy::unwrap_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use engine_stack::run_on_engine_stack;
use fake_llm::FakeLlm;
use oneiron::authority::MachineRole;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{CustodyTier, SECRET_SCOPE_READ, SecretBinding};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EdgeKind,
    EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_broker::testing::{FakeProvider, FakeReply};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{BROKER_EFFECTOR, KeyDoor, VaultKeyDoor};
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::compaction_pass::{
    house_live_fork_bind, house_live_fork_request, house_pass, serve_broker,
};
use serde_json::{Value, json};
use tokio::sync::{oneshot, watch};
use zeroize::Zeroizing;

/// The self-writer frame this test's prompt package carries: a self-written
/// flight, live or not, wears it.
const SELF_WRITER_FRAME: &str =
    "You write this summary as the agent itself, in the first person, about your own run.";

/// The window each flight compacts: two turns.
const WINDOW: [&str; 2] = [
    "Log the north pier tide: 104 centimetres.",
    "Logged the north pier tide at 104 centimetres.",
];

/// The words of the CLAIM the owner erases, which only that row holds.
const ERASED_WORDS: &str = "Mara keeps her clinic visit on the ninth floor of the harbour annex.";

/// The words of the CLAIM that stays.
const KEPT_WORDS: &str = "The ferry timetable moved the last crossing to 21 40.";

/// The summary the scripted model writes of any window it is sent.
const SUMMARY: &str = "The owner logged one north pier tide reading of 104 centimetres.";

/// How long the scripted model's rate refusal says its limit lasts: well
/// inside the vault's shipped longest wait (60 s), so the ladder waits it
/// out and sends again.
const COOLDOWN_SECS: u64 = 1;

/// How long a test waits for a send it started to reach the model.
const SEND_DEADLINE: Duration = Duration::from_secs(30);

/// The words of the TURN a summary covers, which the owner then erases.
const COVERED_WORDS: &str = "Mara moved her clinic visit to the harbour annex on the ninth.";

/// The vault secret the brokered provider's key is registered under.
const KEY_HANDLE: &str = "live-fork-erase-provider-key";

/// Copies the prompt package tree at `from` to `to`.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// The workspace's test prompt package plus a self-writer frame, which the
/// package lacks: without one, self-written summaries are off (FIX 4575).
fn prompt_package_with_frame() -> tempfile::TempDir {
    let package = tempfile::tempdir().unwrap();
    copy_tree(
        &oneiron::prompt::workspace_test_prompt_package_root().unwrap(),
        package.path(),
    );
    std::fs::write(
        package
            .path()
            .join(oneiron::prompt::COMPACTION_SELF_WRITER_PROMPT_RELATIVE_PATH),
        SELF_WRITER_FRAME,
    )
    .unwrap();
    package
}

/// One local provider and no `[roles]`: code mode's compaction is live on
/// the chat role's one-rung seat under `prompts`.
fn models(base_url: &str, prompts: &Path) -> ModelsConfig {
    ModelsConfig::from_toml(
        &format!(
            "default = \"local:test-model\"\n\
             [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
             [code_mode]\nprompt_package = {:?}\n\
             [code_mode.compaction]\nwindow_tokens = 1500\nhot_steps = 1\n\
             [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
             context_tokens = 32768\n",
            prompts.display().to_string(),
        ),
        None,
    )
    .unwrap()
}

/// One provider, `paid`, an OpenAI-compatible model at `origin` whose key
/// is the vault secret [`KEY_HANDLE`], sent through the credential broker
/// child, which trusts the roots in `ca`; otherwise as [`models`].
fn brokered_models(origin: &str, ca: &Path, prompts: &Path) -> ModelsConfig {
    ModelsConfig::from_toml(
        &format!(
            "default = \"paid:test-model\"\n\
             [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
             [code_mode]\nprompt_package = {:?}\n\
             [code_mode.compaction]\nwindow_tokens = 1500\nhot_steps = 1\n\
             [providers.paid]\nkind = \"openai-compat\"\nbase_url = \"{origin}\"\n\
             key_secret = \"{KEY_HANDLE}\"\ntimeout_secs = 20\ncontext_tokens = 32768\n\
             [broker]\nprogram = \"{program}\"\nextra_roots = [\"{ca}\"]\n",
            prompts.display().to_string(),
            program = env!("CARGO_BIN_EXE_oneiron-broker"),
            ca = ca.display(),
        ),
        None,
    )
    .unwrap()
}

/// A rooted vault served with its AI host attached under `models`, as
/// `oneiron serve` starts one: the keystore before the server, then the
/// host root and this install's live machine profile.
async fn served(dir: &Path, models: &ModelsConfig) -> (Arc<SyncServer>, AiHost) {
    served_with_keys(dir, models, |_| None).await
}

/// [`served`], with the credential broker serve sets when `keys` gives a
/// custody door for the vault.
async fn served_with_keys(
    dir: &Path,
    models: &ModelsConfig,
    keys: impl FnOnce(&Arc<Vault>) -> Option<Arc<dyn KeyDoor>>,
) -> (Arc<SyncServer>, AiHost) {
    let vault = Arc::new(Vault::open(dir, VaultConfig::device()).unwrap());
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let keys = keys(&vault);
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("live-fork-refuses-erased-prefix-source".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let server = match keys {
        Some(keys) => serve_broker(server, &models.broker, keys),
        None => server,
    };
    let issuer = vault.load_host_slip_issuer().unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .unwrap();
    let (server, host) = AiHost::attach(server, Some(models)).await;
    (Arc::new(server), host)
}

/// A vault served under [`brokered_models`] for one fake provider, and the
/// directories it reads, which live as long as it.
struct Brokered {
    _host: AiHost,
    server: Arc<SyncServer>,
    _dirs: [tempfile::TempDir; 3],
}

/// [`served_with_keys`] under [`brokered_models`] for `provider`: its key is
/// the vault secret [`KEY_HANDLE`], read through the custody door `door`
/// makes of the vault's own.
async fn served_brokered(
    provider: &FakeProvider,
    door: impl FnOnce(VaultKeyDoor) -> Arc<dyn KeyDoor>,
) -> Brokered {
    let files = tempfile::tempdir().unwrap();
    let ca = files.path().join("ca.pem");
    std::fs::write(&ca, provider.ca_pem()).unwrap();
    let prompts = prompt_package_with_frame();
    let models = brokered_models(provider.origin(), &ca, prompts.path());
    let dir = tempfile::tempdir().unwrap();
    let (server, host) = served_with_keys(dir.path(), &models, |vault| {
        vault
            .register_test_secret(
                KEY_HANDLE,
                b"live-fork-erase-test-key",
                vec![SecretBinding {
                    effector: BROKER_EFFECTOR.to_owned(),
                    tier_ceiling: CustodyTier::T0Doored,
                    scopes: vec![SECRET_SCOPE_READ.to_owned()],
                }],
                1_700_000_000,
            )
            .expect("FIXTURE: the provider key is registered");
        Some(door(VaultKeyDoor::new(Arc::clone(vault))))
    })
    .await;
    Brokered {
        _host: host,
        server,
        _dirs: [files, prompts, dir],
    }
}

/// The vault's custody door, whose first key read says it has begun and
/// then waits until the test lets it go on; every later read goes straight
/// through.
struct GatedKeyDoor {
    door: VaultKeyDoor,
    gate: Mutex<Option<(oneshot::Sender<()>, Receiver<()>)>>,
}

impl KeyDoor for GatedKeyDoor {
    fn check(&self, name: &str) -> anyhow::Result<()> {
        self.door.check(name)
    }

    fn read(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let gate = self
            .gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some((began, go_on)) = gate {
            began.send(()).unwrap();
            go_on.recv().unwrap();
        }
        self.door.read(name)
    }
}

/// The vault's custody door, counting the provider key reads made through
/// it. A brokered send reads its key once the ladder has let it go out, and
/// before the transport's release asks again.
struct CountingKeyDoor {
    door: VaultKeyDoor,
    reads: Arc<AtomicUsize>,
}

impl KeyDoor for CountingKeyDoor {
    fn check(&self, name: &str) -> anyhow::Result<()> {
        self.door.check(name)
    }

    fn read(&self, name: &str) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.door.read(name)
    }
}

/// The seeded default agent: the run's writer.
fn seeded_agent(vault: &Vault) -> EntityId {
    vault
        .get_seeded_agent_definition_by_logical_id("sys.default")
        .unwrap()
        .expect("FIXTURE: sys.default is seeded on open")
        .0
}

/// The PERSON the stored CLAIMs are about.
fn stored_person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"Mara",
        )
        .expect("FIXTURE: the PERSON is stored");
    id
}

/// A CLAIM about `subject` whose value is `words`, stored in `vault`.
fn stored_claim(vault: &Vault, subject: EntityId, words: &str) -> EntityId {
    let id = EntityId::now();
    let body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        serde_json::Value::from(words),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("FIXTURE: the claim body");
    vault
        .put_claim(&id, &body, TimeRange { start: 10, end: 10 }, 10)
        .expect("FIXTURE: the CLAIM is stored");
    id
}

/// A window of `words` and the second turn, naming `rows` as the rows it
/// was read from: read by the host itself, as a conversation's is
/// (`whole`), or asserted by its caller, as an executor's is.
fn window_read_from(
    vault: &Vault,
    words: &str,
    rows: Vec<EntityId>,
    whole: bool,
) -> oneiron::compaction::CompactionRequest {
    let mut request =
        oneiron::test_doors::compaction_request::sealed_window(vault, &[words, WINDOW[1]], 200)
            .unwrap();
    request.sources = rows;
    request.window_read_from_sources = whole;
    request
}

/// The text of one request message: a string, or its text parts joined.
fn message_text(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// The scripted model's answer to a compaction call: [`SUMMARY`] of the
/// span the call's input names.
fn summary_reply(body: &Value) -> String {
    let input: Value = body["messages"]
        .as_array()
        .and_then(|messages| messages.last())
        .and_then(|message| serde_json::from_str(&message_text(message)).ok())
        .unwrap_or(Value::Null);
    json!({"from": input["from"], "through": input["through"], "summary": SUMMARY}).to_string()
}

/// The brokered provider's rate refusal, back in [`COOLDOWN_SECS`].
fn brokered_rate_limited() -> FakeReply {
    let mut reply = FakeReply::json(
        429,
        &json!({"error": {"message": "rate limit", "type": "rate_limit_error"}}),
    );
    reply
        .headers
        .push(("retry-after".to_owned(), COOLDOWN_SECS.to_string()));
    reply
}

/// The owner's privacy (GDPR) erase of `row`, confirmed from its preview.
fn privacy_erase(vault: &Vault, row: EntityId) {
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the vault owner");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let preview = memory
        .preview_entity_delete(&row)
        .expect("FIXTURE: the row previews for erase");
    memory
        .confirm_entity_erase(
            &preview,
            EraseOptions {
                reason: EraseReason::GdprDelete,
                also_same_bytes: false,
                veto_starter: None,
            },
        )
        .expect("FIXTURE: the privacy erase runs");
    assert!(
        vault.is_deleted_shell(&row).unwrap(),
        "FIXTURE: the erase leaves the row deleted"
    );
}

#[test]
fn a_flight_call_sends_no_prefix_read_from_a_row_erased_since() {
    run_on_engine_stack("live-fork-erased-prefix-call", || async {
        let fake = FakeLlm::start(Vec::new(), None).await;
        let prompts = prompt_package_with_frame();
        let dir = tempfile::tempdir().unwrap();
        let (server, _host) = served(dir.path(), &models(&fake.base_url, prompts.path())).await;
        let vault = server.vault();
        let agent = seeded_agent(vault);
        let request =
            oneiron::test_doors::compaction_request::sealed_window(vault, &WINDOW, 200).unwrap();
        let person = stored_person(vault);
        let erased = stored_claim(vault, person, ERASED_WORDS);
        let kept = stored_claim(vault, person, KEPT_WORDS);
        let live_text = format!("{ERASED_WORDS} {KEPT_WORDS}");

        let warm =
            house_live_fork_request(&server, agent, &request, &live_text, vec![erased, kept])
                .unwrap_or_else(|refusal| {
                    panic!("FIXTURE: before the erase the fork's call is built: {refusal}")
                });
        assert!(
            warm.contains(ERASED_WORDS),
            "FIXTURE: the warm copy holds the row's words: {warm}"
        );

        privacy_erase(vault, erased);

        match house_live_fork_request(&server, agent, &request, &live_text, vec![erased, kept]) {
            Err(refusal) => assert!(
                refusal.contains("live_fork_stale"),
                "a fork read from a row erased since is stale: {refusal}"
            ),
            Ok(sent) => panic!(
                "a fork read from a row erased since still sends its prefix (erased words in it: {}): {sent}",
                sent.contains(ERASED_WORDS)
            ),
        }
        let rebuilt = house_live_fork_request(&server, agent, &request, KEPT_WORDS, vec![kept])
            .unwrap_or_else(|refusal| panic!("the clean rebuild's call is built: {refusal}"));
        assert!(
            rebuilt.contains(KEPT_WORDS) && !rebuilt.contains(ERASED_WORDS),
            "the clean rebuild holds the kept row's words and none of the erased: {rebuilt}"
        );
        assert!(
            fake.seen().is_empty(),
            "nothing was sent to the provider: {} requests",
            fake.seen().len()
        );
    });
}

#[test]
fn a_breakpoint_binds_no_fork_read_from_a_row_erased_since() {
    run_on_engine_stack("live-fork-erased-prefix-bind", || async {
        let fake = FakeLlm::start(Vec::new(), None).await;
        let prompts = prompt_package_with_frame();
        let dir = tempfile::tempdir().unwrap();
        let (server, _host) = served(dir.path(), &models(&fake.base_url, prompts.path())).await;
        let vault = server.vault();
        let agent = seeded_agent(vault);
        let request =
            oneiron::test_doors::compaction_request::sealed_window(vault, &WINDOW, 200).unwrap();
        let person = stored_person(vault);
        let erased = stored_claim(vault, person, ERASED_WORDS);
        let kept = stored_claim(vault, person, KEPT_WORDS);
        let live_text = format!("{ERASED_WORDS} {KEPT_WORDS}");

        let before = house_live_fork_bind(&server, agent, &request, &live_text, vec![erased, kept])
            .unwrap_err();
        assert_eq!(
            before, "LiveRungUnbound",
            "FIXTURE: before the erase the bind gets past the prefix's checks"
        );

        privacy_erase(vault, erased);

        let after = house_live_fork_bind(&server, agent, &request, &live_text, vec![erased, kept])
            .unwrap_err();
        assert_eq!(
            after, "LiveForkStale",
            "a breakpoint binds no fork read from a row erased since"
        );
    });
}

#[test]
fn a_pass_sends_no_window_read_from_a_row_erased_since() {
    run_on_engine_stack("live-fork-erased-window-pass", || async {
        let fake = FakeLlm::start(Vec::new(), None).await;
        let prompts = prompt_package_with_frame();
        let dir = tempfile::tempdir().unwrap();
        let (server, _host) = served(dir.path(), &models(&fake.base_url, prompts.path())).await;
        let vault = server.vault();
        let person = stored_person(vault);
        let erased = stored_claim(vault, person, ERASED_WORDS);
        let kept = stored_claim(vault, person, KEPT_WORDS);
        let stale = window_read_from(vault, ERASED_WORDS, vec![erased, kept], true);
        let asserted = window_read_from(vault, ERASED_WORDS, vec![erased, kept], false);
        let clean = window_read_from(vault, KEPT_WORDS, vec![kept], true);

        privacy_erase(vault, erased);

        let refused = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || house_pass(&server, &stale))
                .await
                .unwrap()
        };
        match refused {
            Err(refusal) => assert!(
                refusal.contains("deleted since"),
                "a pass of a window read from a row erased since is refused unsent: {refusal}"
            ),
            Ok(answer) => panic!(
                "a pass of a window read from a row erased since was served: {}",
                answer.summary
            ),
        }
        assert!(
            fake.seen().is_empty(),
            "a window read from a row erased since reached the provider: {} requests",
            fake.seen().len()
        );

        let asserted_pass = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || house_pass(&server, &asserted))
                .await
                .unwrap()
        };
        assert!(
            asserted_pass.is_err() && fake.seen().is_empty(),
            "a window whose asserted ids name a row erased since reached the provider: {} \
             requests",
            fake.seen().len()
        );

        let _clean_pass = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || house_pass(&server, &clean))
                .await
                .unwrap()
        };
        assert!(
            !fake.seen().is_empty(),
            "FIXTURE: a pass of a window read from live rows reaches the provider"
        );
    });
}

#[test]
fn a_pass_resends_no_window_read_from_a_row_erased_before_its_rate_retry() {
    run_on_engine_stack("live-fork-erased-before-rate-retry", || async {
        let provider = FakeProvider::start(FakeReply::json(500, &json!({})));
        // Each pass's first send is refused for its rate; its resend is
        // answered. The second pass's refusal is held until the owner's
        // erase has committed, so the ladder decides on its retry (it asks
        // `may_send` before each rung and in each slice of the wait) only
        // after the erase, however the threads are scheduled.
        let (arrived, mut requests) = watch::channel(0_usize);
        let (erase_committed, erase_seen) = channel::<()>();
        let held = Arc::new(AtomicBool::new(false));
        let held_by_provider = Arc::clone(&held);
        provider.respond_with(move |request| {
            let mut count = 0;
            arrived.send_modify(|seen| {
                *seen += 1;
                count = *seen;
            });
            match count {
                1 => brokered_rate_limited(),
                3 => {
                    let erased_first = erase_seen.recv_timeout(SEND_DEADLINE).is_ok();
                    held_by_provider.store(erased_first, Ordering::SeqCst);
                    brokered_rate_limited()
                }
                _ => brokered_answer(request),
            }
        });
        let reads = Arc::new(AtomicUsize::new(0));
        let door_reads = Arc::clone(&reads);
        let brokered = served_brokered(&provider, move |door| {
            Arc::new(CountingKeyDoor {
                door,
                reads: door_reads,
            })
        })
        .await;
        let server = Arc::clone(&brokered.server);
        let vault = server.vault();
        let person = stored_person(vault);
        let erased = stored_claim(vault, person, ERASED_WORDS);
        let kept = stored_claim(vault, person, KEPT_WORDS);
        let clean = window_read_from(vault, KEPT_WORDS, vec![kept], true);
        let stale = window_read_from(vault, ERASED_WORDS, vec![erased, kept], true);

        // Guard: a pass whose first send is refused for its rate waits the
        // limit out and sends the same window again, which is answered; each
        // send reads the provider's key.
        let reads_before = reads.load(Ordering::SeqCst);
        let resent = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || house_pass(&server, &clean))
                .await
                .unwrap()
        };
        let answer = resent.unwrap_or_else(|refusal| {
            panic!(
                "FIXTURE: a rate-refused pass of live rows is answered after the wait: {refusal}"
            )
        });
        assert!(
            answer.summary.contains(SUMMARY) && provider.seen().len() == 2,
            "FIXTURE: the cooldown's resend went out and was answered: {} requests, {answer:?}",
            provider.seen().len()
        );
        assert_eq!(
            reads.load(Ordering::SeqCst) - reads_before,
            2,
            "FIXTURE: each send of the pass read the provider's key"
        );

        // The same refusal for the window read from both rows; the owner
        // erases one after the first send went out and before the provider's
        // refusal reaches the ladder.
        let reads_before = reads.load(Ordering::SeqCst);
        let pass = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || house_pass(&server, &stale))
        };
        let reached = tokio::time::timeout(SEND_DEADLINE, requests.wait_for(|seen| *seen >= 3))
            .await
            .is_ok_and(|seen| seen.is_ok());
        assert!(
            reached,
            "FIXTURE: the pass's first send reaches the provider"
        );
        privacy_erase(vault, erased);
        erase_committed
            .send(())
            .expect("FIXTURE: the provider still holds the first send's refusal");
        let outcome = pass.await.unwrap();
        assert!(
            held.load(Ordering::SeqCst),
            "FIXTURE: the provider held the first send's refusal until the erase committed"
        );
        match outcome {
            Err(refusal) => assert!(
                refusal.contains("deleted since"),
                "a pass whose row was erased before its rate retry is refused for it: {refusal}"
            ),
            Ok(answer) => panic!(
                "a pass whose row was erased before its rate retry was served: {}",
                answer.summary
            ),
        }
        assert_eq!(
            provider.seen().len(),
            3,
            "the rate retry of a window read from a row erased since went out"
        );
        assert_eq!(
            reads.load(Ordering::SeqCst) - reads_before,
            1,
            "the rate retry of a window read from a row erased since got past the ladder: it \
             read the provider's key, and only the transport's release kept it in"
        );
    });
}

/// The brokered provider's answer to a buffered OpenAI-compatible
/// compaction call: [`summary_reply`] as the one choice's message.
fn brokered_answer(seen: &oneiron_broker::testing::SeenRequest) -> FakeReply {
    let body: Value = serde_json::from_slice(&seen.body).unwrap_or(Value::Null);
    FakeReply::json(
        200,
        &json!({
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "model": "test-model",
            "choices": [{
                "index": 0,
                "message": {"role": "assistant", "content": summary_reply(&body)},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 40, "completion_tokens": 12, "total_tokens": 52},
        }),
    )
}

#[test]
fn a_broker_send_writes_no_window_read_from_a_row_erased_during_its_key_read() {
    run_on_engine_stack("live-fork-erased-during-key-read", || async {
        let provider = FakeProvider::start(FakeReply::json(500, &json!({})));
        provider.respond_with(brokered_answer);
        let (began_tx, began) = oneshot::channel();
        let (go_on, go_on_rx) = channel();
        let brokered = served_brokered(&provider, |door| {
            Arc::new(GatedKeyDoor {
                door,
                gate: Mutex::new(Some((began_tx, go_on_rx))),
            })
        })
        .await;
        let server = Arc::clone(&brokered.server);
        let vault = server.vault();
        let person = stored_person(vault);
        let erased = stored_claim(vault, person, ERASED_WORDS);
        let kept = stored_claim(vault, person, KEPT_WORDS);
        let stale = window_read_from(vault, ERASED_WORDS, vec![erased, kept], true);
        let clean = window_read_from(vault, KEPT_WORDS, vec![kept], true);

        // The pass gets past every check before its send and reads the
        // provider's key; the owner erases one of its rows during that read.
        let mut pass = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || house_pass(&server, &stale))
        };
        tokio::select! {
            began = tokio::time::timeout(SEND_DEADLINE, began) => assert!(
                matches!(began, Ok(Ok(()))),
                "FIXTURE: the brokered pass reads its provider key"
            ),
            _ = &mut pass => {
                panic!("FIXTURE: the brokered pass ended before it read its provider key")
            }
        }
        privacy_erase(vault, erased);
        go_on.send(()).unwrap();
        match pass.await.unwrap() {
            Err(refusal) => assert!(
                refusal.contains("deleted since"),
                "a broker send whose row was erased during its key read is refused for it: \
                 {refusal}"
            ),
            Ok(answer) => panic!(
                "a broker send whose row was erased during its key read was served: {}",
                answer.summary
            ),
        }
        assert!(
            provider.seen().is_empty(),
            "a window read from a row erased during the key read reached the provider: {} \
             requests",
            provider.seen().len()
        );

        // Guard: the same broker route sends a window of live rows, and its
        // provider answers it.
        let served = {
            let server = Arc::clone(&server);
            tokio::task::spawn_blocking(move || house_pass(&server, &clean))
                .await
                .unwrap()
        };
        let answer = served.unwrap_or_else(|refusal| {
            panic!("FIXTURE: a brokered pass of live rows is served: {refusal}")
        });
        assert!(
            answer.summary.contains(SUMMARY) && provider.seen().len() == 1,
            "FIXTURE: the brokered pass went out once and was answered: {} requests, {answer:?}",
            provider.seen().len()
        );
    });
}

#[test]
fn a_flight_call_sends_no_prefix_read_from_a_summary_withdrawn_since() {
    run_on_engine_stack("live-fork-withdrawn-summary-prefix", || async {
        let fake = FakeLlm::start(Vec::new(), None).await;
        let prompts = prompt_package_with_frame();
        let dir = tempfile::tempdir().unwrap();
        let (server, _host) = served(dir.path(), &models(&fake.base_url, prompts.path())).await;
        let vault = server.vault();
        let agent = seeded_agent(vault);
        let request =
            oneiron::test_doors::compaction_request::sealed_window(vault, &WINDOW, 200).unwrap();
        let owner = vault
            .ensure_embedded_owner_actor()
            .expect("FIXTURE: the vault owner");
        // A TURN, and an epoch SUMMARY of it derived from it, as a
        // conversation's compaction lands one in place of the turns it
        // covers. The fork's prefix was read from the SUMMARY alone.
        let turn = oneiron::test_doors::derive::witness_turn(vault, COVERED_WORDS)
            .expect("FIXTURE: the TURN is witnessed");
        let summary = oneiron::test_doors::epoch_lineage_pointer::put_inline_epoch(
            vault,
            &EntityId::now(),
            None,
            1,
            1,
            1,
            COVERED_WORDS,
            &owner,
        )
        .expect("FIXTURE: the epoch SUMMARY is stored");
        vault
            .put_edge(&summary, EdgeKind::DerivedFrom, &turn, 1.0)
            .expect("FIXTURE: the SUMMARY is derived from the TURN");

        let warm = house_live_fork_request(&server, agent, &request, COVERED_WORDS, vec![summary])
            .unwrap_or_else(|refusal| {
                panic!("FIXTURE: before the erase the fork's call is built: {refusal}")
            });
        assert!(
            warm.contains(COVERED_WORDS),
            "FIXTURE: the warm copy holds the summary's words: {warm}"
        );

        privacy_erase(vault, turn);
        assert!(
            !vault.is_deleted_shell(&summary).unwrap(),
            "FIXTURE: the erase of the TURN withdraws its SUMMARY and leaves it standing"
        );

        match house_live_fork_request(&server, agent, &request, COVERED_WORDS, vec![summary]) {
            Err(refusal) => assert!(
                refusal.contains("live_fork_stale"),
                "a fork read from a summary withdrawn since is stale: {refusal}"
            ),
            Ok(sent) => panic!(
                "a fork read from a summary withdrawn since still sends its prefix (covered words \
                 in it: {}): {sent}",
                sent.contains(COVERED_WORDS)
            ),
        }
        assert!(
            fake.seen().is_empty(),
            "nothing was sent to the provider: {} requests",
            fake.seen().len()
        );
    });
}
