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
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test live_fork_refuses_erased_prefix_source`.

#![allow(clippy::unwrap_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::path::Path;
use std::sync::Arc;

use engine_stack::run_on_engine_stack;
use fake_llm::FakeLlm;
use oneiron::authority::MachineRole;
use oneiron::memory::{EraseOptions, EraseReason};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::compaction_pass::{
    house_live_fork_bind, house_live_fork_request, house_pass,
};

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

/// A rooted vault served with its AI host attached under `models`, as
/// `oneiron serve` starts one: the keystore before the server, then the
/// host root and this install's live machine profile.
async fn served(dir: &Path, models: &ModelsConfig) -> (Arc<SyncServer>, AiHost) {
    let vault = Arc::new(Vault::open(dir, VaultConfig::device()).unwrap());
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("live-fork-refuses-erased-prefix-source".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let issuer = vault.load_host_slip_issuer().unwrap();
    vault.ensure_host_root_slip(&issuer).unwrap();
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .unwrap();
    let (server, host) = AiHost::attach(server, Some(models)).await;
    (Arc::new(server), host)
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
        rmpv::Value::from(words),
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
        // A window that names the rows it was read from: read by the host
        // itself, as a conversation's is (`whole`), or asserted by its
        // caller, as an executor's is.
        let window_read_from = |words: &str, rows: Vec<EntityId>, whole: bool| {
            let mut request = oneiron::test_doors::compaction_request::sealed_window(
                vault,
                &[words, WINDOW[1]],
                200,
            )
            .unwrap();
            request.sources = rows;
            request.window_read_from_sources = whole;
            request
        };
        let stale = window_read_from(ERASED_WORDS, vec![erased, kept], true);
        let asserted = window_read_from(ERASED_WORDS, vec![erased, kept], false);
        let clean = window_read_from(KEPT_WORDS, vec![kept], true);

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
