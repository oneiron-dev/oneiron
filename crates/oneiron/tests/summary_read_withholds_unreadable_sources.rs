//! The summary read doors serve a summary only to a reader of every source.
//!
//! Canon arch-0006a #dag-summaries-built
//! (`oneiron/backend/oneiron-arch-0006a-conversations-api-core.md:142`): "A
//! reader sees a summary, its reply or its merge header only while it may
//! read every source." `vault.summaries.read` and `vault.get` read a SUMMARY
//! through the caller's lane, whose row admission also admits each record the
//! summary's words came from (`claim/scoped_read/visibility.rs`,
//! `derived_sources_readable_in`). The declaration half (create refuses a
//! source its caller cannot read) and the context-pack clamp
//! (`disclosure_summary_word_sources.rs`) are pinned elsewhere; this file pins
//! the read half.
//!
//! The readers are credentials of the vault owner narrowed by a records
//! caveat, as a transport verifies a request's slip
//! (`engine_owned_input_rules.rs`, `key_value_credential_read.rs`). A
//! narrowed owner credential is not the owner's own key, so the sources are
//! judged one by one (the owner's own key reads every source but a
//! use-limited one or a private thread's turn). R1 names the summary and both
//! trunk records; R2 names the summary and one of them.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test summary_read_withholds_unreadable_sources`
#![cfg(oneiron_test_support)]

use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::memory::Memory;
use oneiron::test_doors::scope_summary::mint_born_scope_summary;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_testkit::door;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CHALLENGE: &[u8] = b"oneiron-request:summary-read-withholds-unreadable-sources";

/// The minted summary's text.
const TEXT: &str = "The plan, and its first step.";

/// A rooted vault, a two-record trunk the owner wrote, and a scope summary
/// over it, minted as the Dreamer writes one and born with its document.
/// The vault closes before its directory goes.
struct Fixture {
    vault: Vault,
    issuer: HostSlipIssuer,
    owner: EntityId,
    trunk: [EntityId; 2],
    summary: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    // The server roots its vault and provisions the engine's MACHINE writers
    // on every open; the summary is minted under the Dreamer's authority.
    let issuer = provision_engine_machines(&vault);
    bind_host_owner(&vault, &issuer, owner)?;
    let (conversation, trunk) = {
        let host = vault.memory(owner, EdgeActorClass::Human);
        let receipt = host.conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({}),
            text: None,
        })?;
        let conversation = EntityId::from_hex(&receipt.id)?;
        let first =
            host.conversations_records_append(&trunk_record(conversation, None, "the plan"))?;
        let second = host.conversations_records_append(&trunk_record(
            conversation,
            Some(&first.id),
            "the first step",
        ))?;
        (
            conversation,
            [
                EntityId::from_hex(&first.id)?,
                EntityId::from_hex(&second.id)?,
            ],
        )
    };
    let summary = mint_born_scope_summary(
        &vault,
        &ScopeSelector {
            conversation,
            session: None,
            path: ScopePath::Canonical,
            include_forks: false,
        },
        TEXT,
    )?;
    Ok(Fixture {
        vault,
        issuer,
        owner,
        trunk,
        summary,
        _dir: dir,
    })
}

/// One trunk record that advances HEAD from `parent`.
fn trunk_record(conversation: EntityId, parent: Option<&str>, text: &str) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: parent.map(str::to_owned),
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": text, "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    }
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The owner's handle bound to a live `human` credential the host mints
/// from its root claims, held by a records caveat to `records`, verified as a
/// transport verifies the slip a request presents.
fn narrowed_owner<'v>(fixture: &'v Fixture, records: &[EntityId]) -> Memory<'v> {
    let mut claims = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = fixture.owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = records.iter().map(EntityId::to_hex).collect();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("mint the credential");
    let binding = fixture
        .issuer
        .binding_proof(&slip, CHALLENGE)
        .expect("the binding proof");
    let proof: VerifiedSlip = fixture
        .vault
        .verify_capability_slip(&fixture.issuer.public_key(), &slip, CHALLENGE, &binding)
        .expect("verify the credential");
    fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .with_read_proof(&proof)
}

/// `reader`'s `vault.get` of `id`.
fn get(reader: &Memory<'_>, id: &EntityId) -> Value {
    door::invoke(reader, "vault.get", json!({ "entity_ref": id.to_hex() }))
        .unwrap_or_else(|error| panic!("vault.get answers an error: {error:?}"))
}

/// `reader`'s `vault.summaries.read` of `summary`.
fn summaries_read(reader: &Memory<'_>, summary: &EntityId) -> Value {
    door::invoke(
        reader,
        "vault.summaries.read",
        json!({ "summary_ref": summary.to_hex() }),
    )
    .unwrap_or_else(|error| panic!("vault.summaries.read answers an error: {error:?}"))
}

/// A served `vault.get` names the row.
fn assert_served(read: &Value, id: &EntityId, what: &str) {
    assert_eq!(
        read.pointer("/value/id_hex"),
        Some(&json!(id.to_hex())),
        "{what}: {read}"
    );
}

/// A withheld read answers its receipt and no value, as an absent row does.
fn assert_withheld(read: &Value, what: &str) {
    assert!(
        read.get("narrowing").is_some(),
        "{what} answers no read receipt: {read}"
    );
    assert!(read["value"].is_null(), "{what} is served: {read}");
}

/// A served `vault.summaries.read` carries the summary's text and covers.
fn assert_text_served(read: &Value, fixture: &Fixture, what: &str) {
    assert_eq!(
        read.pointer("/value/text"),
        Some(&json!(TEXT)),
        "{what}: {read}"
    );
    assert_eq!(
        read.pointer("/value/covers"),
        Some(&json!([
            fixture.trunk[0].to_hex(),
            fixture.trunk[1].to_hex()
        ])),
        "{what}: {read}"
    );
}

/// R1: a credential that reads the summary and every source it was written
/// from reads its text and its row.
#[test]
fn a_reader_of_every_source_sees_the_summary() -> TestResult {
    let fixture = open()?;
    let [plan, step] = fixture.trunk;
    let r1 = narrowed_owner(&fixture, &[fixture.owner, fixture.summary, plan, step]);
    assert_served(&get(&r1, &plan), &plan, "R1 reads the first trunk record");
    assert_served(&get(&r1, &step), &step, "R1 reads the second trunk record");
    assert_text_served(
        &summaries_read(&r1, &fixture.summary),
        &fixture,
        "R1 reads the summary's text",
    );
    assert_served(
        &get(&r1, &fixture.summary),
        &fixture.summary,
        "R1 reads the summary's row",
    );
    Ok(())
}

/// R2: a credential that reads the summary's row by its own gates but not one
/// of its sources is withheld the summary on both doors, as an absent row
/// is, and is not told which source it lacks.
#[test]
fn a_reader_missing_one_source_is_withheld_the_summary() -> TestResult {
    let fixture = open()?;
    let [plan, step] = fixture.trunk;
    let r2 = narrowed_owner(&fixture, &[fixture.owner, fixture.summary, plan]);
    // The setup: R2 reads the source its caveat names, not the other one.
    assert_served(&get(&r2, &plan), &plan, "R2 reads the named trunk record");
    assert_withheld(&get(&r2, &step), "R2's read of the unnamed trunk record");
    // The promise.
    let read = summaries_read(&r2, &fixture.summary);
    assert_withheld(&read, "R2's read of the summary's text");
    assert!(
        !read.to_string().contains(TEXT) && !read.to_string().contains(&step.to_hex()),
        "the withheld read carries neither the text nor the source: {read}"
    );
    assert_withheld(
        &get(&r2, &fixture.summary),
        "R2's read of the summary's row",
    );
    Ok(())
}

/// The owner's own key reads the summary of the owner's own conversation.
#[test]
fn the_owner_sees_the_summary() -> TestResult {
    let fixture = open()?;
    let owner = door::owner(&fixture.vault)?;
    assert_text_served(
        &summaries_read(&owner, &fixture.summary),
        &fixture,
        "the owner reads the summary's text",
    );
    assert_served(
        &get(&owner, &fixture.summary),
        &fixture.summary,
        "the owner reads the summary's row",
    );
    Ok(())
}
