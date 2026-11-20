//! A scope summary whose text was left blank reads as an empty text on every
//! read door (FIX SUMMARY-BLANK-DOCUMENT-TEXT-REFUSES-EVERY-READ; Engine
//! ANSWER 21 Nov 01:45 = A).
//!
//! A scope summary's text is its entity document's: the read doors resolve
//! the stored row against the document and decode the result
//! (`entity_doc/storage.rs` `resolve_record_body`). The Dreamer never mints a
//! blank text (the codec's encode refuses one), but the text is editable:
//! the owner's anchored edit (`vault.summaries.edit`) may replace all of it
//! with nothing, and a device sync merge of two deletes, neither of which
//! blanks it alone, blanks it with no door to stop it. On main the codec's
//! decode refused a blank text too, so after either one the summary
//! answered an error on every strict read: the owner's own read and the
//! edit door's read-back, the keep door's read-back, and the word-source
//! check that serves it to a reader of every source. Option A: decoding a
//! resolved body accepts a blank text, and the refusal stays on the mint.
//!
//! The summary is minted as the Dreamer writes one and born with its
//! document (`test_doors::scope_summary::mint_born_scope_summary`), over a
//! two-record trunk the owner wrote. The non-owner-key reader is the owner's
//! credential narrowed by a records caveat to the summary and both trunk
//! records, as `summary_read_withholds_unreadable_sources.rs` builds it: its
//! read of a summary is judged source by source.
//!
//! The sync case seeds one vault and copies it, closed, to a second
//! directory, as `room_pins_concurrent_merge.rs` does, so both machines hold
//! the same summary document. Each machine deletes one part of the text on
//! the sync text plane (`EntityDocument::edit_text`); the first then joins
//! the second's UPDATE (`EntityDocument::import`), and the joined text is
//! empty.
//!
//! On main the first two tests fail (the edit door answers an error after
//! its edit landed; the owner's read of the merged summary refuses); the
//! third guards the mint's refusal.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test summary_blank_text_reads_empty`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::memory::Memory;
use oneiron::scope_summary::{
    SummaryEdit, SummaryEditRequest, SummaryKeepRequest, SummaryReadRequest, SummarySpan,
};
use oneiron::store::GateDecisionId;
use oneiron::sync::bridge::Materializer;
use oneiron::sync::documents::EntityDocument;
use oneiron::sync::manager::WindowManager;
use oneiron::sync::transport::{decode_document, document_sub_tags};
use oneiron::test_doors::scope_summary::mint_born_scope_summary;
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig, WriteActor};
use oneiron_testkit::door;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CHALLENGE: &[u8] = b"oneiron-request:summary-blank-text-reads-empty";

/// The minted summary's text.
const TEXT: &str = "The plan, and its first step.";
/// The Unicode scalars of [`TEXT`] up to and including its comma: one
/// machine deletes these, the other the rest.
const FIRST_PART: usize = 9;
/// The keep memo the owner writes on the blank summary.
const KEEP: &str = "Keep the plan's first step.";
/// The vault's directory inside each machine's temp dir.
const VAULT_DIR: &str = "vault";

/// What the seed wrote: the owner, a conversation with a two-record trunk the
/// owner wrote, and a scope summary over it, born with its document.
#[derive(Clone, Copy)]
struct Seeded {
    owner: EntityId,
    conversation: EntityId,
    trunk: [EntityId; 2],
    summary: EntityId,
}

/// A rooted vault at `dir` with its owner bound under the host root, the
/// owner's two-record trunk, and the summary over it. Returns the vault and
/// the host's issuer, which mints the narrowed reader's credential.
fn seed(dir: &Path) -> TestResult<(Vault, HostSlipIssuer, Seeded)> {
    let vault = Vault::open_owned(dir, VaultConfig::default())?;
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
    let summary = mint_born_scope_summary(&vault, &canonical(conversation), TEXT)?;
    Ok((
        vault,
        issuer,
        Seeded {
            owner,
            conversation,
            trunk,
            summary,
        },
    ))
}

fn canonical(conversation: EntityId) -> ScopeSelector {
    ScopeSelector {
        conversation,
        session: None,
        path: ScopePath::Canonical,
        include_forks: false,
    }
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

/// The owner in person: the owner's handle carrying the owner's
/// authenticated proof, so an anchored edit merges at once.
fn owner_in_person(vault: &Vault, owner: EntityId) -> Memory<'_> {
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("the owner authenticates");
    vault
        .memory(owner, EdgeActorClass::Human)
        .with_owner_authorship(&proof)
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The owner's handle bound to a live `human` credential the host mints
/// from its root claims, held by a records caveat to `records`, verified as a
/// transport verifies the slip a request presents.
fn narrowed_owner<'v>(
    vault: &'v Vault,
    issuer: &HostSlipIssuer,
    owner: EntityId,
    records: &[EntityId],
) -> Memory<'v> {
    let mut claims = vault
        .ensure_host_root_slip(issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = records.iter().map(EntityId::to_hex).collect();
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("mint the credential");
    let binding = issuer
        .binding_proof(&slip, CHALLENGE)
        .expect("the binding proof");
    let proof: VerifiedSlip = vault
        .verify_capability_slip(&issuer.public_key(), &slip, CHALLENGE, &binding)
        .expect("verify the credential");
    vault
        .memory(owner, EdgeActorClass::Human)
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

fn covers(seeded: &Seeded) -> Vec<String> {
    seeded.trunk.iter().map(EntityId::to_hex).collect()
}

/// The owner's read of `seeded`'s summary on the summary door: the value,
/// with an anchor over each of `spans`.
fn owner_reads(
    owner: &Memory<'_>,
    seeded: &Seeded,
    spans: Vec<SummarySpan>,
    what: &str,
) -> oneiron::scope_summary::SummaryReadView {
    match owner.read_summary(&SummaryReadRequest {
        summary_ref: seeded.summary.to_hex(),
        spans,
    }) {
        Ok(read) => read
            .value
            .unwrap_or_else(|| panic!("{what}: the owner's read of the summary is withheld")),
        Err(error) => panic!("{what}: the owner's read of the summary refuses: {error:?}"),
    }
}

/// Every read of `seeded`'s summary on `vault`, whose text is now empty,
/// serves it with the empty text and its covers: the owner's read, the keep
/// door and its read-back, the owner's `vault.get`, and a reader of every
/// source on both read doors.
fn assert_reads_as_empty_text(vault: &Vault, issuer: &HostSlipIssuer, seeded: &Seeded, how: &str) {
    let owner = owner_in_person(vault, seeded.owner);
    let view = owner_reads(&owner, seeded, Vec::new(), how);
    assert_eq!(view.text, "", "{how}: the owner reads the summary's text");
    assert_eq!(
        view.covers,
        covers(seeded),
        "{how}: the owner reads the summary's covers"
    );
    let kept = owner
        .set_summary_keep(&SummaryKeepRequest {
            summary_ref: seeded.summary.to_hex(),
            frontier: view.frontier,
            keep: KEEP.to_owned(),
        })
        .unwrap_or_else(|error| {
            panic!("{how}: the owner's keep memo on the summary answers an error: {error:?}")
        });
    assert_eq!(kept.keep, KEEP, "{how}: the keep door's read-back");
    let after = owner_reads(&owner, seeded, Vec::new(), how);
    assert_eq!(
        (after.text.as_str(), after.metadata.keep.as_str()),
        ("", KEEP),
        "{how}: the owner reads the kept summary"
    );
    assert_served(
        &get(&owner, &seeded.summary),
        &seeded.summary,
        &format!("{how}: the owner's vault.get of the summary"),
    );
    let [plan, step] = seeded.trunk;
    let reader = narrowed_owner(
        vault,
        issuer,
        seeded.owner,
        &[seeded.owner, seeded.summary, plan, step],
    );
    let read = summaries_read(&reader, &seeded.summary);
    assert_eq!(
        read.pointer("/value/text"),
        Some(&json!("")),
        "{how}: a reader of every source reads the summary's text: {read}"
    );
    assert_eq!(
        read.pointer("/value/covers"),
        Some(&json!(covers(seeded))),
        "{how}: a reader of every source reads the summary's covers: {read}"
    );
    assert_served(
        &get(&reader, &seeded.summary),
        &seeded.summary,
        &format!("{how}: a reader of every source reads the summary's row"),
    );
}

/// The owner replaces the summary's whole text with nothing through the
/// public edit door: the edit merges at once, and the door answers with its
/// proposal. Then every read serves the summary with an empty text.
#[test]
fn an_owner_edit_that_blanks_a_summary_leaves_it_readable_as_an_empty_text() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, issuer, seeded) = seed(dir.path())?;
    let owner = owner_in_person(&vault, seeded.owner);
    let before = owner_reads(
        &owner,
        &seeded,
        vec![SummarySpan {
            start: 0,
            end: TEXT.chars().count(),
        }],
        "before the edit",
    );
    assert_eq!(before.text, TEXT, "FIXTURE: the minted summary's text");
    let whole = before
        .anchors
        .into_iter()
        .next()
        .expect("FIXTURE: an anchor over the summary's whole text");
    let edited = owner.edit_summary(&SummaryEditRequest {
        summary_ref: seeded.summary.to_hex(),
        base: before.frontier,
        edits: vec![SummaryEdit::ReplaceQuotedSpan {
            span: whole,
            text: String::new(),
        }],
    });
    // The edit lands whatever the door answers: its merge commits before the
    // door reads its proposal back.
    assert_eq!(
        vault.entity_text(&seeded.summary)?,
        "",
        "FIXTURE: the owner's edit merged, and the summary's text is empty"
    );
    if let Err(error) = edited {
        panic!("the owner's edit that blanked the summary answers an error: {error:?}");
    }
    assert_reads_as_empty_text(&vault, &issuer, &seeded, "after the owner's edit");
    Ok(())
}

/// One machine of the vault: its vault, and its live window manager, whose
/// document registry carries the sync text plane.
struct Machine {
    vault: Arc<Vault>,
    manager: Arc<WindowManager>,
    _dir: tempfile::TempDir,
}

impl Machine {
    fn open(dir: tempfile::TempDir, user: &str) -> TestResult<Self> {
        let vault = Arc::new(Vault::open_owned(
            dir.path().join(VAULT_DIR),
            VaultConfig::default(),
        )?);
        let manager = Arc::new(WindowManager::new(
            Arc::clone(&vault),
            Arc::new(Materializer::new()),
            user,
        ));
        Ok(Self {
            vault,
            manager,
            _dir: dir,
        })
    }

    /// The summary's live editable document on this machine.
    fn document(&self, summary: EntityId) -> TestResult<Arc<EntityDocument>> {
        Ok(self.manager.documents().open(summary)?)
    }
}

/// Copies the closed vault directory `from` into `to`, file by file, as the
/// testkit's fixture copy does. The lock file goes too: the root preflight
/// refuses a data file without one. The seed vault was closed with no live
/// transaction, so the copy holds no reader that LMDB would wait on.
fn copy_vault_dir(from: &Path, to: &Path) -> TestResult {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_vault_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Two machines of one seeded vault, each holding the same summary
/// document, and the host's issuer.
fn two_machines() -> TestResult<(Machine, Machine, HostSlipIssuer, Seeded)> {
    let first_dir = tempfile::tempdir()?;
    let first_vault = first_dir.path().join(VAULT_DIR);
    std::fs::create_dir_all(&first_vault)?;
    let (issuer, seeded) = {
        let (vault, issuer, seeded) = seed(&first_vault)?;
        drop(vault);
        (issuer, seeded)
    };
    let mut beside = Vec::new();
    for entry in std::fs::read_dir(first_dir.path())? {
        let name = entry?.file_name();
        if name != VAULT_DIR {
            beside.push(name);
        }
    }
    if !beside.is_empty() {
        return Err(format!(
            "FIXTURE: the seed left {beside:?} beside the vault (key custody or a page seal): a copy would share those keys"
        )
        .into());
    }
    let second_dir = tempfile::tempdir()?;
    let second_vault = second_dir.path().join(VAULT_DIR);
    std::fs::create_dir_all(&second_vault)?;
    copy_vault_dir(&first_vault, &second_vault)?;
    let first = Machine::open(first_dir, "machine-a")?;
    let second = Machine::open(second_dir, "machine-b")?;
    Ok((first, second, issuer, seeded))
}

/// While apart, the first machine deletes the text up to its comma and the
/// second the rest: each leaves words. The first joins the second's UPDATE,
/// as a sync connection carries it, and the merged text is empty. Then every
/// read on the first machine serves the summary with an empty text.
#[test]
fn a_sync_merge_that_blanks_a_summary_leaves_it_readable_as_an_empty_text() -> TestResult {
    let (first, second, issuer, seeded) = two_machines()?;
    let author = WriteActor::new(seeded.owner, EdgeActorClass::Human);
    let ours = first.document(seeded.summary)?;
    let theirs = second.document(seeded.summary)?;
    assert_eq!(ours.text()?, TEXT, "FIXTURE: the first machine's summary");
    assert_eq!(
        theirs.text()?,
        TEXT,
        "FIXTURE: the second machine's summary"
    );
    ours.edit_text(author, first.vault.now_recorded_at(), 0, FIRST_PART, "")?;
    let rest = TEXT.chars().count() - FIRST_PART;
    let frame = theirs.edit_text(author, second.vault.now_recorded_at(), FIRST_PART, rest, "")?;
    assert_eq!(
        ours.text()?,
        " and its first step.",
        "FIXTURE: the first machine's delete leaves words"
    );
    assert_eq!(
        theirs.text()?,
        "The plan,",
        "FIXTURE: the second machine's delete leaves words"
    );
    let carried = decode_document(&frame[1..]).map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        (carried.entity, carried.kind),
        (seeded.summary, document_sub_tags::UPDATE),
        "FIXTURE: the second machine's edit frame is the summary's UPDATE"
    );
    ours.import(document_sub_tags::UPDATE, carried.payload)?;
    assert_eq!(
        first.vault.entity_text(&seeded.summary)?,
        "",
        "FIXTURE: the joined text is empty"
    );
    assert_reads_as_empty_text(&first.vault, &issuer, &seeded, "after the sync merge");
    Ok(())
}

/// The Dreamer's mint still refuses a blank text: only an edit or a merge of
/// the minted text may leave one.
#[test]
fn a_summary_is_never_minted_with_a_blank_text() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (vault, _issuer, seeded) = seed(dir.path())?;
    let minted = mint_born_scope_summary(&vault, &canonical(seeded.conversation), " ");
    let error = minted.expect_err("a summary minted with a blank text");
    assert!(
        format!("{error:?}").contains("summary text is blank"),
        "the mint refuses the blank text: {error:?}"
    );
    Ok(())
}
