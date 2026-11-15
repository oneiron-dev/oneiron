//! The held-sign ask's lapse at the vault owners (OPUS-PACK-KEYS, PK-3).
//!
//! A held automated sign act's ask, left unanswered at the vault owners,
//! lapses once it has waited there for the vault's
//! `esign.held_signing.owner_lapse` (30 days when no row stands): the hold
//! settles as `Lapsed`, the ask leaves the owners' queue so a later answer is
//! refused, the document stays unsigned with the recipient's turn still open,
//! and each owner gets one inbox notice. The owner rules the wait: `"never"`
//! keeps the ask waiting, and a shorter `after_secs` lapses it sooner.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test pack_keys_esign_lapse`.
//! The fixture's host owner and sent mark come from `oneiron::test_support` (feature `test-support`).
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::blob_artifact::esign::{
    DocumentKind, DocumentStatus, EsignAuditActor, EsignDocument, EsignItem, EsignRecipient,
    HELD_SIGNING_LAPSE_NOTIFICATION_PRODUCER, HOLD_ALLOW, HeldSigning, HeldSigningState,
    RecipientRole, SigningAction, SigningCaller, SigningOutcome, SigningStatus,
};
use oneiron::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::inbox::INBOX_PAGE_DEFAULT;
use oneiron::llm::decision::{
    AskAct, AskRole, AskTo, DecisionAnswer, DecisionAsk, DecisionRung, HolderKind, HumanAskReason,
    HumanDecisionRequest, ProviderPin, RoleRank,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The store clock's start, as in `setting_primitive.rs`.
const T0: u64 = 1_790_000_000;
/// One day, in seconds.
const DAY_SECS: u64 = 24 * 60 * 60;
/// The shipped lapse: thirty days, in seconds.
const THIRTY_DAYS_SECS: u64 = 30 * DAY_SECS;
/// The lapse key under test.
const LAPSE_KEY: &str = "esign.held_signing.owner_lapse";

/// A vault whose one automated sign act is held and whose ask waits at the
/// vault owners, on a clock the test moves.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    document: EntityId,
    recipient: String,
    asked_at: u64,
    ask_seq: u64,
    _dir: tempfile::TempDir,
}

/// The pinned genuine one-page PDF every original in this file carries.
fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

/// The audit actor the draft and the send land under.
fn audit_actor(owner: EntityId) -> EsignAuditActor {
    EsignAuditActor {
        actor: owner.to_hex(),
        ip: None,
        user_agent: None,
    }
}

/// A field-less draft with one automated signer, expiring at `expires_at`.
fn draft(artifact: EntityId, recipient: &str, expires_at: u64) -> EsignDocument {
    EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Consulting agreement".into(),
        sequential: false,
        expires_at,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: artifact.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: recipient.to_owned(),
            email: "owen@example.com".into(),
            name: "Owen".into(),
            role: RecipientRole::Signer,
            order: 0,
            expires_at,
            principal_ref: None,
            automated: true,
            natural_person: None,
        }],
        fields: Vec::new(),
        full_trail_appendix: true,
        lifecycle: None,
        project: None,
        commitments: Vec::new(),
    }
}

/// The fixture's one open hold.
fn open_hold(fixture: &Fixture) -> TestResult<HeldSigning> {
    let holds = fixture.vault.esign_held_signings(true)?;
    assert_eq!(holds.len(), 1, "one sign act is held");
    Ok(holds.into_iter().next().expect("one hold"))
}

/// The fixture's ask, open or withdrawn.
fn queued_ask(fixture: &Fixture) -> TestResult<DecisionAsk> {
    Ok(fixture
        .vault
        .decision_ask(fixture.ask_seq)?
        .expect("the ask is kept"))
}

/// A vault on a manual clock whose agent's Complete was held and whose ask
/// waits at the vault owners, as the server worker would have put it.
fn fixture() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let at = TimeRange { start: T0, end: T0 };
    let owner = vault.ensure_embedded_owner_actor()?;
    vault.put_entity(&owner, ENTITY_TYPE_PERSON, at, T0, b"owner")?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let owner_proof =
        vault.authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())?;
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        at,
        T0,
    )?;
    vault.append_blob_artifact_version(
        &id,
        original_pdf(),
        &BlobVersionProvenance::UserUpload,
        WriteActor::new(owner, EdgeActorClass::Human),
        at,
        T0,
    )?;
    let recipient = EntityId::now().to_hex();
    let actor = audit_actor(owner);
    // Past every wait the tests run: the lapse, never the expiry, moves the hold.
    let expires_at = T0 + 730 * DAY_SECS;
    vault.create_esign_document(id, &draft(id, &recipient, expires_at), actor.clone(), T0)?;
    let issued = vault.issue_esign_capabilities(&owner_proof, id)?;
    assert_eq!(
        issued.len(),
        1,
        "FIXTURE: one recipient mints one capability"
    );
    let (recipient_key, token) = issued.into_iter().next().expect("one capability");
    assert_eq!(
        recipient_key, recipient,
        "FIXTURE: the capability is the signer's"
    );
    oneiron::test_support::mark_esign_sent(&vault, id, actor, T0)?;
    let outcome = vault.execute_signing_action_as(
        &token,
        &SigningAction::Complete {
            consent: true,
            next: None,
        },
        SigningCaller::Agent,
        None,
        None,
        None,
    )?;
    assert!(
        matches!(outcome, SigningOutcome::HeldForOwner { .. }),
        "FIXTURE: the dial holds the agent's Complete, got {outcome:?}"
    );
    let SigningOutcome::HeldForOwner { held_at } = outcome else {
        unreachable!("FIXTURE: the dial holds the agent's Complete");
    };
    let holds = vault.esign_held_signings(true)?;
    assert_eq!(
        holds.len(),
        1,
        "FIXTURE: the agent's Complete holds one sign act"
    );
    let held = holds.into_iter().next().expect("one hold");
    assert_eq!(held.held_at, held_at, "FIXTURE: the hold is this call's");
    let question = held.question()?;
    let ask_seq = vault.queue_decision_ask(&HumanDecisionRequest {
        question: question.clone(),
        principal: owner,
        evidence: Vec::new(),
        reason: HumanAskReason::OwnerSelected,
        prior: None,
        prior_provider: None,
        queue_pin: ProviderPin {
            rung: DecisionRung::Human,
            model: "esign.held_signing".to_owned(),
            version: "v1".to_owned(),
        },
        to: AskTo {
            role: AskRole::Owner,
            ceiling: RoleRank::Owner,
            act: AskAct::ESignature,
        },
        correlation: None,
    })?;
    vault.esign_hold_asked(&held.document, &held.recipient, held.held_at, question.id)?;
    let asked = vault.esign_held_signings(true)?;
    assert_eq!(
        asked.len(),
        1,
        "FIXTURE: the hold is still the one open hold"
    );
    let held = asked.into_iter().next().expect("one hold");
    assert!(
        matches!(held.state, HeldSigningState::Asked { .. }),
        "FIXTURE: the hold is Asked, got {:?}",
        held.state
    );
    let HeldSigningState::Asked {
        question: asked_question,
        wait,
    } = &held.state
    else {
        unreachable!("FIXTURE: the hold is Asked");
    };
    assert_eq!(
        *asked_question,
        question.id.to_hex(),
        "FIXTURE: the hold names the queued ask"
    );
    assert!(wait.is_none(), "FIXTURE: the wait runs from the ask");
    let ask = vault.decision_ask(ask_seq)?.expect("the ask is kept");
    let at_role = ask.role.as_ref().expect("the ask resolved to a role");
    assert_eq!(
        at_role.role.rank(),
        RoleRank::Owner,
        "FIXTURE: the ask waits at the vault owners"
    );
    assert!(
        at_role
            .holders
            .iter()
            .any(|holder| holder.actor == owner && holder.kind == HolderKind::Person),
        "FIXTURE: a live owner holds the ask as a person"
    );
    let asked_at = ask.asked_at;
    Ok(Fixture {
        vault,
        clock,
        owner,
        owner_proof,
        document: id,
        recipient,
        asked_at,
        ask_seq,
        _dir: dir,
    })
}

/// With no row standing, the owners' unanswered ask lapses after 30 days, and
/// the lapse never signs: the hold settles as `Lapsed`, the ask leaves the
/// owners' queue, the document stays unsigned with the recipient's turn still
/// open, and the owner gets one lapse notice.
#[test]
fn with_no_row_the_ask_lapses_after_30_days_and_never_signs() -> TestResult {
    let fixture = fixture()?;
    let lapse_at = fixture.asked_at + THIRTY_DAYS_SECS;
    fixture.clock.set(lapse_at - 1);
    let held = open_hold(&fixture)?;
    let ask = queued_ask(&fixture)?;
    assert!(
        !fixture.vault.lapse_stale_esign_ask(&held, &ask)?,
        "one second early the ask still waits"
    );
    assert!(
        matches!(open_hold(&fixture)?.state, HeldSigningState::Asked { .. }),
        "one second early the hold is still Asked"
    );
    fixture.clock.set(lapse_at);
    let held = open_hold(&fixture)?;
    let ask = queued_ask(&fixture)?;
    assert!(
        fixture.vault.lapse_stale_esign_ask(&held, &ask)?,
        "at 30 days the ask lapses"
    );
    let holds = fixture.vault.esign_held_signings(false)?;
    assert_eq!(holds.len(), 1, "the vault keeps the one hold");
    let held = holds.into_iter().next().expect("one hold");
    assert!(
        matches!(held.state, HeldSigningState::Lapsed { .. }),
        "the hold lapsed, got {:?}",
        held.state
    );
    let HeldSigningState::Lapsed { at } = held.state else {
        unreachable!("the hold lapsed");
    };
    assert_eq!(at, lapse_at, "the lapse lands at the instant it waited out");
    assert!(
        fixture.vault.esign_held_signings(true)?.is_empty(),
        "no open hold is left"
    );
    let ask = queued_ask(&fixture)?;
    assert!(ask.withdrawn_at.is_some(), "the ask left the owners' queue");
    assert!(
        fixture
            .vault
            .answer_decision_ask_as(
                &WriteActor::new(fixture.owner, EdgeActorClass::Human),
                fixture.ask_seq,
                DecisionAnswer::Choice(HOLD_ALLOW.to_owned()),
            )
            .is_err(),
        "a later answer is refused"
    );
    let state = fixture.vault.esign_document(fixture.document)?;
    assert_eq!(
        state.status,
        DocumentStatus::Pending,
        "the document stays unsigned"
    );
    assert_eq!(
        state
            .recipients
            .get(&fixture.recipient)
            .expect("the recipient")
            .signing,
        SigningStatus::Ready,
        "the recipient's turn stays open"
    );
    let inbox = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .inbox_list(None, INBOX_PAGE_DEFAULT)?;
    let lapsed: Vec<_> = inbox
        .rows
        .iter()
        .filter(|row| row.source.producer == HELD_SIGNING_LAPSE_NOTIFICATION_PRODUCER)
        .collect();
    assert_eq!(
        lapsed.len(),
        1,
        "the owner gets one lapse notice: {:?}",
        inbox.rows
    );
    Ok(())
}

/// The owner's `"never"` keeps the ask waiting past a year.
#[test]
fn the_owners_never_keeps_the_ask_waiting() -> TestResult {
    let fixture = fixture()?;
    let outcome = fixture.vault.set_setting(
        SettingCaller::Owner(&fixture.owner_proof),
        SetSetting::vault_value(LAPSE_KEY, json!("never")),
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's row applies"
    );
    fixture.clock.set(fixture.asked_at + 365 * DAY_SECS);
    let held = open_hold(&fixture)?;
    let ask = queued_ask(&fixture)?;
    assert!(
        !fixture.vault.lapse_stale_esign_ask(&held, &ask)?,
        "with `never` the ask still waits after a year"
    );
    assert!(
        matches!(open_hold(&fixture)?.state, HeldSigningState::Asked { .. }),
        "with `never` the hold is still Asked after a year"
    );
    Ok(())
}

/// The owner's shorter lapse applies: false just before the hour, true on it.
#[test]
fn the_owners_shorter_lapse_applies() -> TestResult {
    let fixture = fixture()?;
    let outcome = fixture.vault.set_setting(
        SettingCaller::Owner(&fixture.owner_proof),
        SetSetting::vault_value(LAPSE_KEY, json!({ "after_secs": 3600 })),
    )?;
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's row applies"
    );
    fixture.clock.set(fixture.asked_at + 3599);
    let held = open_hold(&fixture)?;
    let ask = queued_ask(&fixture)?;
    assert!(
        !fixture.vault.lapse_stale_esign_ask(&held, &ask)?,
        "one second early the ask still waits"
    );
    assert!(
        matches!(open_hold(&fixture)?.state, HeldSigningState::Asked { .. }),
        "one second early the hold is still Asked"
    );
    fixture.clock.set(fixture.asked_at + 3600);
    let held = open_hold(&fixture)?;
    let ask = queued_ask(&fixture)?;
    assert!(
        fixture.vault.lapse_stale_esign_ask(&held, &ask)?,
        "at the hour the ask lapses"
    );
    Ok(())
}
