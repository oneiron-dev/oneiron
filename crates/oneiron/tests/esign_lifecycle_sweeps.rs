#![cfg(oneiron_test_support)]
//! The signing window and the emailed-token cap expire on separate jobs (ARCH-0064 section 2
//! "Reminders, expiry and compliance are pack data"; SGN-09: "a separate token-expiry job
//! enforces the configured emailed-token cap"). A link lives until its own mint plus the draft's
//! token cap; a window extension (RULING ESIGN-WINDOW-EXTEND-AUTHORITY = A) moves the document
//! and its recipient windows but never a link's cap; the token job removes lapsed links and
//! never ends a window; the window job expires the document at its extended deadline and never
//! touches a link. The extension is called by name and the jobs are read off the report's JSON
//! form, so this file builds where they do not exist and fails there by its asserts.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test esign_lifecycle_sweeps`.

use std::sync::Arc;

use oneiron::blob_artifact::esign::{
    DocumentKind, DocumentStatus, EsignCapability, EsignCreateRequest, EsignDispatchRequest,
    EsignDocument, EsignItem, EsignLifecycleRules, EsignNoticeSwitches, EsignRecipient,
    RecipientRole, SigningAction,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::housekeeping::{HousekeepingBudget, HousekeepingReport};
use oneiron::memory::{Memory, MemoryError};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const EXTEND: &str = "vault.esign.extend";
const T0: u64 = 1_800_000_000;
const HOUR: u64 = 3600;
const DAY: u64 = 86_400;

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

/// The verb's answer, failing the test with the refusal when it has none.
fn answer(memory: &Memory<'_>, verb: &str, input: Value) -> TestResult<Value> {
    let answered: Result<Value, MemoryError> = invoke(memory, verb, input);
    assert!(answered.is_ok(), "{verb} answers: {answered:?}");
    Ok(answered?)
}

/// A fresh proof of the embedded owner, for the owner's own link issue.
fn owner_proof(vault: &Vault, owner: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// The one link the draft issued, which is `recipient`'s.
fn only_link(
    issued: Vec<(String, EsignCapability)>,
    recipient: &str,
) -> TestResult<EsignCapability> {
    let [(id, link)]: [(String, EsignCapability); 1] = issued
        .try_into()
        .map_err(|rest: Vec<_>| format!("the draft issues one link, it issued {}", rest.len()))?;
    assert_eq!(id, recipient, "the link is the recipient's");
    Ok(link)
}

/// The recipient opens the signing page with `link` at the vault's clock.
fn load(vault: &Vault, link: &EsignCapability) -> Result<(), String> {
    vault
        .execute_signing_action(link, &SigningAction::Load, None, None)
        .map(drop)
        .map_err(|error| error.to_string())
}

/// `link` opens the signing page.
fn assert_loads(vault: &Vault, link: &EsignCapability, why: &str) {
    let loaded = load(vault, link);
    assert!(loaded.is_ok(), "{why}: {loaded:?}");
}

/// `link` is refused at the signing page as no capability, the refusal a lapsed link gets.
fn assert_refused(vault: &Vault, link: &EsignCapability, why: &str) {
    let loaded = load(vault, link);
    assert!(
        loaded
            .as_ref()
            .is_err_and(|error| error.contains("invalid capability")),
        "{why}: {loaded:?}"
    );
}

/// The `count` the pass's `sweep` row reports in its `work`, read off the report's JSON form
/// (`{"sweep": .., "outcome": "ran", "work": {<work>: {<count>: ..}}}`).
fn swept(report: &HousekeepingReport, sweep: &str, work: &str, count: &str) -> TestResult<u64> {
    let report = serde_json::to_value(report)?;
    let row = report["sweeps"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["sweep"] == sweep))
        .ok_or_else(|| format!("the pass reports no {sweep} job"))?;
    assert_eq!(row["outcome"], "ran", "the {sweep} job runs: {row}");
    Ok(row["work"][work][count]
        .as_u64()
        .ok_or_else(|| format!("the {sweep} job reports no {work}.{count}: {row}"))?)
}

struct Signing {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    document: EntityId,
    recipient: String,
    _dir: tempfile::TempDir,
}

/// A rooted vault on a manual clock at `T0` whose embedded owner drafted a one-recipient
/// document: a 90 day window, the pack's reminder ladder, and a one hour token cap. The policy
/// lets the owner send and extend on the e-sign channel.
fn signing_draft() -> TestResult<Signing> {
    let dir = tempfile::tempdir()?;
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let at = TimeRange { start: T0, end: T0 };
    let owner = vault.ensure_embedded_owner_actor()?;
    vault.put_entity(
        &owner,
        oneiron::registry::ENTITY_TYPE_PERSON,
        at,
        T0,
        b"owner",
    )?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner)?;
    let scoped_grants: Vec<Value> = ["send_for_signature", "extend"]
        .into_iter()
        .map(|verb| {
            json!({
                "actor_ref": owner.to_hex(),
                "effector": format!("external:{verb}"),
                "scope": oneiron::test_support::effect_preset(),
                "selectors": {"channel": "esign"},
            })
        })
        .collect();
    let policy = json!({
        "schema_version": "1.2", "pack_id": "esign-lifecycle-test", "pack_version": "v1",
        "min_engine_version": "0.0.0",
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [{"actor_class": "human", "actor_ref": owner.to_hex(), "ceiling": "auto"}],
        "scoped_grants": scoped_grants,
    });
    oneiron::test_support::put_policy_manifest_bytes(
        &vault,
        EntityId::now(),
        &rmp_serde::to_vec_named(&policy)?,
    )?;
    let document = EntityId::now();
    vault.put_blob_artifact(
        &document,
        &oneiron::blob_artifact::BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        at,
        T0,
    )?;
    vault.append_blob_artifact_version(
        &document,
        original_pdf(),
        &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
        oneiron::write_envelope::WriteActor::new(owner, EdgeActorClass::Human),
        at,
        T0,
    )?;
    let recipient = EntityId::now().to_hex();
    let draft = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: T0 + 90 * DAY,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: document.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: recipient.clone(),
            email: "owen@example.com".into(),
            name: "Owen".into(),
            role: RecipientRole::Approver,
            order: 0,
            expires_at: T0 + 90 * DAY,
            principal_ref: None,
            automated: false,
            natural_person: None,
        }],
        fields: vec![],
        full_trail_appendix: true,
        lifecycle: Some(EsignLifecycleRules {
            expiry_after_seconds: 90 * DAY,
            first_reminder_after_seconds: 5 * DAY,
            repeat_reminder_every_seconds: 2 * DAY,
            reminder_cap_seconds: 30 * DAY,
            notices: EsignNoticeSwitches::default(),
            // RED SHIM: `token_cap_seconds: Some(HOUR),` names PR-2's field; the base has no token cap.
        }),
        project: None,
        commitments: Vec::new(),
    };
    vault
        .memory(owner, EdgeActorClass::Human)
        .esign_create(&EsignCreateRequest {
            document_ref: document.to_hex(),
            draft,
            qr_pdf_download: false,
        })?;
    Ok(Signing {
        vault,
        clock,
        owner,
        document,
        recipient,
        _dir: dir,
    })
}

#[test]
fn window_and_token_expire_on_separate_jobs() -> TestResult {
    let signing = signing_draft()?;
    let Signing {
        vault,
        clock,
        owner,
        document,
        recipient,
        ..
    } = &signing;
    let memory = vault.memory(*owner, EdgeActorClass::Human);

    // Ten minutes after the draft the owner takes the recipient's link: its cap counts from
    // this mint, so it lapses at T0 + 600 + 1 h.
    clock.set(T0 + 600);
    let early = only_link(
        vault.issue_esign_capabilities(&owner_proof(vault, *owner)?, *document)?,
        recipient,
    )?;
    clock.set(T0 + 600 + HOUR);
    let issued = vault.issue_esign_capabilities(&owner_proof(vault, *owner)?, *document)?;
    assert_eq!(
        issued.len(),
        1,
        "a link past its own token cap is no link: the draft issues the recipient a fresh one"
    );
    let fresh = only_link(issued, recipient)?;
    let fresh_cap_end = T0 + 600 + 2 * HOUR;

    let sent = memory.esign_send_for_signature(&EsignDispatchRequest {
        document_ref: document.to_hex(),
        recipient_count: 1,
        on_behalf_of: None,
        idempotency_key: Some("send-1".into()),
    })?;
    assert_eq!(
        sent.outcome, "delivered_to_channel",
        "the owner's send lands: {sent:?}"
    );
    assert_refused(vault, &early, "the lapsed link stays lapsed after the send");
    assert_loads(vault, &fresh, "the fresh link opens the signing page");

    // Half an hour later the owner moves the window from 90 to 120 days.
    clock.set(T0 + 600 + HOUR + 1800);
    let extended = answer(
        &memory,
        EXTEND,
        json!({
            "document_ref": document.to_hex(),
            "recipient_count": 1,
            "expires_at": T0 + 120 * DAY,
            "idempotency_key": "extend-1",
        }),
    )?;
    assert_eq!(
        extended["outcome"], "delivered_to_channel",
        "the owner's extension lands: {extended}"
    );
    let state = vault.esign_document(*document)?;
    assert_eq!(
        state.document.expires_at,
        T0 + 120 * DAY,
        "the extension moves the document's deadline"
    );
    assert_eq!(
        state.recipients[recipient].expires_at,
        T0 + 120 * DAY,
        "the extension moves the unfinished recipient's window"
    );
    assert_eq!(state.status, DocumentStatus::Pending);

    // The extension never moves a link's cap.
    clock.set(fresh_cap_end - 1);
    assert_loads(vault, &fresh, "the fresh link opens up to its cap end");
    clock.set(fresh_cap_end);
    assert_refused(
        vault,
        &fresh,
        "the fresh link lapses at its own cap end, not at the extended window",
    );

    // The token job removes both lapsed links; the window job expires nothing.
    let report = vault.housekeeping(HousekeepingBudget::unbounded())?;
    assert_eq!(
        swept(&report, "esign_token_expiry", "esign_tokens", "removed")?,
        2,
        "the token-expiry job removes the two lapsed links"
    );
    assert_eq!(
        swept(&report, "esign_expiry", "esign_expiry", "expired")?,
        0,
        "the window job expires nothing before the extended deadline"
    );
    assert_eq!(
        vault.esign_document(*document)?.status,
        DocumentStatus::Pending,
        "a lapsed link leaves its document pending"
    );
    assert_refused(vault, &fresh, "a removed link is refused as no capability");

    // At the extended deadline the window job expires the document, and the token job finds no
    // link left.
    clock.set(T0 + 120 * DAY);
    let report = vault.housekeeping(HousekeepingBudget::unbounded())?;
    assert_eq!(
        swept(&report, "esign_expiry", "esign_expiry", "expired")?,
        1,
        "the window job expires the document at its extended deadline"
    );
    assert_eq!(
        swept(&report, "esign_token_expiry", "esign_tokens", "removed")?,
        0,
        "the token-expiry job has no link left to remove"
    );
    assert_eq!(
        vault.esign_document(*document)?.status,
        DocumentStatus::Expired
    );
    Ok(())
}
