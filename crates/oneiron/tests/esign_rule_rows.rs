#![cfg(oneiron_test_support)]
//! The e-sign rule pack (ARCH-0064 section 2 "Reminders, expiry and compliance are pack data",
//! section 8; SGN-08, SGN-09): a draft created without `lifecycle` carries the pack's lifecycle
//! default row (a 90 day window, a reminder at 5 days and every 2 days after, a 30 day cap); an
//! agent under a Grant listing the verbs proposes a change to an optional row, which waits for the
//! owner's stamp, and never waives, rewrites or removes the UETA section 10 review row; the owner
//! stamps or rejects the exact staged proposal. The verbs are called by name, so this file builds
//! where they do not exist and fails there by its asserts.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test esign_rule_rows`.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::blob_artifact::esign::{
    DocumentKind, EsignCreateRequest, EsignDocument, EsignItem, EsignLifecycleRules,
    EsignNoticeSwitches, EsignRecipient, RecipientRole,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::{Value, json};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

const GET: &str = "vault.esign.rules.get";
const AMEND: &str = "vault.esign.rules.amend";
const APPROVE: &str = "vault.esign.rules.approve";
const REJECT: &str = "vault.esign.rules.reject";
const UETA_ROW: &str = "us.ueta.s10.review_before_complete";
const EIDAS_ROW: &str = "eu.eidas.disclosure";

fn original_pdf() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-seal/tests/fixtures/pdf-input/classic_1page.pdf"
    ))
}

/// The verb's answer, or its refusal.
fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Result<Value, MemoryError> {
    invoke(memory, verb, input)
}

/// The verb's answer, failing the test with the refusal when it has none.
fn answer(memory: &Memory<'_>, verb: &str, input: Value) -> TestResult<Value> {
    let answered = call(memory, verb, input);
    assert!(answered.is_ok(), "{verb} answers: {answered:?}");
    Ok(answered?)
}

/// The refusal's message, failing the test when the verb answered.
fn refusal(memory: &Memory<'_>, verb: &str, input: Value) -> TestResult<MemoryError> {
    match call(memory, verb, input) {
        Ok(value) => Err(format!("{verb} must refuse, answered {value}").into()),
        Err(error) => Ok(error),
    }
}

/// `pack` with `version` and `edit` applied to the row named `row`, or to the pack when `row` is
/// None.
fn edited(pack: &Value, version: u32, row: Option<&str>, edit: impl FnOnce(&mut Value)) -> Value {
    let mut pack = pack.clone();
    pack["pack_version"] = json!(version);
    match row {
        Some(id) => {
            let rows = pack["rows"].as_array_mut().expect("the pack has rows");
            let target = rows
                .iter_mut()
                .find(|candidate| candidate["id"] == id)
                .expect("the row is in the pack");
            edit(target);
        }
        None => edit(&mut pack),
    }
    pack
}

#[test]
fn draft_without_lifecycle_takes_pack_defaults() -> TestResult {
    let dir = tempfile::tempdir()?;
    let now = 1_800_000_000;
    let clock = ManualClock::new(now);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let at = TimeRange {
        start: now,
        end: now,
    };
    let person = vault.ensure_embedded_owner_actor()?;
    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        at,
        now,
        b"owner",
    )?;
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    oneiron::test_support::bind_host_owner(&vault, &issuer, person)?;
    let id = EntityId::now();
    vault.put_blob_artifact(
        &id,
        &oneiron::blob_artifact::BlobArtifactBody::new("agreement.pdf", "application/pdf"),
        at,
        now,
    )?;
    vault.append_blob_artifact_version(
        &id,
        original_pdf(),
        &oneiron::blob_artifact::BlobVersionProvenance::UserUpload,
        oneiron::write_envelope::WriteActor::new(person, EdgeActorClass::Human),
        at,
        now,
    )?;
    let draft = EsignDocument {
        schema_version: 1,
        kind: DocumentKind::Document,
        title: "Agreement".into(),
        sequential: false,
        expires_at: now + 3600,
        token_expires_at: None,
        items: vec![EsignItem {
            artifact_ref: id.to_hex(),
            original_version: 1,
        }],
        recipients: vec![EsignRecipient {
            id: EntityId::now().to_hex(),
            email: "owen@example.com".into(),
            name: "Owen".into(),
            role: RecipientRole::Approver,
            order: 0,
            expires_at: now + 3600,
            principal_ref: None,
            automated: false,
            natural_person: None,
        }],
        fields: vec![],
        full_trail_appendix: true,
        lifecycle: None,
        project: None,
        commitments: Vec::new(),
    };
    vault
        .memory(person, EdgeActorClass::Human)
        .esign_create(&EsignCreateRequest {
            document_ref: id.to_hex(),
            draft,
            qr_pdf_download: false,
        })?;
    let landed = vault.esign_document(id)?.document;
    assert_eq!(
        landed.lifecycle,
        Some(EsignLifecycleRules {
            expiry_after_seconds: 90 * 86_400,
            first_reminder_after_seconds: 5 * 86_400,
            repeat_reminder_every_seconds: 2 * 86_400,
            reminder_cap_seconds: 30 * 86_400,
            notices: EsignNoticeSwitches::default(),
            token_cap_seconds: None,
        }),
        "a draft without lifecycle carries the pack's lifecycle default row"
    );
    assert_eq!(
        landed.expires_at,
        now + 3600,
        "the draft's own deadline stays its own"
    );
    Ok(())
}

/// A rooted vault with its install enrolled, its embedded owner and proof: the owner's Grant acts
/// on `ThisInstall` need the whole install first.
fn rooted_vault() -> TestResult<(Vault, AuthenticatedOwner, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let issuer = vault.bootstrap_host_slip_issuer()?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.provision_engine_machine_identities(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    Ok((vault, proof, dir))
}

/// An enabled agent definition the owner creates.
fn create_agent(vault: &Vault, proof: &AuthenticatedOwner, agent_id: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    create_agent_definition_as(
        vault,
        proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "e-sign rule pack fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))?,
        },
    )?;
    Ok(id)
}

#[test]
fn agent_amends_optional_row_but_never_waives_the_ueta_row() -> TestResult {
    let (vault, proof, _dir) = rooted_vault()?;
    let agent = create_agent(&vault, &proof, "fixture.esign.rules")?;
    let ungranted = create_agent(&vault, &proof, "fixture.esign.rules.ungranted")?;
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "write".to_owned(),
        GET.to_owned(),
        AMEND.to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        &vault,
        &proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope: scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )?;
    assert!(minted.grant.confers, "the rule pack Grant confers");
    let memory = vault.memory(agent, EdgeActorClass::Agent);

    let view = answer(&memory, GET, json!({}))?;
    let active = view["active"].clone();
    assert_eq!(active["pack_id"], "esign.rules");
    assert_eq!(active["pack_version"], 1);
    let ueta = active["rows"]
        .as_array()
        .ok_or("the pack has rows")?
        .iter()
        .find(|row| row["id"] == UETA_ROW)
        .ok_or("the seed carries the UETA section 10 row")?;
    assert_eq!(ueta["waivable"], false, "the UETA row is non-waivable");
    assert_eq!(ueta["kind"], "requirement");
    assert!(view.get("pending").is_none(), "nothing is staged yet");

    // An optional row's new wording is not provably narrower: it waits for the owner.
    let reworded = edited(&active, 2, Some(EIDAS_ROW), |row| {
        row["rule"] = json!(
            "The deployment shows its eIDAS disclosure before the signer opens the document."
        );
    });
    let staged = answer(
        &memory,
        AMEND,
        json!({"prior_version": 1, "pack": reworded}),
    )?;
    assert_eq!(staged["disposition"], "pending_owner_stamp");
    assert_eq!(staged["active_version"], 1, "the active pack is unchanged");

    // The UETA row is never waived, rewritten or removed, whatever the version.
    let waived = edited(&active, 3, Some(UETA_ROW), |row| {
        row["waivable"] = json!(true)
    });
    let rewritten = edited(&active, 3, Some(UETA_ROW), |row| {
        row["rule"] = json!("The signer may skip the review.");
    });
    let removed = edited(&active, 3, None, |pack| {
        pack["rows"]
            .as_array_mut()
            .expect("the pack has rows")
            .retain(|row| row["id"] != UETA_ROW);
    });
    for (what, pack) in [
        ("waived", waived),
        ("rewritten", rewritten),
        ("removed", removed),
    ] {
        let refused = refusal(&memory, AMEND, json!({"prior_version": 1, "pack": pack}))?;
        assert!(
            refused.message.contains("non-waivable"),
            "a {what} UETA row is refused as non-waivable: {refused:?}"
        );
    }

    // An agent no Grant lists the verb for proposes nothing.
    let unlisted = edited(&active, 2, Some(EIDAS_ROW), |row| {
        row["rule"] = json!("Unlisted.");
    });
    let refused = refusal(
        &vault.memory(ungranted, EdgeActorClass::Agent),
        AMEND,
        json!({"prior_version": 1, "pack": unlisted}),
    )?;
    assert_eq!(refused.code, MEMORY_CODE_FORBIDDEN, "{refused:?}");

    let view = answer(&memory, GET, json!({}))?;
    assert_eq!(
        view["active"], active,
        "no refused amend moved the active pack"
    );
    let pending = &view["pending"];
    assert_eq!(pending["pack"]["pack_version"], 2);
    assert_eq!(pending["proposal_hash"], staged["proposal_hash"]);
    Ok(())
}

#[test]
fn owner_stamp_activates_only_the_staged_loosening() -> TestResult {
    // A process-owned vault: the owner verbs answer the embedded owner on the handle that holds
    // the writer lease.
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);

    let active = answer(&memory, GET, json!({}))?["active"].clone();
    // A longer signing window loosens the pack: even the owner's proposal waits for its stamp.
    let longer = edited(&active, 2, None, |pack| {
        pack["lifecycle"]["expiry_after_seconds"] = json!(120 * 86_400);
    });
    let staged = answer(&memory, AMEND, json!({"prior_version": 1, "pack": longer}))?;
    assert_eq!(staged["disposition"], "pending_owner_stamp");
    let hash = staged["proposal_hash"].clone();

    let wrong = refusal(
        &memory,
        APPROVE,
        json!({"prior_version": 1, "proposal_hash": "0".repeat(64)}),
    )?;
    assert!(
        wrong.message.contains("does not bind"),
        "a stamp of another hash is refused: {wrong:?}"
    );
    let applied = answer(
        &memory,
        APPROVE,
        json!({"prior_version": 1, "proposal_hash": hash}),
    )?;
    assert_eq!(applied["disposition"], "applied");
    assert_eq!(applied["active_version"], 2);
    let view = answer(&memory, GET, json!({}))?;
    assert_eq!(
        view["active"]["lifecycle"]["expiry_after_seconds"],
        120 * 86_400
    );
    assert!(
        view.get("pending").is_none(),
        "the stamp consumed the proposal"
    );
    assert_eq!(
        view["notices"].as_array().map(Vec::len),
        Some(1),
        "one activation, one notice: {view}"
    );

    // More reminders loosen too; the owner's reject leaves the active pack as it was.
    let more_reminders = edited(&view["active"], 3, None, |pack| {
        pack["lifecycle"]["repeat_reminder_every_seconds"] = json!(86_400);
    });
    let staged = answer(
        &memory,
        AMEND,
        json!({"prior_version": 2, "pack": more_reminders}),
    )?;
    assert_eq!(staged["disposition"], "pending_owner_stamp");
    let rejected = answer(
        &memory,
        REJECT,
        json!({"prior_version": 2, "proposal_hash": staged["proposal_hash"]}),
    )?;
    assert_eq!(rejected["disposition"], "rejected");
    assert_eq!(rejected["active_version"], 2);
    let after = answer(&memory, GET, json!({}))?;
    assert_eq!(after["active"], view["active"]);
    assert!(after.get("pending").is_none());
    Ok(())
}
