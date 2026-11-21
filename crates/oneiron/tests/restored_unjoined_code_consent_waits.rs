//! RESTORED-UNJOINED-CODE-RESUME-HOLD-TEST: an approval kept in an image
//! does not let the restored copy drive, refuse, admit or settle its effect
//! until the owner joins the copy.

#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::Cell;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::authority::{HostSlipIssuer, InvocationSlipBinding, MachineRole};
use oneiron::code_run::{
    CodeConsentAnswerInput, CodeConsentBrowserAction, CodeConsentBrowserOutcome, CodeConsentChoice,
    CodeConsentEffectHost, CodeConsentSavedCredential, CodeConsentSettleOutcome,
    CodeConsentWaitState, CodeConsentWaitView,
};
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCallRoute, ConnectorCatalogEntry, ConnectorConsentTarget,
    ConnectorKeySpec, ConnectorToolConsent, ConnectorToolConsentRow, SlateDataClass,
    SlateToolManifest, draft_connector_slate,
};
use oneiron::consent::{AuthenticatedOwner, tool_scope::DataClass};
use oneiron::outbound_consent::tool_call::MutationIntent;
use oneiron::outbound_consent::{
    ConnectorCallHost, ConnectorCallInvocation, ConnectorCallOutcome, ConnectorCallRequest,
    OutboundResultSender, OutboundTransportResult, RawOutboundResult, UntrustedToolResult,
};
use oneiron::outbound_intent_ledger::{FrozenOutboundCall, OutboundSendOutcome};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::runtime_hooks::verb::VerbAskRefusal;
use oneiron::store::{GateDecisionId, ports::ManualClock};
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::task_verb::{TaskAskHandle, TaskAskOptionId, TaskAskWord};
use oneiron::test_doors::ask_answer_proof::admit_word_unsettled;
use oneiron::test_doors::coach::last_committed_txn_id;
use oneiron::test_doors::outbound_wait_setting_keys::held_connector_call_settled;
use oneiron::test_doors::restored_code_consent_waits::{
    approve_once_available, code_consent_memory, park_code_consent_step,
};
use oneiron::test_support::{restore_tempdir, test_host_issuer};
use oneiron::{AttemptId, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

const SERVER: &str = "restored_consent";
const TOOL: &str = "record";
const REVISION: &str = "2026-09-01";
const ENDPOINT: &str = "https://connector.invalid/mcp";

/// The first install, rooted with its owner bound and the checkpoint signer held.
struct Host {
    vault: Vault,
    _dir: tempfile::TempDir,
    issuer: HostSlipIssuer,
    vault_id: [u8; 32],
    clock: Arc<ManualClock>,
    owner: EntityId,
}

fn rooted_host() -> Host {
    let dir = tempfile::tempdir().expect("FIXTURE: host directory");
    let clock = ManualClock::new(1_700_000_000);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config).expect("FIXTURE: host install");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("FIXTURE: host install profile");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner");
    oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("FIXTURE: owner binding");
    vault.hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    let vault_id = vault
        .authority_vault_id()
        .expect("FIXTURE: the fold reads")
        .expect("FIXTURE: a rooted vault");
    Host {
        vault,
        _dir: dir,
        issuer,
        vault_id,
        clock,
        owner,
    }
}

/// A copy restored beside the host, with its own keystore and owner proof.
struct Copy {
    vault: Vault,
    proof: AuthenticatedOwner,
}

fn restored_copy(host: &Host, backups: &Path) -> Copy {
    let image = backups.join("image");
    host.vault
        .snapshot_checkpoint(&image, 100)
        .expect("FIXTURE: the image");
    let key = host.vault.checkpoint_key().expect("FIXTURE: its key");
    let origin = host
        .vault
        .side_restore_source()
        .expect("FIXTURE: the beside restore source");
    let mut config = VaultConfig::device();
    config.store_clock = host.clock.bundle();
    let (vault, _) =
        Vault::restore_checkpoint_beside(&image, &key, &backups.join("copy"), config, &origin, 200)
            .expect("FIXTURE: a copy of the image");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the owner on the copy");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: an owner proof on the copy");
    let encryption = vault
        .machine_encryption_key(host.vault_id)
        .expect("FIXTURE: the copy's encryption key");
    let request = vault
        .machine_enrolment_request(host.vault_id, encryption)
        .expect("FIXTURE: the copy's enrolment request");
    assert!(
        vault
            .authority_fold()
            .expect("FIXTURE: the copy's fold")
            .machine(request.machine)
            .is_none(),
        "FIXTURE: the copy is no machine of the vault yet"
    );
    assert!(
        vault
            .restored_unjoined()
            .expect("FIXTURE: the join state reads"),
        "FIXTURE: the copy is restored and unjoined"
    );
    Copy { vault, proof }
}

fn owner_joins(host: &Host, copy: &Copy) {
    copy.vault
        .hold_checkpoint_root_signer(Arc::new(test_host_issuer()));
    copy.vault
        .join_restored_install(&host.issuer, &copy.proof, MachineRole::Unanswered)
        .expect("the owner's word joins the copy");
    assert!(!copy.vault.restored_unjoined().unwrap());
}

struct RecoverySender {
    outcome: OutboundSendOutcome,
    calls: usize,
    endpoint: Option<&'static str>,
    endpoint_checks: Cell<usize>,
}

impl RecoverySender {
    fn new(endpoint: Option<&'static str>) -> Self {
        Self {
            outcome: OutboundSendOutcome::Acked,
            calls: 0,
            endpoint,
            endpoint_checks: Cell::new(0),
        }
    }
}

impl OutboundResultSender for RecoverySender {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        self.calls += 1;
        OutboundTransportResult {
            outcome: self.outcome,
            raw_result: RawOutboundResult::new(None, None, None, None),
        }
    }
}

impl ConnectorCallHost for RecoverySender {
    fn tool_endpoint(&self, _route: &ConnectorCallRoute) -> Option<String> {
        self.endpoint_checks.set(self.endpoint_checks.get() + 1);
        self.endpoint.map(str::to_owned)
    }

    fn take_result(&mut self) -> Option<UntrustedToolResult> {
        None
    }
}

/// Lets the real answer land but leaves the answered pass to the test.
#[derive(Default)]
struct DeferredEffectHost(AtomicUsize);

impl CodeConsentEffectHost for DeferredEffectHost {
    fn resume_answered(&self, _vault: &Vault, _wait_id: EntityId) -> oneiron::Result<()> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn caller_witness(host: &Host) -> InvocationSlipBinding {
    let root = host
        .vault
        .ensure_host_root_slip(&host.issuer)
        .expect("FIXTURE: root slip");
    let mut claims = root.claims;
    claims.slip_id[..16].copy_from_slice(EntityId::now().as_bytes());
    claims.slip_id[16..].copy_from_slice(EntityId::now().as_bytes());
    claims.holder_ref = host.owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    let slip = host
        .vault
        .mint_capability_slip(&host.issuer, claims)
        .expect("FIXTURE: caller's slip");
    let challenge = b"restored-code-consent-waits";
    let proof = host
        .issuer
        .binding_proof(&slip, challenge)
        .expect("FIXTURE: holder proof");
    host.vault
        .bind_invocation_slip(&slip, challenge, &proof)
        .expect("FIXTURE: live invocation witness")
}

fn register_manual_connector(vault: &Vault, owner: &AuthenticatedOwner) {
    let now = vault.now_recorded_at();
    let manifest = [SlateToolManifest {
        name: TOOL.to_owned(),
        data_class: SlateDataClass::Personal,
        header_parameters: Vec::new(),
        resolved_input_schema: Some(json!({"type": "object"})),
        trigger: None,
        destroys: false,
        spends: false,
        sends_outward: false,
        legacy_ask: false,
        read_only: false,
        idempotent: true,
        price: None,
    }];
    let draft = serde_json::to_string(&draft_connector_slate(&manifest))
        .expect("FIXTURE: connector slate draft");
    let slate = vault
        .store_connector_slate(&manifest, &draft)
        .expect("FIXTURE: connector slate");
    let mut spec = ConnectorKeySpec::new(SERVER);
    spec.slate_ref = Some(slate);
    spec.protocol_revision = Some(REVISION.to_owned());
    let (catalog, _) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: SERVER.to_owned(),
                connector: SERVER.to_owned(),
                summary: "Restored code consent fixture".to_owned(),
                verbs: vec![TOOL.to_owned()],
                call_class: ConnectorCallClass::ScopedMcp,
                registered_at: now,
            },
            spec,
            now,
        )
        .expect("FIXTURE: catalog connector");
    let revision = vault
        .connector_slate(slate)
        .expect("FIXTURE: the slate reads")
        .expect("FIXTURE: the slate exists")
        .revision();
    vault
        .accept_connector_slate_all_manual(owner, slate, revision)
        .expect("FIXTURE: always ask");
    vault
        .attest_connector_key(owner, &catalog, REVISION, now)
        .expect("FIXTURE: active connector");
    vault
        .consent_connector_tools(
            owner,
            &ConnectorToolConsent {
                connector: SERVER.to_owned(),
                target: ConnectorConsentTarget::Owner,
                endpoint: ENDPOINT.to_owned(),
                rows: vec![ConnectorToolConsentRow {
                    tool: TOOL.to_owned(),
                    data_class_ceiling: DataClass::Personal,
                    headers: false,
                }],
            },
        )
        .expect("FIXTURE: connector grant");
}

fn hold_connector(host: &Host, witness: &InvocationSlipBinding) -> (EntityId, EntityId) {
    let (run, wait) = (EntityId::now(), EntityId::now());
    let memory = code_consent_memory(&host.vault, host.owner, run, wait, Some(witness))
        .expect("FIXTURE: connector call site");
    let mut sender = RecoverySender::new(Some(ENDPOINT));
    let outcome = host
        .vault
        .call_connector(
            &memory,
            ConnectorCallRequest {
                name: SERVER.to_owned(),
                source: None,
                tool: TOOL.to_owned(),
                arguments: json!({}),
                mutation: MutationIntent::default(),
            },
            Some(ConnectorCallInvocation {
                attempt_id: AttemptId::now(),
                call_seq: 0,
            }),
            &mut sender,
        )
        .expect("FIXTURE: the connector call holds");
    let ConnectorCallOutcome::Held { call_ref, .. } = outcome else {
        panic!("FIXTURE: expected a held connector call, got {outcome:?}");
    };
    assert_eq!(sender.calls, 0, "FIXTURE: minting the hold sent nothing");
    park_code_consent_step(
        &host.vault,
        run,
        wait,
        AgentVerb::ConnectorCall,
        json!({"name": SERVER, "tool": TOOL, "arguments": {}}),
    )
    .expect("FIXTURE: seal the connector wait");
    (wait, call_ref)
}

fn hold_browser(host: &Host) -> EntityId {
    let (run, wait) = (EntityId::now(), EntityId::now());
    let memory = code_consent_memory(&host.vault, host.owner, run, wait, None)
        .expect("FIXTURE: browser call site");
    let verb = AgentVerb::SelfBrowserClick;
    let input = json!({"ref": "#submit"});
    let action = CodeConsentBrowserAction {
        act: verb.as_str().to_owned(),
        operands: input.to_string(),
        class: "browser.send".to_owned(),
        role: "button".to_owned(),
        name: "Submit".to_owned(),
        locator: "#submit".to_owned(),
        page: Some("https://browser.invalid/form".to_owned()),
        audience: Some("https://browser.invalid".to_owned()),
        actor_class: EdgeActorClass::Human as u8,
        project: None,
        tab: "test-tab".to_owned(),
        document: Some("test-document".to_owned()),
        session: "test-guest".to_owned(),
        need: "per_send".to_owned(),
        stopped: None,
        hook_pre: None,
    };
    assert_eq!(
        memory
            .hold_browser_press(verb, action)
            .expect("FIXTURE: the browser hold"),
        Some(wait),
        "FIXTURE: the browser act bound its wait"
    );
    park_code_consent_step(&host.vault, run, wait, verb, input)
        .expect("FIXTURE: seal the browser wait");
    wait
}

fn approve_once(host: &Host, proof: &AuthenticatedOwner, wait_id: EntityId) {
    let vault = &host.vault;
    let view = vault
        .code_consent_wait_as(proof, wait_id)
        .expect("FIXTURE: the wait reads");
    let (wait_generation, step_hash) = view.sealed.expect("FIXTURE: the wait is sealed");
    let handle = TaskAskHandle {
        group_ref: view.ask.expect("FIXTURE: the wait's ask"),
    };
    let result = EntityId::now();
    let at = vault.now_recorded_at();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("role"),
            rmpv::Value::from("answer"),
        )]),
    )
    .expect("FIXTURE: the answer turn bytes");
    vault
        .put_entity(
            &result,
            ENTITY_TYPE_TURN,
            TimeRange { start: at, end: at },
            at,
            &body,
        )
        .expect("FIXTURE: the answer turn");
    let choice = CodeConsentChoice::ApproveOnce;
    let mut word = TaskAskWord::new(result);
    word.option =
        Some(TaskAskOptionId::new(choice.as_str()).expect("FIXTURE: approve-once option"));
    let word = admit_word_unsettled(
        vault,
        &handle,
        WriteActor::new(host.owner, EdgeActorClass::Human),
        &word,
        Some(proof),
    )
    .expect("FIXTURE: the owner's own word");
    let approved = vault
        .settle_code_consent_wait_as(
            proof,
            &CodeConsentAnswerInput {
                run_id: view.run_id,
                wait_id,
                wait_generation,
                step_hash,
                effect_digest: view.effect_digest,
                choice,
                remember_asking_lineage: false,
                word_ref: word.word_ref,
            },
        )
        .expect("FIXTURE: the owner's approval lands without driving the effect");
    assert_approved(&approved);
}

fn assert_approved(view: &CodeConsentWaitView) {
    assert_eq!(
        view.state,
        CodeConsentWaitState::Settling,
        "FIXTURE: unsettled wait"
    );
    assert_eq!(
        view.answer,
        Some(CodeConsentChoice::ApproveOnce),
        "FIXTURE: approval kept"
    );
    assert_eq!(view.outcome, None, "FIXTURE: no settlement kept");
}

struct Fixture {
    host: Host,
    copy: Copy,
    _backups: tempfile::TempDir,
    connector_wait: EntityId,
    browser_wait: EntityId,
    call_ref: EntityId,
    credential: CodeConsentSavedCredential,
    effect_host: Arc<DeferredEffectHost>,
}

impl Fixture {
    fn new() -> Self {
        let host = rooted_host();
        let proof = host
            .vault
            .authenticate_owner(
                host.owner,
                &host.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("FIXTURE: owner proof on the host");
        let deferred = Arc::new(DeferredEffectHost::default());
        host.vault
            .install_code_consent_effect_host(deferred.clone());
        register_manual_connector(&host.vault, &proof);
        let witness = caller_witness(&host);
        let (connector_wait, call_ref) = hold_connector(&host, &witness);
        let browser_wait = hold_browser(&host);
        approve_once(&host, &proof, connector_wait);
        approve_once(&host, &proof, browser_wait);
        assert_eq!(
            deferred.0.load(Ordering::Relaxed),
            2,
            "FIXTURE: both drives deferred"
        );
        let credential = CodeConsentSavedCredential {
            instrument: None,
            door: None,
            witness,
        };

        let backups = restore_tempdir();
        let copy = restored_copy(&host, backups.path());
        let effect_host = Arc::new(DeferredEffectHost::default());
        copy.vault
            .install_code_consent_effect_host(effect_host.clone());
        let fx = Self {
            host,
            copy,
            _backups: backups,
            connector_wait,
            browser_wait,
            call_ref,
            credential,
            effect_host,
        };
        let connector = fx.wait(connector_wait);
        assert_approved(&connector);
        assert_eq!(
            fx.copy
                .vault
                .answered_code_consent_wait_for_call(&call_ref)
                .expect("FIXTURE: the call's wait link reads"),
            Some(connector_wait),
            "FIXTURE: the pending connector row points to the answered wait"
        );
        assert_eq!(
            fx.copy
                .vault
                .code_consent_wait_credential(connector_wait)
                .expect("FIXTURE: the kept credential reads")
                .as_ref(),
            Some(&fx.credential),
            "FIXTURE: the wait kept the caller's credential"
        );
        assert_eq!(
            fx.call_settled(),
            Some(false),
            "FIXTURE: the call is pending"
        );
        fx.copy
            .vault
            .verify_invocation_slip(&fx.credential.witness)
            .expect("FIXTURE: the restored caller witness still verifies");
        assert!(
            fx.copy
                .vault
                .route_connector_call(SERVER)
                .expect("FIXTURE: the copied catalog reads")
                .is_some(),
            "FIXTURE: the call still has a catalog route"
        );
        let browser = fx.wait(browser_wait);
        assert_approved(&browser);
        assert!(
            browser.browser.is_some(),
            "FIXTURE: the browser act was restored"
        );
        assert!(
            fx.copy
                .vault
                .approved_browser_code_consent_waits(u64::MAX)
                .expect("FIXTURE: the approved browser waits list reads")
                .contains(&browser_wait),
            "FIXTURE: the browser wait has not been admitted"
        );
        assert!(
            approve_once_available(&fx.copy.vault, browser.effect_digest)
                .expect("FIXTURE: the browser marker reads"),
            "FIXTURE: the browser's approve-once marker is live"
        );
        fx
    }

    fn wait(&self, id: EntityId) -> CodeConsentWaitView {
        self.copy
            .vault
            .code_consent_wait_as(&self.copy.proof, id)
            .expect("FIXTURE: the restored wait reads")
    }

    fn call_settled(&self) -> Option<bool> {
        held_connector_call_settled(&self.copy.vault, &self.call_ref)
            .expect("FIXTURE: the restored connector row reads")
    }

    fn assert_unchanged(&self, before: &CodeConsentWaitView, committed: usize) {
        assert_eq!(&self.wait(before.wait_id), before, "the wait is unchanged");
        assert_eq!(
            self.call_settled(),
            Some(false),
            "the pending call was not settled"
        );
        assert_eq!(
            self.effect_host.0.load(Ordering::Relaxed),
            0,
            "the effect host was not called"
        );
        assert_eq!(
            last_committed_txn_id(&self.copy.vault),
            committed,
            "no write committed"
        );
    }
}

/// The answered connector pass holds the call and its wait until the owner joins.
#[test]
fn an_unjoined_copy_keeps_the_answered_code_connector_call_held() {
    let fx = Fixture::new();
    let vault = &fx.copy.vault;
    let before = fx.wait(fx.connector_wait);
    let committed = last_committed_txn_id(vault);
    // The copy has not installed this endpoint. A drive reaches a terminal
    // refusal before a transport or the outbound gate could stop it.
    let mut transport = RecoverySender::new(None);

    let answered = vault
        .resume_answered_code_consent_wait(fx.connector_wait, &mut transport)
        .expect("the answered pass returns the held wait");
    assert_eq!(
        answered, before,
        "the answered pass leaves its wait settling"
    );
    fx.assert_unchanged(&before, committed);
    assert_eq!(
        transport.endpoint_checks.get(),
        0,
        "the connector host was not called"
    );
    assert_eq!(transport.calls, 0, "nothing was sent");

    // The answered entry returns only the view. Listing reaches the same
    // code-owned hold with `answered = false` and exposes its full outcome.
    let (outcome, _) = vault
        .resume_connector_call_listing(&fx.call_ref, &mut transport)
        .unwrap();
    assert_eq!(
        outcome,
        ConnectorCallOutcome::Held {
            call_ref: fx.call_ref,
            decision_ref: None,
            reasons: vec!["restored_not_joined".to_owned()],
            approval_digest: None,
        }
    );
    fx.assert_unchanged(&before, committed);
    assert_eq!(transport.endpoint_checks.get(), 0);
    assert_eq!(transport.calls, 0);

    owner_joins(&fx.host, &fx.copy);
    let after = vault
        .resume_answered_code_consent_wait(fx.connector_wait, &mut transport)
        .unwrap();
    assert_eq!(after.state, CodeConsentWaitState::Settled);
    assert_eq!(after.outcome, Some(CodeConsentSettleOutcome::Refused));
    assert_eq!(after.reasons, ["connector_endpoint_not_installed"]);
    assert_eq!(fx.call_settled(), Some(true));
    assert_eq!(
        transport.endpoint_checks.get(),
        1,
        "the joined pass reached the connector host"
    );
    assert_eq!(transport.calls, 0);
}

/// A credential refusal cannot settle an answered call and wait before the join.
#[test]
fn an_unjoined_copy_defers_a_code_connector_credential_refusal() {
    let fx = Fixture::new();
    let vault = &fx.copy.vault;
    let before = fx.wait(fx.connector_wait);
    let committed = last_committed_txn_id(vault);
    let refusal = VerbAskRefusal::CredentialRevoked;

    let held = vault
        .refuse_answered_code_consent_wait(fx.connector_wait, &fx.credential, refusal)
        .expect("the unjoined refusal returns the held wait");
    assert_eq!(
        held, before,
        "the credential refusal leaves the wait settling"
    );
    fx.assert_unchanged(&before, committed);

    owner_joins(&fx.host, &fx.copy);
    let after = vault
        .refuse_answered_code_consent_wait(fx.connector_wait, &fx.credential, refusal)
        .unwrap();
    assert_eq!(after.state, CodeConsentWaitState::Settled);
    assert_eq!(after.outcome, Some(CodeConsentSettleOutcome::Refused));
    assert!(
        after
            .reasons
            .iter()
            .any(|reason| reason == "credential_revoked")
    );
    assert_eq!(fx.call_settled(), Some(true));
}

/// Browser admission keeps the one-shot marker and writes no admission before the join.
#[test]
fn an_unjoined_copy_does_not_admit_an_approved_browser_code_wait() {
    let fx = Fixture::new();
    let vault = &fx.copy.vault;
    let before = fx.wait(fx.browser_wait);
    let committed = last_committed_txn_id(vault);

    assert_eq!(
        vault
            .admit_browser_code_consent_wait(fx.browser_wait)
            .expect("browser admission reads"),
        None,
        "the unjoined copy releases no browser act"
    );
    fx.assert_unchanged(&before, committed);
    assert!(
        approve_once_available(vault, before.effect_digest).unwrap(),
        "marker still live"
    );
    assert!(
        vault
            .approved_browser_code_consent_waits(u64::MAX)
            .unwrap()
            .contains(&fx.browser_wait)
    );

    owner_joins(&fx.host, &fx.copy);
    let admitted = vault
        .admit_browser_code_consent_wait(fx.browser_wait)
        .unwrap()
        .expect("the joined copy admits the exact act");
    assert_eq!(admitted.run_id, before.run_id);
    assert_eq!(Some(admitted.action), before.browser);
    assert!(
        !vault
            .approved_browser_code_consent_waits(u64::MAX)
            .unwrap()
            .contains(&fx.browser_wait)
    );
    assert!(matches!(
        approve_once_available(vault, before.effect_digest),
        Err(oneiron::Error::Gate(
            oneiron::error::GateError::ConsentApproveOnceSpent(_)
        ))
    ));
}

/// The browser host's refusal cannot settle an approved wait before the join.
#[test]
fn an_unjoined_copy_does_not_settle_an_approved_browser_code_wait() {
    let fx = Fixture::new();
    let vault = &fx.copy.vault;
    let before = fx.wait(fx.browser_wait);
    let committed = last_committed_txn_id(vault);
    // The served host can refuse before admitting the act, if guest admission fails.
    let outcome = CodeConsentBrowserOutcome::Refused(vec!["fixture_guest_refused".to_owned()]);

    assert!(
        !vault
            .settle_browser_code_consent_wait(fx.browser_wait, outcome.clone())
            .expect("browser settlement reads"),
        "the unjoined copy did not settle the browser wait"
    );
    fx.assert_unchanged(&before, committed);
    assert!(
        approve_once_available(vault, before.effect_digest).unwrap(),
        "marker still live"
    );

    owner_joins(&fx.host, &fx.copy);
    assert!(
        vault
            .settle_browser_code_consent_wait(fx.browser_wait, outcome)
            .unwrap()
    );
    let after = fx.wait(fx.browser_wait);
    assert_eq!(after.state, CodeConsentWaitState::Settled);
    assert_eq!(after.outcome, Some(CodeConsentSettleOutcome::Refused));
    assert_eq!(after.reasons, ["fixture_guest_refused"]);
}
