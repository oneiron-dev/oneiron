//! Engine doors whose CLAIM subject has no FACET of its own put that claim in
//! a stored FACET ([CLAIM-FACET-BIRTH-GATE-CENSUS]). `ClaimBody::new` stamps
//! the subject's derived substrate id, which is a stored FACET only for a
//! PERSON, so the CLAIM birth gate (#4389) refused every other subject with
//! `InvalidFacet`. A born claim now takes the vault default facet, or the
//! facet its subject record was born under; a PERSON subject keeps its own
//! substrate.
//! Run with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test claim_facet_birth`.
#![cfg(oneiron_test_support)]

use std::path::PathBuf;
use std::sync::Arc;

use oneiron::actor_claims::{ActorClaimEvidence, ActorClaimRow, write_actor_claim};
use oneiron::affect::state_index::{ENGAGEMENT, GOAL_VELOCITY, StateIndexEvidence};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::MachineRole;
use oneiron::booking::EventTypeKey;
use oneiron::booking::anti_abuse::{
    BookingRequestFacts, booking_ip_hash, quarantine_borderline_submission,
};
use oneiron::campaign::claims::PREDICATE_COMM_DO_NOT_CONTACT;
use oneiron::campaign::send_hygiene::{SuppressionCause, SuppressionInput, apply_suppression};
use oneiron::channel_identity::{ChannelIdentity, ChannelIdentityBinding, SelfHeldShape};
use oneiron::channel_identity_provider::native_mail::{
    NativeMailRunMode, PREDICATE_NATIVE_MAIL_MAILBOX,
};
use oneiron::channel_identity_provider::stalwart::{
    NativeMailReputationReport, NativeMailSignalSource, StalwartConfig,
};
use oneiron::channel_identity_provider::{LINE_CHANNEL, LineChat, LineChatKind};
use oneiron::claim::relationship_predicates::PREDICATE_RELATIONSHIP_PERSON_REF;
use oneiron::code_revision::CodeSessionRun;
use oneiron::consent::AuthenticatedOwner;
use oneiron::context_board::{BoardSelection, BoardTurn};
use oneiron::disclosure::{AttendeeIdentityChoice, UnknownAttendeeAsk, attendee_ask_ref};
use oneiron::git_wire::{GitOid, GitRefName, GitWireRepo, GitWireRepoIdentity};
use oneiron::origin::publication::OriginPublicationRequest;
use oneiron::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::HostBinding;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::claim_facet_birth as door;
use oneiron::test_doors::derive::imported_turn;
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::typed_body::TypedBodyWriter;
use oneiron::write_envelope::provenance::made_by::{MadeBy, MadeByClass, MadeByProcess};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EntityId, RepoRef, TimeRange, Vad, VadAnnotation, VadAnnotationSource, Vault,
    VaultConfig, WriteActor,
};
use oneiron_store::ports::manual_clock::ManualClock;
use rmpv::Value;
use serde_json::json;

/// The shipped default policy pack, whose rules a fixture extends.
const SHIPPED_POLICY_PACK: &str = "oneiron-default-policy";

/// The rooted vault's fixed clock: no wall time, no sleeps.
const ROOTED_T0: u64 = 1_780_000_000;
/// The lease owner of the agent run a rooted vault's host holds.
const RUN_LEASE_OWNER: &str = "claim-facet-birth-host";

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    (directory, vault)
}

/// A vault with install signing, a host root, the engine machine identities
/// and a serving install profile, as a host that serves an agent's verb calls
/// holds it; the third value is the embedded owner.
fn rooted_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let mut config = VaultConfig::device();
    config.store_clock = ManualClock::new(ROOTED_T0).bundle();
    let vault = Vault::open(directory.path(), config).expect("rooted vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
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
    (directory, vault, owner)
}

fn stored_row(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, entity_type, TimeRange { start: 5, end: 5 }, 5, body)
        .expect("fixture row");
    id
}

/// The claim stored at `claim`, after checking its scope facet is a stored
/// FACET.
fn claim_in_stored_facet(vault: &Vault, claim: &EntityId) -> ClaimBody {
    let body = vault
        .get_claim(claim)
        .expect("claim read")
        .expect("stored claim");
    assert_eq!(
        vault
            .get_entity_type(&body.scope_facet)
            .expect("facet read"),
        Some(ENTITY_TYPE_FACET),
        "the {} claim's scope facet is a stored FACET",
        body.predicate
    );
    body
}

/// Every `predicate` claim on `subject`, each checked to sit in a stored
/// FACET.
fn claims_on(vault: &Vault, subject: EntityId, predicate: &str) -> Vec<ClaimBody> {
    vault
        .claims_for_subject(&subject)
        .expect("subject claim ids")
        .iter()
        .filter(|id| {
            vault
                .get_claim(id)
                .expect("claim read")
                .is_some_and(|body| body.predicate == predicate)
        })
        .map(|id| claim_in_stored_facet(vault, id))
        .collect()
}

fn default_facet(vault: &Vault) -> EntityId {
    vault.default_facet().expect("vault default facet")
}

fn owner_proof(vault: &Vault, owner: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof")
}

/// An ask about speaker `speaker-1` at roster revision 1 of `session_key`.
fn attendee_ask(vault: &Vault, session_key: &str) -> UnknownAttendeeAsk {
    UnknownAttendeeAsk {
        session_key: session_key.to_owned(),
        speaker_key: "speaker-1".to_owned(),
        roster_revision: 1,
        trigger_turn: None,
        candidates: Vec::new(),
        until: vault.now_recorded_at() + 86_400,
    }
}

/// Declares each `(prefix, exact)` rule normal in the stored default policy,
/// as an owner's rule would: a predicate no rule names takes the criticality
/// floor, so its write pends for the owner instead of landing.
fn declare_predicates_normal(vault: &Vault, declared: &[(&str, bool)]) {
    let axes = json!({ "criticality": "normal", "sensitivity": "normal" });
    for id in vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy manifests")
    {
        let Some(bytes) = vault.get(&id).expect("policy manifest read") else {
            continue;
        };
        let mut manifest: serde_json::Value =
            rmp_serde::from_slice(&bytes).expect("policy manifest body");
        if manifest["pack_id"] != SHIPPED_POLICY_PACK {
            continue;
        }
        let rules = manifest
            .as_object_mut()
            .expect("policy manifest map")
            .entry("rules")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("policy rules list");
        for &(prefix, exact) in declared {
            let found = rules.iter().position(|rule| rule["prefix"] == prefix);
            let index = match found {
                Some(index) => index,
                None => {
                    rules.push(json!({ "prefix": prefix }));
                    rules.len() - 1
                }
            };
            rules[index]["axes"] = axes.clone();
            if exact {
                rules[index]["exact"] = json!(true);
            }
        }
        oneiron::test_support::put_policy_manifest_bytes(
            vault,
            id,
            &rmp_serde::to_vec_named(&manifest).expect("policy manifest encode"),
        )
        .expect("policy manifest put");
        return;
    }
    panic!("the vault holds no shipped policy manifest");
}

/// One run of `agent`, dispatched and leased by the host, as the host holds
/// the run an agent's calls go through.
fn leased_run(vault: &Vault, agent: EntityId) -> AttemptRecord {
    let now = vault.now_recorded_at();
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("dispatch the agent's run")
    else {
        panic!("the agent's run was not dispatched");
    };
    let ClaimOutcome::Claimed(leased) = AttemptQueue::new(vault)
        .claim(ClaimAttempt {
            lease_owner: RUN_LEASE_OWNER.into(),
            now,
        })
        .expect("claim the run")
    else {
        panic!("the agent's run was not leased");
    };
    assert_eq!(leased.id, status.attempt.id, "the dispatched run is leased");
    leased
}

#[test]
fn code_session_run_provenance_is_born_in_the_default_facet() {
    let (_directory, vault) = fresh_vault();
    let session = stored_row(&vault, ENTITY_TYPE_SESSION, b"code session");
    let actor = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let run = CodeSessionRun {
        session,
        actor,
        model: "model-a".to_owned(),
        prompt_hash: [1; 32],
        content_hash: [2; 32],
        params_hash: [3; 32],
        version: "1".to_owned(),
        diff_lineage_receipt: Value::Map(vec![(Value::from("diff"), Value::from("lineage"))]),
    };
    let claim = vault
        .record_code_session_run(&run, 11)
        .expect("a SESSION's run provenance is recorded");
    let body = claim_in_stored_facet(&vault, &claim);
    assert_eq!(body.scope_facet, default_facet(&vault));
}

#[test]
fn turn_vad_annotation_is_born_in_a_stored_facet() {
    let (_directory, vault) = fresh_vault();
    let turn = stored_row(&vault, ENTITY_TYPE_TURN, b"turn");
    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.5,
            arousal: 0.6,
            dominance: 0.9,
        },
        VadAnnotationSource::UserSelfReport,
        12,
    )
    .expect("annotation");
    vault
        .annotate_turn_vad(&turn, annotation)
        .expect("a TURN is annotated");
    assert_eq!(
        claims_on(&vault, turn, "affect.vad").len(),
        1,
        "one affect.vad claim on the TURN"
    );
}

#[test]
fn member_binding_on_a_non_person_member_is_born_in_the_default_facet() {
    let (_directory, vault) = fresh_vault();
    declare_predicates_normal(&vault, &[(PREDICATE_RELATIONSHIP_PERSON_REF, true)]);
    let member = stored_row(&vault, ENTITY_TYPE_ASSET, b"member");
    let person = stored_row(&vault, ENTITY_TYPE_PERSON, b"person");
    let claim = oneiron::federation::bind_member_person(
        &vault,
        member,
        person,
        TimeRange { start: 13, end: 13 },
        13,
    )
    .expect("a non-PERSON member is bound");
    let body = claim_in_stored_facet(&vault, &claim);
    assert_eq!(body.scope_facet, default_facet(&vault));
}

#[test]
fn member_binding_on_a_person_member_keeps_its_substrate() {
    let (_directory, vault) = fresh_vault();
    declare_predicates_normal(&vault, &[(PREDICATE_RELATIONSHIP_PERSON_REF, true)]);
    let member = stored_row(&vault, ENTITY_TYPE_PERSON, b"member");
    let person = stored_row(&vault, ENTITY_TYPE_PERSON, b"person");
    let claim = oneiron::federation::bind_member_person(
        &vault,
        member,
        person,
        TimeRange { start: 13, end: 13 },
        13,
    )
    .expect("a PERSON member is bound");
    let body = claim_in_stored_facet(&vault, &claim);
    assert_eq!(
        body.scope_facet,
        oneiron::claim::substrate_facet_id(member).expect("substrate id")
    );
}

#[test]
fn line_chat_observation_is_born_in_a_stored_facet() {
    let (_directory, vault) = fresh_vault();
    let destination = format!("U{}", "2".repeat(32));
    let chat = LineChat::new(LineChatKind::Group, format!("C{}", "1".repeat(32)));
    // As the LINE webhook does: the join event is archived first, which
    // stores the provider-inbound MACHINE the observation is about.
    let event = json!({
        "destination": destination,
        "event": { "type": "join", "webhookEventId": "line-join-1" },
    });
    let archive = vault
        .archive_provider_event_with_receipt(
            LINE_CHANNEL,
            "line-join-1",
            &serde_json::to_vec(&event).expect("LINE event encode"),
            14,
        )
        .expect("the LINE join event is archived");
    let claim = vault
        .observe_line_chat_from_archive(&destination, &chat, &archive, true, 14)
        .expect("a LINE chat is observed");
    claim_in_stored_facet(&vault, &claim);
}

#[test]
fn dreamer_peer_binding_is_born_in_a_stored_facet() {
    let (_directory, vault) = fresh_vault();
    let dreamer = vault.dreamer_authority().expect("Dreamer authority");
    let claim = oneiron::edit_distance::register_peer_actor(&vault, 7, &dreamer)
        .expect("the Dreamer MACHINE is registered as a peer actor");
    claim_in_stored_facet(&vault, &claim);
}

/// S85, OPUS-LEARNING's measured case (fleet job 1112-082745-3db7): an
/// AGENT_DEF with no Grant cannot read the TASK addressed to it, so the
/// generated reference check of `tasks.accept` refuses the call and receipts
/// the refusal. The receipt mints the agent's first stamp token, which took
/// the agent's derived substrate id, so the birth gate refused it and the call
/// answered "invalid active facet" instead of the refusal.
#[test]
fn ungranted_agent_accept_is_refused_and_its_stamp_token_is_born_in_the_default_facet() {
    let (_directory, vault, owner) = rooted_vault();
    let agent = define_agent(&vault, "claim-facet-assignee").expect("agent definition");
    let created = invoke(
        &vault.memory(owner, EdgeActorClass::Human),
        "tasks.create",
        json!({
            "spec": { "summary": "summarize the week's notes" },
            "assignee": { "child": { "actor_ref": agent.to_hex() } },
        }),
    )
    .expect("the owner creates the task");
    let task: EntityId = serde_json::from_value(created["task_ref"].clone())
        .unwrap_or_else(|error| panic!("no created task ({error}): {created}"));
    let run = leased_run(&vault, agent);
    let hosted = vault
        .memory(agent, EdgeActorClass::Agent)
        .with_task_host(HostBinding::from_leased(&run, None).expect("host binding"));

    let refusal = invoke(
        &hosted,
        "tasks.accept",
        json!({ "task_ref": task.to_hex(), "intent_key": "take-the-task" }),
    )
    .expect_err("an agent with no Grant reads no TASK");

    assert_eq!(refusal.code, "INVENTED_REFERENCE", "{refusal:?}");
    let tokens = claims_on(&vault, agent, "actor.stamp_token");
    assert_eq!(
        tokens.len(),
        1,
        "the refusal receipt minted one stamp token"
    );
    assert_eq!(tokens[0].scope_facet, default_facet(&vault));
}

/// S31: a typed-body birth written by an AGENT_DEF binds the document peer in
/// the vault default facet; before, only a MACHINE writer had that facet.
#[test]
fn agent_definition_typed_body_peer_binding_is_born_in_the_default_facet() {
    let (_directory, vault, _owner) = rooted_vault();
    let agent = define_agent(&vault, "claim-facet-writer").expect("agent definition");
    let entity = stored_row(&vault, ENTITY_TYPE_ASSET, b"typed body fixture");
    let made_by = MadeBy {
        inputs: Vec::new(),
        process: MadeByProcess {
            actor: agent,
            class: MadeByClass::Concluded,
            identity: "claim-facet-birth-fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "fixture".to_owned(),
        },
        at: 7,
        trigger: None,
    };

    vault
        .birth_typed_body(
            &entity,
            TypedBodyWriter {
                schema: "claim-facet-birth.fixture.v1",
                actor: WriteActor::new(agent, EdgeActorClass::Agent),
                made_by: &made_by,
            },
            |document| {
                document
                    .get_map("body")
                    .insert("text", "fixture")
                    .expect("body edit");
                Ok(())
            },
        )
        .expect("an AGENT_DEF's typed-body birth binds its peer");

    let bindings = claims_on(&vault, agent, "actor.peer_binding");
    assert_eq!(bindings.len(), 1, "one actor.peer_binding claim");
    assert_eq!(bindings[0].scope_facet, default_facet(&vault));
}

/// S124: an AGENT_DEF's lesson drawn from an imported chat is born in a
/// stored FACET (the actor's birth FACET, else the vault default).
#[test]
fn imported_chat_lesson_of_an_agent_definition_is_born_in_a_stored_facet() {
    let (_directory, vault, _owner) = rooted_vault();
    let actor = define_agent(&vault, "claim-facet-learner").expect("agent definition");
    let session = stored_row(&vault, ENTITY_TYPE_SESSION, b"imported session");
    let turn = imported_turn(&vault).expect("imported TURN");
    let evidence = ActorClaimEvidence::chat(session, vec![turn], 20).expect("chat evidence");
    let claim = write_actor_claim(
        &vault,
        ActorClaimRow::Lesson {
            actor,
            text: "check the roster first".to_owned(),
        },
        &evidence,
    )
    .expect("an AGENT_DEF's imported lesson is written");
    claim_in_stored_facet(&vault, &claim);
}

/// S64: a borderline booking's quarantine claim is about the booking page, an
/// EVENT, and is born in a stored FACET.
#[test]
fn booking_quarantine_on_an_event_page_is_born_in_a_stored_facet() {
    let (_directory, vault) = fresh_vault();
    let page = stored_row(&vault, ENTITY_TYPE_EVENT, b"booking page");
    let facts = BookingRequestFacts {
        page_ref: page,
        event_type: Some(EventTypeKey("intro-call".to_owned())),
        ip_hash: booking_ip_hash("203.0.113.10"),
        email_hash: None,
        session_hash: None,
        started_at_millis: 1_000_000,
        submitted_at_millis: 1_005_000,
        submission_fingerprint: [1; 32],
        selected_slot_hash: [2; 32],
        intake_content_hash: [3; 32],
        honeypot_nonempty: false,
        intake_chars: 40,
        active_future_bookings_for_email: 0,
        active_holds_for_session: 0,
        email: None,
    };
    let receipt = quarantine_borderline_submission(&vault, &facts, "borderline", 1)
        .expect("a borderline submission is quarantined");
    let claim = EntityId::from_bytes(receipt.claim_id).expect("quarantine claim id");
    claim_in_stored_facet(&vault, &claim);
}

/// S35: an attendee ask raised by an AGENT_DEF is about the agent, so it is
/// born in the vault default facet. The ask commits in its own write; the
/// owner task that follows may refuse, which this test does not judge.
#[test]
fn attendee_ask_raised_by_an_agent_definition_is_born_in_the_default_facet() {
    let (_directory, vault, _owner) = rooted_vault();
    let agent = define_agent(&vault, "claim-facet-asker").expect("agent definition");
    let _raised = vault
        .memory(agent, EdgeActorClass::Agent)
        .raise_unknown_attendee_ask(&attendee_ask(&vault, "room-agent"));
    let ask = attendee_ask_ref("room-agent", "speaker-1", 1).expect("ask id");
    let body = claim_in_stored_facet(&vault, &ask);
    assert_eq!(body.scope_facet, default_facet(&vault));
}

/// S37: the owner's answer to an attendee ask is a claim about the ask
/// claim, so it is born in the ask's own FACET.
#[test]
fn attendee_identity_answer_is_born_in_its_ask_facet() {
    let (_directory, vault, owner) = rooted_vault();
    let proof = owner_proof(&vault, owner);
    let _raised = vault
        .memory(owner, EdgeActorClass::Human)
        .raise_unknown_attendee_ask(&attendee_ask(&vault, "room-person"));
    let ask = attendee_ask_ref("room-person", "speaker-1", 1).expect("ask id");
    let ask_body = claim_in_stored_facet(&vault, &ask);
    let resolution = vault
        .resolve_attendee_identity(&proof, &ask, 1, AttendeeIdentityChoice::Unknown)
        .expect("the owner answers the ask");
    let identity = claim_in_stored_facet(&vault, &resolution.identity_ref);
    assert_eq!(identity.scope_facet, ask_body.scope_facet);
}

/// S115: a context-board turn whose owner is an AGENT_DEF writes its
/// selection claims in a stored FACET.
#[test]
fn board_turn_of_an_agent_definition_owner_is_born_in_a_stored_facet() {
    let (_directory, vault, _owner) = rooted_vault();
    let owner = define_agent(&vault, "claim-facet-board-owner").expect("agent definition");
    let turn = stored_row(&vault, ENTITY_TYPE_TURN, b"turn");
    let receipt = vault
        .record_board_turn(
            &BoardTurn {
                turn,
                owner,
                at: 1,
                selection: BoardSelection {
                    allowed_base: true,
                    ..BoardSelection::default()
                },
            },
            10,
        )
        .expect("an AGENT_DEF's board turn is recorded");
    assert!(
        !receipt.changed_claims.is_empty(),
        "the board turn writes its selection"
    );
    for claim in &receipt.changed_claims {
        claim_in_stored_facet(&vault, claim);
    }
}

/// S88: a do-not-contact suppression whose subject is no PERSON is born in a
/// stored FACET.
#[test]
fn do_not_contact_on_an_agent_definition_is_born_in_a_stored_facet() {
    let (_directory, vault, _owner) = rooted_vault();
    declare_predicates_normal(&vault, &[(PREDICATE_COMM_DO_NOT_CONTACT, true)]);
    let subject = define_agent(&vault, "claim-facet-suppressed").expect("agent definition");
    let evidence = stored_row(&vault, ENTITY_TYPE_TURN, b"unsubscribe");
    let receipt = apply_suppression(
        &vault,
        SuppressionCause::Unsubscribe,
        &SuppressionInput {
            person_ref: subject,
            campaign_ref: None,
            channel: "email".to_owned(),
            sender_ref: None,
            evidence_ref: evidence,
            occurred_at: 50,
        },
    )
    .expect("the suppression is applied");
    claim_in_stored_facet(&vault, &receipt.do_not_contact_claim_ref);
}

/// S23: the composite state index of an AGENT_DEF subject is born in the
/// vault default facet. On main the TURN's VAD annotation (S10) is refused
/// first, so this red stops before the index.
#[test]
fn state_index_of_an_agent_definition_is_born_in_the_default_facet() {
    let (_directory, vault, _owner) = rooted_vault();
    declare_predicates_normal(&vault, &[("state.", false)]);
    let subject = define_agent(&vault, "claim-facet-state-subject").expect("agent definition");
    let turn = stored_row(&vault, ENTITY_TYPE_TURN, b"turn");
    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.5,
            arousal: 0.6,
            dominance: 0.9,
        },
        VadAnnotationSource::UserSelfReport,
        12,
    )
    .expect("annotation");
    vault
        .annotate_turn_vad(&turn, annotation)
        .expect("a TURN is annotated");
    let facet = default_facet(&vault);
    let signal = |predicate: &str, value: f32| -> EntityId {
        let id = EntityId::now();
        let mut body = ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject),
            Value::F32(value),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("signal claim");
        body.source = Some(ClaimSource::Observed);
        // The public claim door keeps the facet it is given.
        body.scope_facet = facet;
        vault
            .put_claim(&id, &body, TimeRange { start: 10, end: 10 }, 10)
            .expect("signal claim put");
        id
    };
    let evidence = StateIndexEvidence {
        vad_turns: vec![turn],
        goal_velocity: signal(GOAL_VELOCITY, 0.7),
        engagement: signal(ENGAGEMENT, 0.8),
    };
    let index = vault
        .derive_state_index(&subject, &evidence, 20)
        .expect("the state index is derived");
    let body = claim_in_stored_facet(&vault, &index);
    assert_eq!(body.scope_facet, facet);
}

/// S2: an origin publication intent is a claim about the publishing actor's
/// edge to the repo; an AGENT_DEF publisher's intent is born in a stored
/// FACET.
#[test]
fn publication_intent_of_an_agent_definition_is_born_in_a_stored_facet() {
    let (_directory, vault, _owner) = rooted_vault();
    let publisher = define_agent(&vault, "claim-facet-publisher").expect("agent definition");
    let commit = "1".repeat(40);
    let request = OriginPublicationRequest {
        repo_id: EntityId::now(),
        repo: GitWireRepo {
            repo_ref: RepoRef::LocalFolder {
                path: "/nonexistent/repo".to_owned(),
                commit: commit.clone(),
            },
            repo_root: PathBuf::from("/nonexistent/repo"),
            common_dir: PathBuf::from("/nonexistent/repo/.git"),
            identity: GitWireRepoIdentity([7; 32]),
        },
        ref_name: GitRefName::parse_full("refs/heads/main").expect("ref name"),
        expected_old_oid: None,
        new_oid: GitOid::parse_hex(commit).expect("commit oid"),
        required_objects: Vec::new(),
        required_lfs_oids: Vec::new(),
        provenance_claim_id: EntityId::now(),
        actor_id: publisher,
        occurred: TimeRange { start: 5, end: 5 },
        learned_at: 5,
    };
    vault
        .put_origin_publication_intent(&request)
        .expect("an AGENT_DEF's publication intent is put");
    claim_in_stored_facet(&vault, &request.provenance_claim_id);
}

/// S114: the native mailbox record is about the channel identity, which has
/// no FACET of its own.
#[test]
fn native_mailbox_record_is_born_in_the_default_facet() {
    let (_directory, vault) = fresh_vault();
    let identity = stored_row(&vault, ENTITY_TYPE_ASSET, b"channel identity");
    door::record_native_mailbox(&vault, identity, "assistant@mail.example.test", 15)
        .expect("the mailbox is recorded");
    let records = claims_on(&vault, identity, PREDICATE_NATIVE_MAIL_MAILBOX);
    assert_eq!(records.len(), 1, "one mailbox record");
    assert_eq!(records[0].scope_facet, default_facet(&vault));
}

/// S8 and S9: a native mail reputation report writes its heads and, for a
/// degraded mailbox, a rotate proposal, each about the channel identity. The
/// vault is unseeded, so the built-in native mail pack needs no checked
/// connection.
#[test]
fn native_mail_reputation_claims_are_born_in_a_stored_facet() {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open_unseeded_for_test(directory.path(), VaultConfig::device())
        .expect("unseeded vault");
    vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let identity = EntityId::now();
    vault
        .create_channel_identity(
            &identity,
            &ChannelIdentity::requested(
                "email",
                format!("mail-{}@mail.example.test", identity.to_hex()),
                SelfHeldShape::DedicatedAddress,
                ChannelIdentityBinding::agent(EntityId::now()),
                1,
            ),
        )
        .expect("an email identity");
    let evidence_ref = stored_row(&vault, ENTITY_TYPE_ASSET, b"postmaster report");
    let config = StalwartConfig::new(
        "http://127.0.0.1:1/jmap/session",
        "instance-1",
        "owner-1",
        "mail.example.test",
        "domain-1",
        NativeMailRunMode::SelfRun,
    )
    .expect("stalwart config");
    let report = NativeMailReputationReport {
        observation_ref: "report-1".to_owned(),
        evidence_ref,
        source: NativeMailSignalSource::Postmaster,
        delivered: 20,
        bounces: 0,
        complaints: 0,
        spam_label_observations: 1,
        replies: 2,
        out_of_office: 0,
        postmaster_healthy: Some(true),
        observed_at: 50,
    };
    let claims = door::record_reputation(&vault, config, identity, &report)
        .expect("the reputation report is recorded");
    assert!(!claims.is_empty(), "the report writes its heads");
    for claim in &claims {
        claim_in_stored_facet(&vault, claim);
    }
}

fn conflict_repo() -> RepoRef {
    RepoRef::LocalFolder {
        path: "/nonexistent/repo".to_owned(),
        commit: "9d561405a81ffbf29d1369cd848e0ef9fca4f277".to_owned(),
    }
}

/// S96: the open repo conflict claim is a replicated put that skips the birth
/// gate, so it stored the branch subject's derived substrate id, which no
/// FACET row holds; it now stores the vault default facet.
#[test]
fn open_repo_conflict_is_stored_in_the_default_facet() {
    let (_directory, vault) = fresh_vault();
    let branch = stored_row(&vault, ENTITY_TYPE_ASSET, b"branch subject");
    let open = door::record_open_repo_conflict(
        &vault,
        &conflict_repo(),
        branch,
        "feature",
        [&"1".repeat(40), &"2".repeat(40), &"3".repeat(40)],
        vec!["README.md".to_owned()],
    )
    .expect("the open conflict is recorded");
    assert_eq!(
        claim_in_stored_facet(&vault, &open).scope_facet,
        default_facet(&vault)
    );
}

/// S97: the conflict resolution claim takes the same replicated put as S96.
#[test]
fn repo_conflict_resolution_is_stored_in_the_default_facet() {
    let (_directory, vault) = fresh_vault();
    let branch = stored_row(&vault, ENTITY_TYPE_ASSET, b"branch subject");
    let resolved = door::put_repo_conflict_resolution(
        &vault,
        &conflict_repo(),
        branch,
        "feature",
        EntityId::now(),
        &"4".repeat(40),
        vec!["README.md".to_owned()],
    )
    .expect("the resolution is recorded");
    assert_eq!(
        claim_in_stored_facet(&vault, &resolved).scope_facet,
        default_facet(&vault)
    );
}
