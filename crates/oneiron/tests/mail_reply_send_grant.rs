//! PLAN L3-35 PR 4, D6 (the drafter sends its reply under the vault's
//! send grant; Engine rulings L3-35-PRINCIPAL = A and L335-REPLY-GMAIL = A):
//! the agent that drafted a mail reply dispatches its current revision as
//! itself, and the Gate's send check-in decides.
//!
//! - Under a `check_in` mode row of `full-access` on `outbound_send`, the
//!   drafter's send goes: the draft is `Sent`, its Ask clears, and sending
//!   again answers `Sent` with no second provider send.
//! - With no row, the Member role default asks: the dispatch is held, the
//!   draft stays `Proposed` with its outcome `held: ...` and its Ask
//!   standing, and the mailbox's person still sends it by approving it.
//! - Once the Gate admits the drafter's send, the revision is neither
//!   discarded nor drafted again until the send's outcome settles it (the
//!   pipeline review of #8870): a discard or a redraft made while the
//!   provider send runs is refused, and the draft ends `Sent`.
//! - A mailbox whose person is not the vault's Owner is never dispatched,
//!   even under a full-access row: the draft stays `Proposed` with
//!   `held: mailbox_person_approves`, keeping that person's press. A Google
//!   reply likewise waits for its person's press (L335-REPLY-GMAIL = A);
//!   this file exercises the IMAP account route.
//!
//! The provider send goes to a recording sink through
//! `oneiron::test_doors::mail_reply_send`: SMTP needs TLS with platform
//! roots and Graph has constant URLs, so no test sends through them.
//!
//! Red at the PR 3 head: the target does not build, with no
//! `mail_reply_send` door and no `test_doors::mail_reply_send`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test mail_reply_send_grant`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::mail_pack::{
    IMAP_CONNECTOR_EFFECTOR, MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage,
    MailHistoryRead, MailIdPage, MailInboxRequest, MailListQuery, MailMessageRef, MailProvider,
    MailProviderWire, MailReplyApproveRequest, MailReplyDraftRef, MailReplyDraftRequest,
    MailReplyDraftState, MailReplyDraftView, MailReplySendRequest, MailSourceConnectRequest,
    MailSourceKind, MailSyncBudget, MailSyncSource, SMTP_SUBMISSION_CONNECTOR_EFFECTOR,
    install_mail_calendar_pack_embedded,
};
use oneiron::memory::Memory;
use oneiron::memory::hook_regen_doors::PackPutOutcome;
use oneiron::outbound::{
    OutboundExecutionOutcome, OutboundExecutionRequest, OutboundExecutionSink,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{
    SECRET_CUSTODY_SCHEMA_VERSION, SECRET_SCOPE_READ, decode_secret_custody_body,
};
use oneiron::subject_model::anchor_actor_subject;
use oneiron::test_doors::mail_reply_send::{
    approve_mail_reply_into, mail_reply_send_into, reply_ask_open,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde_json::json;

/// The owner's mailbox address.
const OWNER_ADDRESS: &str = "owner@example.com";
/// The second person's mailbox address.
const MEMBER_ADDRESS: &str = "member@example.com";
/// The counterparty the parent message comes from.
const COUNTERPARTY: &str = "noor@example.com";
/// The fixture IMAP host both mailboxes read from.
const IMAP_HOST: &str = "imap.example.com";
/// The fixture submission host both mailboxes send through.
const SMTP_HOST: &str = "smtp.example.com";
/// The parent message's RFC Message-ID.
const PARENT_MESSAGE_ID: &str = "<reply-fixture-parent@example.com>";

/// An owned vault with the host start a server makes, and its owner: the
/// `mail_active_sources` bootstrap. The directory stays alive beside the
/// vault.
fn owned_vault() -> (tempfile::TempDir, Vault, EntityId) {
    let directory = tempfile::tempdir().expect("a temp dir");
    let vault =
        Vault::open_owned(directory.path(), VaultConfig::default()).expect("open the vault owned");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let issuer =
        HostSlipIssuer::from_secret(b"mail reply send grant test host").expect("a host issuer");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_host_root_slip(&issuer)
        .expect("root the vault under the host");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("profile this install");
    (directory, vault, owner)
}

/// Installs the mail/calendar pack as the embedded owner.
fn install_pack(vault: &Vault, owner: EntityId) {
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let installed = install_mail_calendar_pack_embedded(&memory).expect("install the mail pack");
    assert_eq!(
        installed.outcome,
        PackPutOutcome::Installed,
        "the embedded owner installs the pack: {installed:?}"
    );
}

/// Registers the IMAP credential `custody_ref` for `username`: the
/// `mail_active_sources` custody body, its value the IMAP credential JSON
/// and its bindings the two mail connectors at `T0Doored`, stored for
/// `holder` (`None` is the Owner's own, which names no holder scope).
fn register_imap_credential(
    vault: &Vault,
    custody_ref: &str,
    username: &str,
    holder: Option<EntityId>,
) {
    let credential = json!({
        "host": IMAP_HOST,
        "port": 993,
        "security": "tls",
        "username": username,
        "password": "fixture-imap-password",
        "submission": {
            "host": SMTP_HOST,
            "port": 587,
            "security": "starttls",
        },
    });
    let band = |min: u64, max: u64| {
        RmpValue::Map(vec![
            (RmpValue::from("min"), RmpValue::from(min)),
            (RmpValue::from("max"), RmpValue::from(max)),
        ])
    };
    let floor = RmpValue::Map(vec![
        (RmpValue::from("portable"), band(0, 2)),
        (RmpValue::from("device_bound"), band(0, 2)),
        (RmpValue::from("cross_vault"), band(0, 0)),
        (RmpValue::from("rotation_max_age_secs"), RmpValue::Nil),
        (RmpValue::from("env_bindings"), RmpValue::Map(vec![])),
    ]);
    let holder_scope = holder.map(|person| format!("actor:{}", person.to_hex()));
    let binding = |effector: &str| {
        let mut scopes = vec![RmpValue::from(SECRET_SCOPE_READ)];
        if let Some(scope) = holder_scope.as_deref() {
            scopes.push(RmpValue::from(scope));
        }
        RmpValue::Map(vec![
            (RmpValue::from("effector"), RmpValue::from(effector)),
            (RmpValue::from("tier_ceiling"), RmpValue::from(0_u64)),
            (RmpValue::from("scopes"), RmpValue::Array(scopes)),
        ])
    };
    let body = RmpValue::Map(vec![
        (
            RmpValue::from("schema_version"),
            RmpValue::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (RmpValue::from("name"), RmpValue::from(custody_ref)),
        (RmpValue::from("class"), RmpValue::from("custody-portable")),
        (RmpValue::from("device_only"), RmpValue::from(false)),
        (
            RmpValue::from("value_bytes"),
            RmpValue::Binary(credential.to_string().into_bytes()),
        ),
        (RmpValue::from("status"), RmpValue::from("active")),
        (RmpValue::from("registered_at"), RmpValue::from(1_u64)),
        (RmpValue::from("rotated_at"), RmpValue::Nil),
        (RmpValue::from("rotation_generation"), RmpValue::from(0_u64)),
        (
            RmpValue::from("bindings"),
            RmpValue::Array(vec![
                binding(IMAP_CONNECTOR_EFFECTOR),
                binding(SMTP_SUBMISSION_CONNECTOR_EFFECTOR),
            ]),
        ),
        (RmpValue::from("manifest_ref"), RmpValue::from("")),
        (RmpValue::from("declared_paths"), RmpValue::Array(vec![])),
        (RmpValue::from("policy_floor_snapshot"), floor),
        (RmpValue::from("model_reveal_allowed"), RmpValue::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode the custody body");
    let _ = vault
        .register_secret(decode_secret_custody_body(&bytes).expect("decode the custody body"))
        .expect("register the IMAP credential");
}

/// Connects an Active IMAP personal mailbox for `address`, backed by its
/// own custody record `custody_ref`: the owner's own when `for_person` is
/// none, another person's when it names them. Answers the source.
fn connect_imap_mailbox(
    vault: &Vault,
    owner_memory: &Memory<'_>,
    address: &str,
    username: &str,
    custody_ref: &str,
    for_person: Option<EntityId>,
) -> EntityId {
    register_imap_credential(vault, custody_ref, username, for_person);
    let connected = owner_memory
        .mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Imap,
            kind: MailSourceKind::PersonalMailbox,
            address: address.to_owned(),
            provider_account: format!("{username}@{IMAP_HOST}"),
            custody_ref: custody_ref.to_owned(),
            members: Vec::new(),
            for_person: for_person.map(|person| person.to_hex()),
            channel_identity_ref: None,
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
        })
        .expect("connect the IMAP mailbox");
    EntityId::from_hex(&connected.source.source_ref).expect("parse the source ref")
}

/// A provider wire serving the one received message: the listing names it,
/// its headers read, and the change feed is empty.
struct OneMessageWire {
    headers: MailHeaders,
}

impl MailProviderWire for OneMessageWire {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::error::Result<String> {
        Ok("fixture-anchor".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> oneiron::error::Result<MailIdPage> {
        Ok(MailIdPage {
            messages: vec![MailMessageRef {
                provider_id: self.headers.provider_id.clone(),
                thread_id: self.headers.thread_id.clone(),
            }],
            next_page: None,
        })
    }

    fn headers(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::error::Result<Option<MailHeaders>> {
        Ok((provider_id == self.headers.provider_id).then(|| self.headers.clone()))
    }

    fn full(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::error::Result<Option<MailFull>> {
        // Never read: the step's body budget is 0. Served whole if asked,
        // as the `mail_counterparty` wire serves its message.
        Ok((provider_id == self.headers.provider_id).then(|| MailFull {
            headers: self.headers.clone(),
            body_text: Some("Can we move the review to Thursday?".to_owned()),
            attachments: Vec::new(),
            content_digest: None,
        }))
    }

    fn history(
        &self,
        _source: &MailSyncSource,
        _anchor: &str,
        _page: Option<&str>,
    ) -> oneiron::error::Result<MailHistoryRead> {
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes: Vec::new(),
            next_page: None,
            anchor: "fixture-anchor".to_owned(),
        }))
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> oneiron::error::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// Lands one message from `from` to `to` on `source` through the public
/// sync step: headers only, one listing page, no bodies.
fn land_one_message(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    source: EntityId,
    from: &str,
    to: &str,
    message_id: &str,
) {
    let received_at = vault.now_recorded_at();
    let wire = OneMessageWire {
        headers: MailHeaders {
            provider_id: "1".to_owned(),
            thread_id: Some("fixture-thread-1".to_owned()),
            rfc_message_id: Some(message_id.to_owned()),
            in_reply_to: None,
            references: Vec::new(),
            from: Some(from.to_owned()),
            to: vec![to.to_owned()],
            cc: Vec::new(),
            reply_to: Vec::new(),
            subject: Some("The quarterly plan".to_owned()),
            date: Some(received_at),
            received_at,
            labels: vec!["INBOX".to_owned()],
            sent_by_mailbox: false,
            trash_or_spam: false,
            draft: false,
        },
    };
    let _ = vault
        .mail_sync_step(
            owner_proof,
            source,
            &wire,
            MailSyncBudget {
                history_pages: 0,
                list_pages: 1,
                bodies: 0,
                attachments: 0,
            },
        )
        .expect("land the parent message");
}

/// A second live PERSON.
fn second_person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a second person",
        )
        .expect("put the second person");
    person
}

/// Creates an active AGENT_DEF with an Auto definition ceiling as the
/// owner, and anchors it to `person`, whose mailbox it drafts in. Answers
/// the drafter.
fn create_drafter(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    owner: EntityId,
    person: EntityId,
    agent_id: &str,
) -> EntityId {
    let agent = EntityId::now();
    let definition = AgentDefinition::new(
        agent_id,
        "A mail reply drafter",
        "1",
        Some("Draft careful replies.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Auto,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        // The codec requires a non-empty provenance map.
        RmpValue::Map(vec![(
            RmpValue::from("definedVia"),
            RmpValue::from("define_agent"),
        )]),
        None,
        true,
        None,
    );
    let at = vault.now_recorded_at();
    vault
        .create_agent_definition_as(
            owner_proof,
            &agent,
            &definition,
            TimeRange { start: at, end: at },
            at,
        )
        .expect("create the drafter's agent definition");
    let _ = anchor_actor_subject(
        vault,
        agent,
        person,
        WriteActor::new(owner, EdgeActorClass::Human),
        at,
    )
    .expect("anchor the drafter to its person");
    agent
}

/// Installs the Owner's manifest beside the seeded one: the Auto ceiling
/// for `agent`, and, when `with_row`, the full-access send row.
fn install_policy(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent: EntityId,
    with_row: bool,
) {
    let mut manifest = json!({
        "schema_version": "1.2",
        "pack_id": "mail-reply-send-grant",
        "pack_version": "1.0.0",
        "min_engine_version": env!("CARGO_PKG_VERSION"),
        "defaults": {"criticality": "normal", "sensitivity": "normal"},
        "rules": [],
        "actor_ceilings": [
            {"actor_class": "agent", "actor_ref": agent.to_hex(), "ceiling": "auto"}
        ],
    });
    if with_row {
        manifest["check_in"] = json!({
            "version": 1,
            "mode": [{"row_ref": "reply-send-free", "act_class": "outbound_send", "mode": "full-access"}],
        });
    }
    let body = rmp_serde::to_vec_named(&manifest).expect("encode the owner manifest");
    vault
        .install_owner_policy_manifest(owner_proof, EntityId::now(), body, vault.now_recorded_at())
        .expect("install the owner manifest");
}

/// Records each provider send the Gate releases, and answers that the
/// provider took it: the test's stand-in for SMTP or Graph.
#[derive(Default)]
struct RecordingSink {
    calls: usize,
    intent_refs: Vec<String>,
}

impl OutboundExecutionSink for RecordingSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        self.intent_refs.push(request.intent_ref.to_owned());
        OutboundExecutionOutcome::delivered_to_channel("provider:reply:1")
    }

    /// One provider send delivers the frozen reply to every recipient it
    /// names, as the account sink does.
    fn delivers_recipient_lists(&self) -> bool {
        true
    }
}

/// The agent's thread and parent turn on `source`: the one landed message.
fn thread_and_parent(agent_memory: &Memory<'_>, source: EntityId) -> (String, String) {
    let page = agent_memory
        .mail_inbox(&MailInboxRequest {
            source_ref: Some(source.to_hex()),
            ..Default::default()
        })
        .expect("read the agent's inbox");
    let item = page
        .items
        .first()
        .expect("the landed parent lists in the agent's inbox");
    (item.thread_ref.clone(), item.turn_ref.clone())
}

/// Drafts the agent's reply to its parent turn. Answers the view.
fn draft_reply(agent_memory: &Memory<'_>, thread_ref: &str, turn_ref: &str) -> MailReplyDraftView {
    agent_memory
        .mail_reply_draft(&MailReplyDraftRequest {
            thread_ref: thread_ref.to_owned(),
            parent_turn_ref: Some(turn_ref.to_owned()),
            body: "Thanks - Thursday works for the review.".to_owned(),
            body_html: None,
            reply_all: false,
            cc: Vec::new(),
            request_key: "reply-send-fixture-1".to_owned(),
        })
        .expect("draft the reply")
}

#[test]
fn drafter_sends_its_reply_under_a_full_access_row() {
    let (_directory, vault, owner) = owned_vault();
    install_pack(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let source = connect_imap_mailbox(
        &vault,
        &owner_memory,
        OWNER_ADDRESS,
        "owner",
        "fixture-imap-owner",
        None,
    );
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        &vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        OWNER_ADDRESS,
        PARENT_MESSAGE_ID,
    );
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafter");
    let agent = create_drafter(&vault, &create_proof, owner, owner, "reply-send.drafter");
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(&vault, &install_proof, agent, true);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    let draft = draft_reply(&agent_memory, &thread_ref, &turn_ref);
    assert_eq!(
        draft.revision, 1,
        "the first draft is revision 1: {draft:?}"
    );
    assert_eq!(
        draft.state,
        MailReplyDraftState::Proposed,
        "a fresh draft waits proposed: {draft:?}"
    );
    let draft_id = EntityId::from_hex(&draft.draft_ref).expect("parse the draft ref");

    let mut sink = RecordingSink::default();
    let sent = mail_reply_send_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        &mut sink,
    )
    .expect("send the draft under the row");
    assert_eq!(
        sent.state,
        MailReplyDraftState::Sent,
        "the full-access row releases the drafter's send: {sent:?}"
    );
    assert_eq!(
        sent.outcome.as_deref(),
        Some("delivered_to_channel"),
        "the sent view names the delivery: {sent:?}"
    );
    assert_eq!(
        sink.calls, 1,
        "the released send reaches the provider once: {sent:?}"
    );
    assert_eq!(
        sink.intent_refs,
        vec![format!("mail-reply:{}:1", draft.draft_ref)],
        "the provider send carries the draft's intent ref: {sent:?}"
    );
    assert!(
        !reply_ask_open(&vault, draft_id, 1).expect("read the revision's Ask"),
        "the sent revision's Ask clears: {sent:?}"
    );

    let again = mail_reply_send_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        &mut sink,
    )
    .expect("send the revision again");
    assert_eq!(
        again.state,
        MailReplyDraftState::Sent,
        "sending again answers Sent: {again:?}"
    );
    assert_eq!(
        sink.calls, 1,
        "the second send makes no second provider call: {again:?}"
    );
}

#[test]
fn drafter_send_without_a_row_waits_for_the_mailbox_person() {
    let (_directory, vault, owner) = owned_vault();
    install_pack(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let source = connect_imap_mailbox(
        &vault,
        &owner_memory,
        OWNER_ADDRESS,
        "owner",
        "fixture-imap-owner",
        None,
    );
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        &vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        OWNER_ADDRESS,
        PARENT_MESSAGE_ID,
    );
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafter");
    let agent = create_drafter(&vault, &create_proof, owner, owner, "reply-send.drafter");
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(&vault, &install_proof, agent, false);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    let draft = draft_reply(&agent_memory, &thread_ref, &turn_ref);
    assert_eq!(
        draft.revision, 1,
        "the first draft is revision 1: {draft:?}"
    );
    assert_eq!(
        draft.state,
        MailReplyDraftState::Proposed,
        "a fresh draft waits proposed: {draft:?}"
    );
    let draft_id = EntityId::from_hex(&draft.draft_ref).expect("parse the draft ref");

    let mut sink = RecordingSink::default();
    let held = mail_reply_send_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        &mut sink,
    )
    .expect("send the draft with no row");
    assert_eq!(
        held.state,
        MailReplyDraftState::Proposed,
        "with no row the draft stays proposed: {held:?}"
    );
    assert!(
        held.outcome
            .as_deref()
            .is_some_and(|outcome| outcome.starts_with("held: ")),
        "the held view names its wait: {held:?}"
    );
    assert_eq!(
        sink.calls, 0,
        "a held send never reaches the provider: {held:?}"
    );
    assert!(
        reply_ask_open(&vault, draft_id, 1).expect("read the revision's Ask"),
        "the held revision's Ask stands: {held:?}"
    );

    let approve_proof = owner_memory
        .embedded_owner("vault.mail.reply.approve")
        .expect("prove the owner to approve");
    let mut approval_sink = RecordingSink::default();
    let approved = approve_mail_reply_into(
        &vault,
        &approve_proof,
        &MailReplyApproveRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        &mut approval_sink,
    )
    .expect("the mailbox person approves");
    assert_eq!(
        approved.state,
        MailReplyDraftState::Sent,
        "the mailbox person's approval sends the revision: {approved:?}"
    );
    assert_eq!(
        approval_sink.calls, 1,
        "the approval reaches the provider once: {approved:?}"
    );
    assert!(
        !reply_ask_open(&vault, draft_id, 1).expect("read the revision's Ask"),
        "the approved revision's Ask clears: {approved:?}"
    );
}

#[test]
fn a_members_mailbox_keeps_its_persons_press() {
    let (_directory, vault, owner) = owned_vault();
    install_pack(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let member = second_person(&vault);
    let source = connect_imap_mailbox(
        &vault,
        &owner_memory,
        MEMBER_ADDRESS,
        "member",
        "fixture-imap-member",
        Some(member),
    );
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        &vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        MEMBER_ADDRESS,
        PARENT_MESSAGE_ID,
    );
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafter");
    let agent = create_drafter(
        &vault,
        &create_proof,
        owner,
        member,
        "reply-send.member-drafter",
    );
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(&vault, &install_proof, agent, true);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    let draft = draft_reply(&agent_memory, &thread_ref, &turn_ref);
    assert_eq!(
        draft.revision, 1,
        "the first draft is revision 1: {draft:?}"
    );
    assert_eq!(
        draft.state,
        MailReplyDraftState::Proposed,
        "a fresh draft waits proposed: {draft:?}"
    );

    let mut sink = RecordingSink::default();
    let waiting = mail_reply_send_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        &mut sink,
    )
    .expect("send the member mailbox draft under the row");
    assert_eq!(
        waiting.state,
        MailReplyDraftState::Proposed,
        "a member's mailbox keeps its draft proposed: {waiting:?}"
    );
    assert_eq!(
        waiting.outcome.as_deref(),
        Some("held: mailbox_person_approves"),
        "the waiting view names the member's press: {waiting:?}"
    );
    assert_eq!(
        sink.calls, 0,
        "a member's send is never dispatched: {waiting:?}"
    );
    let draft_id = EntityId::from_hex(&draft.draft_ref).expect("parse the draft ref");
    assert!(
        reply_ask_open(&vault, draft_id, 1).expect("read the revision's Ask"),
        "the waiting revision's Ask stands: {waiting:?}"
    );
}

/// The first test's world: the owner's IMAP mailbox with one landed parent,
/// a drafter in it under the full-access send row, and the drafter's reply.
/// Answers the drafter, the reply's thread and parent turn, and the draft.
fn owner_mailbox_draft(
    vault: &Vault,
    owner: EntityId,
) -> (EntityId, String, String, MailReplyDraftView) {
    install_pack(vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let source = connect_imap_mailbox(
        vault,
        &owner_memory,
        OWNER_ADDRESS,
        "owner",
        "fixture-imap-owner",
        None,
    );
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        OWNER_ADDRESS,
        PARENT_MESSAGE_ID,
    );
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafter");
    let agent = create_drafter(vault, &create_proof, owner, owner, "reply-send.drafter");
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(vault, &install_proof, agent, true);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    let draft = draft_reply(&agent_memory, &thread_ref, &turn_ref);
    (agent, thread_ref, turn_ref, draft)
}

/// What a sink does to the draft while its provider send runs.
enum DuringSend {
    /// The mailbox's owner discards the draft.
    Discard,
    /// The drafter drafts the reply again, in other words.
    Redraft {
        thread_ref: String,
        turn_ref: String,
    },
}

/// Changes the draft as `during` says from inside the provider send, the
/// moment a discard or redraft racing the dispatch would land, records that
/// answer, and answers that the provider took the reply.
struct ChangingSink<'a, 'm> {
    memory: &'a Memory<'m>,
    draft_ref: String,
    during: DuringSend,
    calls: usize,
    change: Option<Result<MailReplyDraftView, String>>,
}

impl OutboundExecutionSink for ChangingSink<'_, '_> {
    fn execute(&mut self, _request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
        self.calls += 1;
        let change = match &self.during {
            DuringSend::Discard => self.memory.mail_reply_discard(&MailReplyDraftRef {
                draft_ref: self.draft_ref.clone(),
            }),
            DuringSend::Redraft {
                thread_ref,
                turn_ref,
            } => self.memory.mail_reply_draft(&MailReplyDraftRequest {
                thread_ref: thread_ref.clone(),
                parent_turn_ref: Some(turn_ref.clone()),
                body: "Thursday no longer works; Friday instead.".to_owned(),
                body_html: None,
                reply_all: false,
                cc: Vec::new(),
                request_key: "reply-send-fixture-1".to_owned(),
            }),
        };
        self.change = Some(change.map_err(|error| format!("{error:?}")));
        OutboundExecutionOutcome::delivered_to_channel("provider:reply:1")
    }

    fn delivers_recipient_lists(&self) -> bool {
        true
    }
}

#[test]
fn a_discard_while_the_drafters_send_runs_is_refused() {
    let (_directory, vault, owner) = owned_vault();
    let (agent, _, _, draft) = owner_mailbox_draft(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let mut sink = ChangingSink {
        memory: &owner_memory,
        draft_ref: draft.draft_ref.clone(),
        during: DuringSend::Discard,
        calls: 0,
        change: None,
    };
    let sent = mail_reply_send_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        &mut sink,
    )
    .expect("send the draft under the row");
    assert_eq!(sink.calls, 1, "the admitted send reaches the provider once");
    let discard = sink.change.take().expect("the sink tried the discard");
    assert!(
        discard
            .as_ref()
            .is_err_and(|error| error.contains("send was admitted")),
        "a discard while the admitted send runs is refused: {discard:?}"
    );
    assert_eq!(
        sent.state,
        MailReplyDraftState::Sent,
        "the reply the provider took is recorded sent, not discarded: {sent:?}"
    );
}

#[test]
fn a_redraft_while_the_drafters_send_runs_is_refused() {
    let (_directory, vault, owner) = owned_vault();
    let (agent, thread_ref, turn_ref, draft) = owner_mailbox_draft(&vault, owner);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let mut sink = ChangingSink {
        memory: &agent_memory,
        draft_ref: draft.draft_ref.clone(),
        during: DuringSend::Redraft {
            thread_ref,
            turn_ref,
        },
        calls: 0,
        change: None,
    };
    let sent = mail_reply_send_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        &mut sink,
    )
    .expect("send the draft under the row");
    assert_eq!(sink.calls, 1, "the admitted send reaches the provider once");
    let redraft = sink.change.take().expect("the sink tried the redraft");
    assert!(
        redraft
            .as_ref()
            .is_err_and(|error| error.contains("send was admitted")),
        "a redraft while the admitted send runs is refused: {redraft:?}"
    );
    assert_eq!(
        (sent.revision, sent.state),
        (1, MailReplyDraftState::Sent),
        "the revision the provider took stays the draft's, recorded sent: {sent:?}"
    );
}
