//! FIX [MAIL-REPLY-GMAIL-SEND-GRANT] (the vault's own `outbound_send`
//! check-in mode row releases a Google reply from the vault Owner's own
//! mailbox; Engine 14:16 rulings GMAIL-GRANT-ROW = A and GMAIL-GRANT-SENDER
//! = A): the agent that drafted a Google reply dispatches its current
//! revision as itself through the mailbox's delegated identity, and the
//! Gate's send check-in decides.
//!
//! - Under a `check_in` mode row of `full-access` on `outbound_send`, with
//!   the identity bound to the drafter, the drafter's send goes: the draft
//!   is `Sent`, its Ask clears, and the Gmail send reaches the wire once
//!   through its token door.
//! - With no row, the rows-only reach keeps the Owner's press per send:
//!   the dispatch is held, the draft stays `Proposed` with its outcome
//!   `held: ...` and its Ask standing, and the wire is never called.
//! - Through an identity bound to another agent, or to the owner PERSON,
//!   the draft is never dispatched even under a full-access row: it stays
//!   `Proposed` with `held: delegated_identity_keeps_person_press`.
//! - Once the Gate admits the drafter's Google send, the Owner's discard
//!   made while Gmail's send runs is refused, and the draft ends `Sent`
//!   (the pipeline review of #8895).
//!
//! The Gmail send goes to a recording wire through
//! `oneiron::test_doors::mail_reply_send`, and the draft takes the answered
//! message's address headers from the test, since Gmail's URLs are
//! constants.
//!
//! Red at PR 4's head cf6e2fa91dc7: the target does not build, with no
//! `mail_reply_send_gmail_into` / `mail_reply_draft_with_address_headers`.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test mail_reply_gmail_send_grant`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::channel_identity::{
    ChannelIdentityFulfillment, ChannelIdentityStep, DelegatedGrantScope,
    delegated_custody_scopes_for_grant,
};
use oneiron::channel_identity_provider::EMAIL_CHANNEL;
use oneiron::channel_identity_provider::gmail::{
    GMAIL_CONNECTOR_EFFECTOR, GMAIL_READONLY_OAUTH_SCOPE, GMAIL_SEND_OAUTH_SCOPE,
    GmailDelegatedAdapter, GmailDelegatedAdapterConfig, GmailSendAuthority, GmailSendWire,
    GmailSendWireError, GmailSentMessage,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::mail_pack::{
    MailAddressHeaders, MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailInboxRequest, MailListQuery, MailMessageRef, MailProvider, MailProviderWire,
    MailReplyDraftRef, MailReplyDraftRequest, MailReplyDraftState, MailReplyDraftView,
    MailReplySendRequest, MailSourceConnectRequest, MailSourceKind, MailSyncBudget, MailSyncSource,
    install_mail_calendar_pack_embedded,
};
use oneiron::memory::Memory;
use oneiron::memory::hook_regen_doors::PackPutOutcome;
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::subject_model::anchor_actor_subject;
use oneiron::test_doors::mail_reply_send::{
    mail_reply_draft_with_address_headers, mail_reply_send_gmail_into, reply_ask_open,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use rmpv::Value as RmpValue;
use serde_json::json;

/// The owner's Gmail mailbox address.
const OWNER_MAILBOX: &str = "owner@gmail.com";
/// The counterparty the parent message comes from.
const COUNTERPARTY: &str = "noor@example.com";
/// The stable Google account id the source resumes on.
const GOOGLE_ACCOUNT_SUB: &str = "google-sub-owner-1";
/// The delegated grant's send custody record name.
const SEND_CUSTODY_REF: &str = "fixture-gmail-send";
/// The Google source's sync credential name.
const SYNC_CUSTODY_REF: &str = "fixture-gmail-sync";
/// The parent message's Gmail thread id.
const PARENT_THREAD_ID: &str = "fixture-gmail-thread-1";
/// The parent message's RFC Message-ID.
const PARENT_MESSAGE_ID: &str = "<gmail-fixture-parent@example.com>";
/// The Gmail message id the recording wire answers.
const SENT_GMAIL_MESSAGE_ID: &str = "fixture-gmail-msg-1";

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
        HostSlipIssuer::from_secret(b"gmail reply send grant test host").expect("a host issuer");
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

/// Registers one Gmail custody record under `custody_ref` with `value` and
/// `scopes` on its single `connector:gmail` binding at `T0Doored`: the
/// `mail_active_sources` body, with the scopes the caller names.
fn register_gmail_custody_record(
    vault: &Vault,
    custody_ref: &str,
    value: &[u8],
    scopes: Vec<String>,
) {
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
    let binding = RmpValue::Map(vec![
        (
            RmpValue::from("effector"),
            RmpValue::from(GMAIL_CONNECTOR_EFFECTOR),
        ),
        (RmpValue::from("tier_ceiling"), RmpValue::from(0_u64)),
        (
            RmpValue::from("scopes"),
            RmpValue::Array(
                scopes
                    .iter()
                    .map(|scope| RmpValue::from(scope.as_str()))
                    .collect(),
            ),
        ),
    ]);
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
            RmpValue::Binary(value.to_vec()),
        ),
        (RmpValue::from("status"), RmpValue::from("active")),
        (RmpValue::from("registered_at"), RmpValue::from(1_u64)),
        (RmpValue::from("rotated_at"), RmpValue::Nil),
        (RmpValue::from("rotation_generation"), RmpValue::from(0_u64)),
        (RmpValue::from("bindings"), RmpValue::Array(vec![binding])),
        (RmpValue::from("manifest_ref"), RmpValue::from("")),
        (RmpValue::from("declared_paths"), RmpValue::Array(vec![])),
        (RmpValue::from("policy_floor_snapshot"), floor),
        (RmpValue::from("model_reveal_allowed"), RmpValue::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("encode the custody body");
    let _ = vault
        .register_secret(decode_secret_custody_body(&bytes).expect("decode the custody body"))
        .expect("register the Gmail credential");
}

/// Registers the send custody record for the delegated identity on
/// `mailbox`: live, `connector:gmail` read-bound at `T0Doored`, naming the
/// mailbox as its subject with the provider's `granted:mail.send` evidence
/// a send row needs.
fn register_gmail_send_custody(vault: &Vault, custody_ref: &str, mailbox: &str) {
    let scopes = delegated_custody_scopes_for_grant(
        EMAIL_CHANNEL,
        mailbox,
        &[DelegatedGrantScope::MailRead, DelegatedGrantScope::MailSend],
    );
    register_gmail_custody_record(vault, custody_ref, b"fixture-gmail-oauth-token", scopes);
}

/// Registers the sync credential for a Google source as
/// `mail_active_sources` does: the same record shape with no scopes, never
/// read by the test wire.
fn register_gmail_sync_custody(vault: &Vault, custody_ref: &str) {
    register_gmail_custody_record(vault, custody_ref, b"test-mail-token", Vec::new());
}

/// Connects an Active Google personal mailbox for `mailbox`, owned by the
/// vault Owner, reading through a send-capable delegated identity bound to
/// `bound_sender`. Answers the source and the identity.
fn connect_google_mailbox(
    vault: &Vault,
    owner_memory: &Memory<'_>,
    mailbox: &str,
    bound_sender: EntityId,
) -> (EntityId, EntityId) {
    register_gmail_send_custody(vault, SEND_CUSTODY_REF, mailbox);
    register_gmail_sync_custody(vault, SYNC_CUSTODY_REF);
    let config = GmailDelegatedAdapterConfig::new(mailbox, SEND_CUSTODY_REF)
        .expect("bind the Gmail grant config")
        .with_google_oauth_scopes_allowing_send(&[
            GMAIL_READONLY_OAUTH_SCOPE,
            GMAIL_SEND_OAUTH_SCOPE,
        ])
        .expect("admit the read and send scopes");
    let adapter = GmailDelegatedAdapter::new(config);
    let identity_id = EntityId::now();
    let at = vault.now_recorded_at();
    let _ = adapter
        .provision_delegated_identity(vault, identity_id, bound_sender, at)
        .expect("provision the delegated identity");
    let _ = vault
        .step_channel_identity(
            &identity_id,
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            at.saturating_add(1),
        )
        .expect("bind the delegated identity");
    let _ = vault
        .step_channel_identity(
            &identity_id,
            ChannelIdentityStep::Fulfill,
            at.saturating_add(2),
        )
        .expect("fulfill the delegated identity");
    let connected = owner_memory
        .mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Google,
            kind: MailSourceKind::PersonalMailbox,
            address: mailbox.to_owned(),
            provider_account: GOOGLE_ACCOUNT_SUB.to_owned(),
            custody_ref: SYNC_CUSTODY_REF.to_owned(),
            members: Vec::new(),
            for_person: None,
            channel_identity_ref: Some(identity_id.to_hex()),
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
        })
        .expect("connect the Google mailbox");
    let source = EntityId::from_hex(&connected.source.source_ref).expect("parse the source ref");
    (source, identity_id)
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
            thread_id: Some(PARENT_THREAD_ID.to_owned()),
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
        "pack_id": "gmail-reply-send-grant",
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

/// What the recording Gmail wire saw: each released send, resolved through
/// its token door and answered without any request.
#[derive(Debug, Default)]
struct GmailSendLog {
    calls: usize,
    token_doors_used: usize,
    thread_ids: Vec<Option<String>>,
}

/// Records each Gmail send the Gate releases, and answers that Google took
/// it: the test's stand-in for Gmail's HTTP API. It resolves its token at
/// the send authority's door and makes no request.
#[derive(Clone)]
struct RecordingGmailWire {
    log: Rc<RefCell<GmailSendLog>>,
}

impl RecordingGmailWire {
    fn new(log: Rc<RefCell<GmailSendLog>>) -> Self {
        Self { log }
    }
}

impl GmailSendWire for RecordingGmailWire {
    fn send_message(
        &self,
        authority: &GmailSendAuthority<'_>,
        _raw: &[u8],
        gmail_thread_id: Option<&str>,
    ) -> std::result::Result<GmailSentMessage, GmailSendWireError> {
        let mut saw_token = false;
        authority
            .with_token_at_door(&mut |token: &[u8]| {
                saw_token = !token.is_empty();
                Ok(())
            })
            .map_err(|error| GmailSendWireError::NotSent(error.to_string()))?;
        let mut log = self.log.borrow_mut();
        log.calls += 1;
        if saw_token {
            log.token_doors_used += 1;
        }
        log.thread_ids.push(gmail_thread_id.map(str::to_owned));
        Ok(GmailSentMessage {
            gmail_message_id: SENT_GMAIL_MESSAGE_ID.to_owned(),
            gmail_thread_id: gmail_thread_id.unwrap_or(PARENT_THREAD_ID).to_owned(),
            rfc_message_id: None,
        })
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

/// Drafts the agent's Google reply to its parent turn, with the answered
/// message's address headers from the test. Answers the view.
fn draft_google_reply(
    agent_memory: &Memory<'_>,
    thread_ref: &str,
    turn_ref: &str,
    mailbox: &str,
) -> MailReplyDraftView {
    mail_reply_draft_with_address_headers(
        agent_memory,
        &MailReplyDraftRequest {
            thread_ref: thread_ref.to_owned(),
            parent_turn_ref: Some(turn_ref.to_owned()),
            body: "Thanks - Thursday works for the review.".to_owned(),
            body_html: None,
            reply_all: false,
            cc: Vec::new(),
            request_key: "gmail-reply-fixture-1".to_owned(),
            attachments: Vec::new(),
        },
        MailAddressHeaders {
            from: vec![COUNTERPARTY.to_owned()],
            reply_to: Vec::new(),
            to: vec![mailbox.to_owned()],
            cc: Vec::new(),
        },
    )
    .expect("draft the Google reply")
}

/// The Gate decision standing on `grant_ref`, newest first, if any: its
/// outcome and its receipt reasons.
fn gate_decision_on_row(vault: &Vault, grant_ref: &str) -> Option<(String, Vec<String>)> {
    let decisions = vault.gate_decisions(64).expect("read the gate decisions");
    decisions.into_iter().find_map(|record| {
        (record.grant_ref.as_deref() == Some(grant_ref))
            .then(|| (record.outcome, record.receipt_reasons))
    })
}

#[test]
fn drafter_sends_its_google_reply_under_the_owners_full_access_row() {
    let (_directory, vault, owner) = owned_vault();
    install_pack(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafter");
    let agent = create_drafter(&vault, &create_proof, owner, owner, "gmail-reply.drafter");
    let (source, _identity) = connect_google_mailbox(&vault, &owner_memory, OWNER_MAILBOX, agent);
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        &vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        OWNER_MAILBOX,
        PARENT_MESSAGE_ID,
    );
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(&vault, &install_proof, agent, true);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    let draft = draft_google_reply(&agent_memory, &thread_ref, &turn_ref, OWNER_MAILBOX);
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

    let log = Rc::new(RefCell::new(GmailSendLog::default()));
    let wire = RecordingGmailWire::new(Rc::clone(&log));
    let sent = mail_reply_send_gmail_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        wire,
    )
    .expect("send the Google draft under the row");
    assert_eq!(
        sent.state,
        MailReplyDraftState::Sent,
        "the full-access row releases the drafter's Google send: {sent:?}"
    );
    assert_eq!(
        sent.outcome.as_deref(),
        Some("delivered_to_channel"),
        "the sent view names the delivery: {sent:?}"
    );
    let borrowed = log.borrow();
    assert_eq!(
        borrowed.calls, 1,
        "the released send reaches Gmail once: {sent:?}"
    );
    assert_eq!(
        borrowed.token_doors_used, 1,
        "the wire resolves its token at the door: {sent:?}"
    );
    assert_eq!(
        borrowed.thread_ids,
        vec![Some(PARENT_THREAD_ID.to_owned())],
        "the reply sends into its parent thread: {sent:?}"
    );
    drop(borrowed);
    assert!(
        !reply_ask_open(&vault, draft_id, 1).expect("read the revision's Ask"),
        "the sent revision's Ask clears: {sent:?}"
    );
    let (outcome, reasons) = gate_decision_on_row(&vault, "check_in:row:reply-send-free")
        .expect("the send's Gate decision stands on the row");
    assert_eq!(
        outcome, "allow",
        "the row releases the Google send: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason == "check_in_row_reply-send-free"),
        "the decision names its row: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason == "check_in_go_never_ask"),
        "the decision names its never-ask: {reasons:?}"
    );
}

#[test]
fn with_no_row_a_google_reply_keeps_the_owners_press() {
    let (_directory, vault, owner) = owned_vault();
    install_pack(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafter");
    let agent = create_drafter(&vault, &create_proof, owner, owner, "gmail-reply.drafter");
    let (source, _identity) = connect_google_mailbox(&vault, &owner_memory, OWNER_MAILBOX, agent);
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        &vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        OWNER_MAILBOX,
        PARENT_MESSAGE_ID,
    );
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(&vault, &install_proof, agent, false);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    let draft = draft_google_reply(&agent_memory, &thread_ref, &turn_ref, OWNER_MAILBOX);
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

    let log = Rc::new(RefCell::new(GmailSendLog::default()));
    let wire = RecordingGmailWire::new(Rc::clone(&log));
    let held = mail_reply_send_gmail_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        wire,
    )
    .expect("send the Google draft with no row");
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
        log.borrow().calls,
        0,
        "a held send never reaches Gmail: {held:?}"
    );
    assert!(
        reply_ask_open(&vault, draft_id, 1).expect("read the revision's Ask"),
        "the held revision's Ask stands: {held:?}"
    );
}

#[test]
fn a_drafter_not_bound_to_the_identity_is_held() {
    let (_directory, vault, owner) = owned_vault();
    install_pack(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafters");
    let agent = create_drafter(&vault, &create_proof, owner, owner, "gmail-reply.first");
    let bound = create_drafter(&vault, &create_proof, owner, owner, "gmail-reply.second");
    let (source, _identity) = connect_google_mailbox(&vault, &owner_memory, OWNER_MAILBOX, bound);
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        &vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        OWNER_MAILBOX,
        PARENT_MESSAGE_ID,
    );
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(&vault, &install_proof, agent, true);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    let draft = draft_google_reply(&agent_memory, &thread_ref, &turn_ref, OWNER_MAILBOX);
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

    let log = Rc::new(RefCell::new(GmailSendLog::default()));
    let wire = RecordingGmailWire::new(Rc::clone(&log));
    let waiting = mail_reply_send_gmail_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        wire,
    )
    .expect("send the draft bound to another agent under the row");
    assert_eq!(
        waiting.state,
        MailReplyDraftState::Proposed,
        "a draft bound to another agent stays proposed: {waiting:?}"
    );
    assert_eq!(
        waiting.outcome.as_deref(),
        Some("held: delegated_identity_keeps_person_press"),
        "the waiting view names the person's press: {waiting:?}"
    );
    assert_eq!(
        log.borrow().calls,
        0,
        "an unbound drafter's send is never dispatched: {waiting:?}"
    );
    assert!(
        reply_ask_open(&vault, draft_id, 1).expect("read the revision's Ask"),
        "the waiting revision's Ask stands: {waiting:?}"
    );
}

#[test]
fn an_identity_bound_to_the_owner_keeps_the_owners_press() {
    let (_directory, vault, owner) = owned_vault();
    install_pack(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafter");
    let agent = create_drafter(&vault, &create_proof, owner, owner, "gmail-reply.drafter");
    let (source, _identity) = connect_google_mailbox(&vault, &owner_memory, OWNER_MAILBOX, owner);
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        &vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        OWNER_MAILBOX,
        PARENT_MESSAGE_ID,
    );
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(&vault, &install_proof, agent, true);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    let draft = draft_google_reply(&agent_memory, &thread_ref, &turn_ref, OWNER_MAILBOX);
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

    let log = Rc::new(RefCell::new(GmailSendLog::default()));
    let wire = RecordingGmailWire::new(Rc::clone(&log));
    let waiting = mail_reply_send_gmail_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        wire,
    )
    .expect("send the owner-bound draft under the row");
    assert_eq!(
        waiting.state,
        MailReplyDraftState::Proposed,
        "an owner-bound draft stays proposed: {waiting:?}"
    );
    assert_eq!(
        waiting.outcome.as_deref(),
        Some("held: delegated_identity_keeps_person_press"),
        "the waiting view names the person's press: {waiting:?}"
    );
    assert_eq!(
        log.borrow().calls,
        0,
        "an owner-bound send is never dispatched: {waiting:?}"
    );
    assert!(
        reply_ask_open(&vault, draft_id, 1).expect("read the revision's Ask"),
        "the waiting revision's Ask stands: {waiting:?}"
    );
}

/// The first test's world: the owner's Google mailbox with one landed
/// parent, its identity bound to a drafter under the owner's full-access
/// send row, and the drafter's reply. Answers the drafter and the draft.
fn owner_google_draft(vault: &Vault, owner: EntityId) -> (EntityId, MailReplyDraftView) {
    install_pack(vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let create_proof = owner_memory
        .embedded_owner("vault.agents.put")
        .expect("prove the owner to create the drafter");
    let agent = create_drafter(vault, &create_proof, owner, owner, "gmail-reply.drafter");
    let (source, _identity) = connect_google_mailbox(vault, &owner_memory, OWNER_MAILBOX, agent);
    let sync_proof = owner_memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("prove the owner for the sync step");
    land_one_message(
        vault,
        &sync_proof,
        source,
        COUNTERPARTY,
        OWNER_MAILBOX,
        PARENT_MESSAGE_ID,
    );
    let install_proof = owner_memory
        .embedded_owner("vault.policy.put")
        .expect("prove the owner to install policy");
    install_policy(vault, &install_proof, agent, true);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let (thread_ref, turn_ref) = thread_and_parent(&agent_memory, source);
    (
        agent,
        draft_google_reply(&agent_memory, &thread_ref, &turn_ref, OWNER_MAILBOX),
    )
}

/// The owner discards the draft from inside Gmail's send, the moment a
/// discard racing the dispatch would land; records that answer, and
/// answers that Google took the reply.
struct DiscardingGmailWire<'a, 'm> {
    owner_memory: &'a Memory<'m>,
    draft_ref: String,
    discard: Rc<RefCell<Option<Result<MailReplyDraftView, String>>>>,
}

impl GmailSendWire for DiscardingGmailWire<'_, '_> {
    fn send_message(
        &self,
        _authority: &GmailSendAuthority<'_>,
        _raw: &[u8],
        gmail_thread_id: Option<&str>,
    ) -> std::result::Result<GmailSentMessage, GmailSendWireError> {
        let discard = self
            .owner_memory
            .mail_reply_discard(&MailReplyDraftRef {
                draft_ref: self.draft_ref.clone(),
            })
            .map_err(|error| format!("{error:?}"));
        *self.discard.borrow_mut() = Some(discard);
        Ok(GmailSentMessage {
            gmail_message_id: SENT_GMAIL_MESSAGE_ID.to_owned(),
            gmail_thread_id: gmail_thread_id.unwrap_or(PARENT_THREAD_ID).to_owned(),
            rfc_message_id: None,
        })
    }
}

#[test]
fn a_discard_while_the_drafters_google_send_runs_is_refused() {
    let (_directory, vault, owner) = owned_vault();
    let (agent, draft) = owner_google_draft(&vault, owner);
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let agent_memory = vault.memory(agent, EdgeActorClass::Agent);
    let discard = Rc::new(RefCell::new(None));
    let wire = DiscardingGmailWire {
        owner_memory: &owner_memory,
        draft_ref: draft.draft_ref.clone(),
        discard: Rc::clone(&discard),
    };
    let sent = mail_reply_send_gmail_into(
        &agent_memory,
        &MailReplySendRequest {
            draft_ref: draft.draft_ref.clone(),
            revision: 1,
        },
        wire,
    )
    .expect("send the Google draft under the row");
    let discard = discard.take().expect("the wire tried the discard");
    assert!(
        discard
            .as_ref()
            .is_err_and(|error| error.contains("send was admitted")),
        "a discard while the admitted Google send runs is refused: {discard:?}"
    );
    assert_eq!(
        sent.state,
        MailReplyDraftState::Sent,
        "the reply Google took is recorded sent, not discarded: {sent:?}"
    );
}
