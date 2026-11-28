//! FIX 15416 slice 1 (owner rulings EXPORT-MAILBOXES, 2026-11-07 01:43 and
//! 01:45): the Owner's whole-vault JSON export and another member's personal
//! mailbox. A person-owned shared vault (Family) leaves the member's mailbox
//! out and names it to the Owner; an org-owned one (Team) carries it and
//! tells the member.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_json_export_member_mailbox`.
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{InitialSharedMember, SharedVaultPreset};
use oneiron::inbox::{NotificationBody, decode_notification_body};
use oneiron::mail_pack::{
    MailAddressHeaders, MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProvider, MailProviderWire,
    MailSourceConnectRequest, MailSourceKind, MailSyncBudget, MailSyncSource,
    install_mail_calendar_pack_embedded,
};
use oneiron::registry::{
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_TURN,
};
use oneiron::secret_custody::{CustodyTier, SecretBinding};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::{EdgeActorClass, EntityId, Result, Vault, VaultConfig};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use serde_json::{Value, json};

const SHARED: u64 = 42;
const MEMBER_BODY: &str = "yuki-ledger-body-9e47";
const MEMBER_SUBJECT: &str = "yuki-private-subject-31ab";

/// One message in one thread, as a provider answers it.
struct OneMessageWire {
    headers: MailHeaders,
    body: String,
}

impl MailProviderWire for OneMessageWire {
    fn current_anchor(&self, _source: &MailSyncSource) -> Result<String> {
        Ok("anchor-1".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> Result<MailIdPage> {
        Ok(MailIdPage {
            messages: vec![MailMessageRef {
                provider_id: self.headers.provider_id.clone(),
                thread_id: self.headers.thread_id.clone(),
            }],
            next_page: None,
        })
    }

    fn headers(&self, _source: &MailSyncSource, provider_id: &str) -> Result<Option<MailHeaders>> {
        Ok((provider_id == self.headers.provider_id).then(|| self.headers.clone()))
    }

    fn full(&self, _source: &MailSyncSource, provider_id: &str) -> Result<Option<MailFull>> {
        Ok((provider_id == self.headers.provider_id).then(|| MailFull {
            headers: self.headers.clone(),
            body_text: Some(self.body.clone()),
            attachments: Vec::new(),
            content_digest: None,
        }))
    }

    fn history(
        &self,
        _source: &MailSyncSource,
        _anchor: &str,
        _page: Option<&str>,
    ) -> Result<MailHistoryRead> {
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes: Vec::new(),
            next_page: None,
            anchor: "anchor-1".to_owned(),
        }))
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn raw_address_headers(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
    ) -> Result<Option<MailAddressHeaders>> {
        Ok(None)
    }
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// Every mail row the vault holds: conversations, turns and messages.
fn mail_rows(vault: &Vault) -> BTreeSet<EntityId> {
    [
        ENTITY_TYPE_CONVERSATION,
        ENTITY_TYPE_TURN,
        ENTITY_TYPE_MESSAGE,
    ]
    .into_iter()
    .flat_map(|kind| vault.entities_by_type_page(kind, None, 1000).expect("rows"))
    .collect()
}

/// Connects a personal mailbox of `for_person` (`None`: the Owner's own),
/// under its own custody record, and lands one message in it. Answers the
/// source ref and the rows the landing added.
fn mailbox_with_one_message(
    vault: &Vault,
    owner: EntityId,
    for_person: Option<EntityId>,
    tag: &str,
    subject: &str,
    body: &str,
) -> (String, BTreeSet<EntityId>) {
    let custody = format!("{tag}-credential");
    // A member's credential is held for that member; the Owner's for the Owner.
    let scopes = for_person
        .map(|person| format!("actor:{}", person.to_hex()))
        .into_iter()
        .collect();
    vault
        .register_test_secret(
            &custody,
            b"test-mail-token",
            vec![SecretBinding {
                effector: "connector:gmail".to_owned(),
                tier_ceiling: CustodyTier::T0Doored,
                scopes,
            }],
            1,
        )
        .expect("a custody record");
    let address = format!("{tag}@example.com");
    let source = vault
        .memory(owner, EdgeActorClass::Human)
        .mail_sources_connect(&MailSourceConnectRequest {
            provider: MailProvider::Google,
            kind: MailSourceKind::PersonalMailbox,
            address: address.clone(),
            provider_account: format!("{tag}-account"),
            custody_ref: custody,
            members: Vec::new(),
            for_person: for_person.map(|person| person.to_hex()),
            channel_identity_ref: None,
            copy: None,
            on_provider_delete: None,
            calendar_details: None,
        })
        .expect("the mailbox connects")
        .source
        .source_ref;
    let before = mail_rows(vault);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let wire = OneMessageWire {
        headers: MailHeaders {
            provider_id: format!("{tag}-message-1"),
            thread_id: Some(format!("{tag}-thread")),
            rfc_message_id: Some(format!("<{tag}-1@example.com>")),
            in_reply_to: None,
            references: Vec::new(),
            from: Some("sender@example.com".to_owned()),
            to: vec![address],
            cc: Vec::new(),
            reply_to: Vec::new(),
            subject: Some(subject.to_owned()),
            date: Some(now),
            received_at: now,
            labels: vec!["INBOX".to_owned()],
            sent_by_mailbox: false,
            trash_or_spam: false,
            draft: false,
        },
        body: body.to_owned(),
    };
    vault
        .mail_sync_step(
            &proof(vault, owner),
            EntityId::from_hex(&source).expect("a source ref"),
            &wire,
            MailSyncBudget::default(),
        )
        .expect("the mailbox imports");
    let added: BTreeSet<EntityId> = mail_rows(vault).difference(&before).copied().collect();
    assert!(!added.is_empty(), "FIXTURE: {tag}'s import landed rows");
    (source, added)
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    member: EntityId,
    member_source: String,
    owner_rows: BTreeSet<EntityId>,
    member_rows: BTreeSet<EntityId>,
}

/// A vault whose Owner and one member each have a personal mailbox with one
/// message, then shared under `preset`, the member accepted.
fn fixture(preset: SharedVaultPreset) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open_owned(dir.path(), VaultConfig::default()).expect("vault");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let member = EntityId::now();
    vault
        .put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live member PERSON");
    install_mail_calendar_pack_embedded(&vault.memory(owner, EdgeActorClass::Human))
        .expect("the mail pack installs");
    let (_, owner_rows) =
        mailbox_with_one_message(&vault, owner, None, "owen", "owen-subject", "owen-body");
    let (member_source, member_rows) = mailbox_with_one_message(
        &vault,
        owner,
        Some(member),
        "yuki",
        MEMBER_SUBJECT,
        MEMBER_BODY,
    );
    vault
        .initialize_shared_vault(
            &proof(&vault, owner),
            SHARED,
            Some(preset),
            &[InitialSharedMember {
                member_ref: member,
                role: None,
            }],
            10,
        )
        .expect("the shared vault");
    let member_proof = proof(&vault, member);
    let invitation = vault
        .shared_invitations(&member_proof, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.founding)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
        .expect("the member accepts");
    Fixture {
        _dir: dir,
        vault,
        member,
        member_source,
        owner_rows,
        member_rows,
    }
}

/// Every inbox notification addressed to `person`.
fn notifications_for(vault: &Vault, person: EntityId) -> Vec<NotificationBody> {
    vault
        .entities_by_type_page(ENTITY_TYPE_NOTIFICATION, None, 1000)
        .expect("notifications")
        .into_iter()
        .filter_map(|id| vault.get_raw(&id).expect("a notification row"))
        .map(|raw| decode_notification_body(&raw[ENTITY_METADATA_HEADER_LEN..]).expect("a body"))
        .filter(|body| body.recipient.as_deref() == Some(person.to_hex().as_str()))
        .collect()
}

fn export(vault: &Vault) -> (String, Value) {
    let bytes = vault
        .export_vault_json()
        .expect("the whole-vault JSON export");
    (
        String::from_utf8(bytes.clone()).expect("utf-8"),
        serde_json::from_slice(&bytes).expect("JSON"),
    )
}

#[test]
fn owner_json_export_omits_other_member_mailbox() {
    // Person-owned; "Owners can export members' mail" never set, so off.
    let fx = fixture(SharedVaultPreset::Family);
    let (text, bundle) = export(&fx.vault);
    assert!(
        fx.owner_rows.iter().any(|id| text.contains(&id.to_hex())),
        "FIXTURE: the Owner's own mail is in the copy"
    );
    let leaked: Vec<String> = fx
        .member_rows
        .iter()
        .map(EntityId::to_hex)
        .filter(|hex| text.contains(hex))
        .collect();
    assert!(
        leaked.is_empty(),
        "a member's mailbox stays home in a person-owned vault's export: {leaked:?}"
    );
    assert!(
        !text.contains(MEMBER_BODY) && !text.contains(MEMBER_SUBJECT),
        "no word of the member's mail is in the copy"
    );
    let notices = bundle["mailbox_notices"]
        .as_array()
        .expect("the export names the mailboxes it left out");
    assert!(
        notices
            .iter()
            .any(|notice| notice["source_ref"] == json!(fx.member_source)
                && notice["reason"] == json!("member_mailbox")),
        "the member's mailbox is named to the Owner: {notices:?}"
    );
    assert!(
        notifications_for(&fx.vault, fx.member).is_empty(),
        "a mailbox left out tells no one"
    );
}

#[test]
fn org_owner_json_export_carries_member_mailbox_and_tells_member() {
    // Org-owned: the member's mailbox goes, and the member is told.
    let fx = fixture(SharedVaultPreset::Team);
    assert!(
        notifications_for(&fx.vault, fx.member).is_empty(),
        "FIXTURE: no export notice before the export"
    );
    let (text, bundle) = export(&fx.vault);
    assert!(
        fx.owner_rows.iter().any(|id| text.contains(&id.to_hex())),
        "FIXTURE: the Owner's own mail is in the copy"
    );
    assert!(
        fx.member_rows.iter().any(|id| text.contains(&id.to_hex())),
        "an org-owned vault's export carries the member's mailbox"
    );
    let told = notifications_for(&fx.vault, fx.member);
    assert_eq!(told.len(), 1, "the member is told once: {told:?}");
    assert_eq!(told[0].source.producer, "mail_pack.member_mailbox_export");
    assert!(
        told[0].subject_refs.contains(&fx.member_source),
        "the notice names the mailbox: {:?}",
        told[0].subject_refs
    );
    assert_eq!(bundle["mailbox_notices"], json!([]), "nothing was left out");
}
