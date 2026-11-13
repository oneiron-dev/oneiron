//! FIX 15416 slices 1 and 3 (owner rulings EXPORT-MAILBOXES, 2026-11-07
//! 01:43 and 01:45): the Owner's whole-vault JSON export and another member's
//! personal mailbox. A person-owned shared vault (Family) leaves the member's
//! mailbox out and names it to the Owner; an org-owned one (Team) carries it
//! and tells the member. In a person-owned vault an Owner may request the
//! mailbox (`vault.mail.export_request`): the member alone answers one Ask,
//! and an approval carries the mailbox in that Owner's next export only.
//!
//! Slice 2: the Owner's whole-vault archive and OKF bundle follow the same
//! rule, and so does every row whose words came from such a mailbox though
//! only a side ledger or the row's birth records it: a blob version's
//! made_by, a born-from Ask, a birth's prompt inputs (fix list rows 22344
//! and 22345, Engine ruling EXPORT-EDGES = C), over every recorded hop.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test owner_json_export_member_mailbox`.
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;

use oneiron::batch::export::WholeVaultExport;
use oneiron::blob_artifact::{
    BlobArtifactBody, BlobArtifactVersion, BlobVersionProvenance, BornFromSource,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{InitialSharedMember, SharedVaultPreset};
use oneiron::inbox::{NotificationBody, decode_notification_body};
use oneiron::llm::decision::DecisionAnswer;
use oneiron::mail_pack::{
    MailAddressHeaders, MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead,
    MailIdPage, MailListQuery, MailMessageRef, MailProvider, MailProviderWire,
    MailSourceConnectRequest, MailSourceKind, MailSyncBudget, MailSyncSource, MailboxLeftOutReason,
    install_mail_calendar_pack_embedded,
};
use oneiron::memory::{ClaimInput, MemoryResult};
use oneiron::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTIFICATION,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use oneiron::secret_custody::{CustodyTier, SecretBinding};
use oneiron::store::GateDecisionId;
use oneiron::temporal::TimeRange;
use oneiron::write_envelope::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
};
use oneiron::{EdgeActorClass, EntityId, Result, Vault, VaultConfig, WriteActor};
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
    owner: EntityId,
    member: EntityId,
    member_source: String,
    owner_rows: BTreeSet<EntityId>,
    member_rows: BTreeSet<EntityId>,
}

/// What a test builds before the vault is shared: the Owner writes as the
/// vault's one person then, and both mailboxes have landed.
struct Staged<'a> {
    vault: &'a Vault,
    owner: EntityId,
    owner_rows: &'a BTreeSet<EntityId>,
    member_rows: &'a BTreeSet<EntityId>,
}

/// A vault whose Owner and one member each have a personal mailbox with one
/// message, then shared under `preset`, the member accepted.
fn fixture(preset: SharedVaultPreset) -> Fixture {
    fixture_with(preset, |_| ()).0
}

/// [`fixture`], with `build` run once both mailboxes have landed and before
/// the vault is shared; answers what `build` answered.
fn fixture_with<T>(
    preset: SharedVaultPreset,
    build: impl FnOnce(&Staged<'_>) -> T,
) -> (Fixture, T) {
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
    let built = build(&Staged {
        vault: &vault,
        owner,
        owner_rows: &owner_rows,
        member_rows: &member_rows,
    });
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
    (
        Fixture {
            _dir: dir,
            vault,
            owner,
            member,
            member_source,
            owner_rows,
            member_rows,
        },
        built,
    )
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

/// Whether `text` holds any of the member's mail rows.
fn carries_member_mail(fx: &Fixture, text: &str) -> bool {
    fx.member_rows.iter().any(|id| text.contains(&id.to_hex()))
}

/// Whether the export names the member's mailbox to the Owner as left out.
fn names_member_mailbox(fx: &Fixture, bundle: &Value) -> bool {
    bundle["mailbox_notices"]
        .as_array()
        .expect("the export's mailbox notices")
        .iter()
        .any(|notice| {
            notice["source_ref"] == json!(fx.member_source)
                && notice["reason"] == json!("member_mailbox")
        })
}

/// The Owner's request for the member's mailbox, called by the verb's name
/// as the Owner's own embedded handle calls it.
fn request_member_mailbox(fx: &Fixture) -> MemoryResult<Value> {
    oneiron::task_verb::sdk::invoke(
        &fx.vault.memory(fx.owner, EdgeActorClass::Human),
        "vault.mail.export_request",
        json!({ "source_ref": fx.member_source }),
    )
}

/// The open Ask whose correlation is the request `view` answers.
fn request_ask_seq(vault: &Vault, view: &Value) -> u64 {
    let request = EntityId::from_hex(view["request_ref"].as_str().expect("a request ref"))
        .expect("a request id");
    vault
        .decision_asks(None, 1000, true)
        .expect("the open Asks")
        .into_iter()
        .find(|ask| ask.correlation == Some(request))
        .expect("the member's Ask for the request is queued")
        .seq
}

/// `who` answers the Ask `seq` with `choice`, as a person.
fn answer_as(vault: &Vault, who: EntityId, seq: u64, choice: &str) -> Result<()> {
    vault
        .answer_decision_ask_as(
            &WriteActor::new(who, EdgeActorClass::Human),
            seq,
            DecisionAnswer::Choice(choice.to_owned()),
        )
        .map(drop)
}

#[test]
fn a_member_approval_carries_their_mailbox_in_the_owner_next_export_once() {
    let fx = fixture(SharedVaultPreset::Family);
    let (text, bundle) = export(&fx.vault);
    assert!(
        !carries_member_mail(&fx, &text) && names_member_mailbox(&fx, &bundle),
        "FIXTURE: before any request the member's mailbox stays home and is named"
    );
    let request =
        request_member_mailbox(&fx).expect("the Owner's request for the member's mailbox is taken");
    assert_eq!(request["state"], json!("pending"), "{request}");
    assert_eq!(request["source_ref"], json!(fx.member_source), "{request}");
    let again = request_member_mailbox(&fx).expect("the Owner asks again");
    assert_eq!(
        again["request_ref"], request["request_ref"],
        "asking again while the member has not answered answers the same request"
    );

    // Not answered: the export never waits; it leaves the mailbox out and names it.
    let (text, bundle) = export(&fx.vault);
    assert!(
        !carries_member_mail(&fx, &text),
        "an unanswered request leaves the member's mailbox out"
    );
    assert!(
        names_member_mailbox(&fx, &bundle),
        "the mailbox an unanswered request left out is named to the Owner"
    );
    assert!(
        notifications_for(&fx.vault, fx.member).is_empty(),
        "a mailbox left out tells no one"
    );

    let seq = request_ask_seq(&fx.vault, &request);
    assert!(
        answer_as(&fx.vault, fx.owner, seq, "Approve").is_err(),
        "no Owner answers the member's Ask in their place"
    );
    answer_as(&fx.vault, fx.member, seq, "Approve").expect("the member approves");

    let (text, bundle) = export(&fx.vault);
    assert!(
        carries_member_mail(&fx, &text),
        "the Owner's next export carries the mailbox its member approved"
    );
    assert!(
        !names_member_mailbox(&fx, &bundle),
        "a carried mailbox is not named as left out"
    );
    let told = notifications_for(&fx.vault, fx.member);
    let producers: BTreeSet<&str> = told
        .iter()
        .map(|notice| notice.source.producer.as_str())
        .collect();
    assert_eq!(
        producers,
        BTreeSet::from([
            "mail_pack.member_mail_request_used",
            "mail_pack.member_mailbox_export",
        ]),
        "the member is told the export carried the mailbox and used the approval: {told:?}"
    );
    assert_eq!(told.len(), 2, "each told once: {told:?}");
    let request_ref = request["request_ref"].as_str().expect("a request ref");
    assert!(
        told.iter().any(|notice| {
            notice.source.producer == "mail_pack.member_mail_request_used"
                && notice.source.event.contains(request_ref)
        }),
        "the use notice names the request: {told:?}"
    );

    // One export only: the approval was used.
    let (text, bundle) = export(&fx.vault);
    assert!(
        !carries_member_mail(&fx, &text),
        "an approval covers one export: the next leaves the mailbox out"
    );
    assert!(
        names_member_mailbox(&fx, &bundle),
        "the next export names the mailbox again"
    );
    assert_eq!(
        notifications_for(&fx.vault, fx.member).len(),
        2,
        "the export after the used approval tells no one"
    );
    let renewed = request_member_mailbox(&fx).expect("the Owner asks again after the use");
    assert_eq!(renewed["state"], json!("pending"), "{renewed}");
    assert_ne!(
        renewed["request_ref"], request["request_ref"],
        "after a use the Owner's request is a new one"
    );
}

#[test]
fn a_declined_request_leaves_the_mailbox_out_and_named() {
    let fx = fixture(SharedVaultPreset::Family);
    let request =
        request_member_mailbox(&fx).expect("the Owner's request for the member's mailbox is taken");
    let seq = request_ask_seq(&fx.vault, &request);
    answer_as(&fx.vault, fx.member, seq, "Decline").expect("the member declines");
    let (text, bundle) = export(&fx.vault);
    assert!(
        !carries_member_mail(&fx, &text),
        "a declined request leaves the member's mailbox out"
    );
    assert!(
        !text.contains(MEMBER_BODY) && !text.contains(MEMBER_SUBJECT),
        "no word of the member's mail is in the copy"
    );
    assert!(
        names_member_mailbox(&fx, &bundle),
        "the mailbox a declined request left out is named to the Owner"
    );
    assert!(
        notifications_for(&fx.vault, fx.member).is_empty(),
        "a declined request tells no one"
    );
    let renewed = request_member_mailbox(&fx).expect("the Owner asks again after a decline");
    assert_eq!(renewed["state"], json!("pending"), "{renewed}");
    assert_ne!(
        renewed["request_ref"], request["request_ref"],
        "after a decline the Owner's request is a new one"
    );
}

/// Every member of an export's ZIP, by path, decompressed.
fn zip_members(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes)).expect("a ZIP archive");
    let mut members = BTreeMap::new();
    for index in 0..archive.len() {
        let mut member = archive.by_index(index).expect("a member");
        let mut body = Vec::new();
        member.read_to_end(&mut body).expect("the member's bytes");
        members.insert(member.name().to_owned(), body);
    }
    members
}

/// Whether any member's path or bytes hold `needle` (a hex id or a word).
fn mentions(members: &BTreeMap<String, Vec<u8>>, needle: &str) -> bool {
    members
        .iter()
        .any(|(path, body)| path.contains(needle) || String::from_utf8_lossy(body).contains(needle))
}

/// The ids of the entity rows an archive carries: `records/entity/*.jsonl`,
/// one JSON object per row with a hex `id` (a SKILL row nests it under
/// `entity`).
fn archive_entity_ids(members: &BTreeMap<String, Vec<u8>>) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for (path, body) in members {
        if !path.starts_with("records/entity/") || !path.ends_with(".jsonl") {
            continue;
        }
        for line in String::from_utf8_lossy(body)
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            let row: Value = serde_json::from_str(line).expect("a JSONL row");
            let id = row
                .get("id")
                .or_else(|| row.pointer("/entity/id"))
                .and_then(Value::as_str);
            ids.extend(id.map(str::to_owned));
        }
    }
    ids
}

/// The ids of the concepts an OKF bundle carries: `<kind>/<32 hex>.md`.
fn okf_entity_ids(members: &BTreeMap<String, Vec<u8>>) -> BTreeSet<String> {
    members
        .keys()
        .filter_map(|path| {
            let id = path.split_once('/')?.1.strip_suffix(".md")?;
            (id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then(|| id.to_owned())
        })
        .collect()
}

/// A TURN among `rows`: an Ask trigger names one.
fn a_turn(vault: &Vault, rows: &BTreeSet<EntityId>) -> EntityId {
    rows.iter()
        .copied()
        .find(|id| vault.get_entity_type(id).expect("a row type") == Some(ENTITY_TYPE_TURN))
        .expect("FIXTURE: the mailbox landed a TURN")
}

fn rows_of(vault: &Vault, kind: u8) -> BTreeSet<EntityId> {
    vault
        .entities_by_type_page(kind, None, 10_000)
        .expect("rows")
        .into_iter()
        .collect()
}

/// A made_by naming `inputs` and `trigger`, its process the Owner's, so the
/// version keeps the inputs exactly as given.
fn made_by_naming(owner: EntityId, inputs: &[EntityId], trigger: Option<MadeByTrigger>) -> MadeBy {
    MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: owner,
            class: MadeByClass::Stated,
            identity: "export-fixture".to_owned(),
            version: "1".to_owned(),
            params_hash: "fixture".to_owned(),
        },
        at: 1,
        trigger,
    }
}

/// One blob artifact with one version, whose made_by is `made_by`: the
/// artifact, the version (its ledger claim is `claim_id`) and the ASSET rows
/// its bytes added.
struct Made {
    artifact: EntityId,
    version: BlobArtifactVersion,
    assets: BTreeSet<EntityId>,
}

fn artifact_made_by(
    vault: &Vault,
    owner: EntityId,
    name: &str,
    bytes: &[u8],
    made_by: &MadeBy,
) -> Made {
    let assets_before = rows_of(vault, ENTITY_TYPE_ASSET);
    let artifact = EntityId::now();
    let at = vault.now_recorded_at();
    let range = TimeRange { start: at, end: at };
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(name, "application/octet-stream"),
            range,
            at,
        )
        .expect("the artifact");
    let version = vault
        .append_blob_artifact_version_made_by(
            &artifact,
            None,
            bytes,
            &BlobVersionProvenance::UserUpload,
            made_by,
            WriteActor::new(owner, EdgeActorClass::Human),
            range,
            at,
        )
        .expect("the version");
    let assets = rows_of(vault, ENTITY_TYPE_ASSET)
        .difference(&assets_before)
        .copied()
        .collect();
    Made {
        artifact,
        version,
        assets,
    }
}

/// A raw PERSON a claim is about.
fn a_person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a PERSON");
    person
}

/// A Proposed claim about `about`, born with `producers` as its prompt
/// inputs: its birth is the only record of what its words came from.
fn claim_prompted_by(
    vault: &Vault,
    owner: EntityId,
    about: EntityId,
    predicate: &str,
    producers: &[EntityId],
) -> EntityId {
    let claim = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .claim_propose_prompted(
            &ClaimInput {
                id: Some(claim.to_hex()),
                predicate: predicate.to_owned(),
                subject_ref: about.to_hex(),
                value: json!("owen-fixture-words"),
                confidence: 0.8,
                source: "inferred".to_owned(),
                world_ref: None,
                relationship_ref: None,
                scope: None,
                valid_from: None,
                valid_to: None,
                occurred_at: None,
                learned_at: None,
                salience: None,
                confidence_details: None,
            },
            "export-fixture",
            producers,
            &[b"read bytes".as_slice()],
        )
        .expect("a proposal born from its prompt rows");
    let birth = vault
        .row_birth(&claim)
        .expect("a birth read")
        .expect("FIXTURE: the claim has a birth");
    for producer in producers {
        assert!(
            birth
                .made_by
                .inputs
                .iter()
                .any(|input| input.row == *producer && input.role == MadeByInputRole::Prompt),
            "FIXTURE: the birth names {} as a prompt input",
            producer.to_hex()
        );
    }
    claim
}

/// Whether an archive or OKF copy's answer names the member's mailbox as
/// left out.
fn names_member_mailbox_in(fx: &Fixture, export: &WholeVaultExport) -> bool {
    export.mailbox_notices().iter().any(|notice| {
        notice.source_ref.as_deref() == Some(fx.member_source.as_str())
            && notice.reason == MailboxLeftOutReason::MemberMailbox
    })
}

/// The Owner's whole-vault archive, its members and the ids of its entity
/// rows.
fn archive_of(
    vault: &Vault,
) -> (
    WholeVaultExport,
    BTreeMap<String, Vec<u8>>,
    BTreeSet<String>,
) {
    let export = vault.export_whole_vault(true).expect("the Owner's archive");
    let members = zip_members(export.bytes());
    let ids = archive_entity_ids(&members);
    (export, members, ids)
}

#[test]
fn owner_archive_and_okf_omit_other_member_mailbox() {
    // Person-owned; "Owners can export members' mail" never set, so off.
    let fx = fixture(SharedVaultPreset::Family);
    let (archive, members, ids) = archive_of(&fx.vault);
    assert!(
        fx.owner_rows.iter().any(|id| ids.contains(&id.to_hex())),
        "FIXTURE: the Owner's own mail is in the archive"
    );
    let okf = fx.vault.export_okf().expect("the Owner's OKF bundle");
    let okf_members = zip_members(okf.bytes());
    assert!(
        !okf_entity_ids(&okf_members).is_empty(),
        "FIXTURE: the OKF bundle holds concepts"
    );
    for (what, export, members) in [
        ("archive", &archive, &members),
        ("OKF bundle", &okf, &okf_members),
    ] {
        for id in &fx.member_rows {
            assert!(
                !mentions(members, &id.to_hex()),
                "a member's mailbox stays home: the {what} carries member row {}",
                id.to_hex()
            );
        }
        assert!(
            !mentions(members, MEMBER_BODY) && !mentions(members, MEMBER_SUBJECT),
            "no word of the member's mail is in the {what}"
        );
        assert!(
            names_member_mailbox_in(&fx, export),
            "the {what} names the member's mailbox it left out"
        );
    }
}

#[test]
fn owner_copy_withholds_a_version_made_from_a_member_mailbox() {
    let (fx, (m, a, b)) = fixture_with(SharedVaultPreset::Family, |s| {
        let m = a_turn(s.vault, s.member_rows);
        let o = a_turn(s.vault, s.owner_rows);
        let a = artifact_made_by(
            s.vault,
            s.owner,
            "a.bin",
            b"a-bytes",
            &made_by_naming(s.owner, &[m], None),
        );
        let b = artifact_made_by(
            s.vault,
            s.owner,
            "b.bin",
            b"b-bytes",
            &made_by_naming(s.owner, &[o], None),
        );
        (m, a, b)
    });
    assert!(
        !a.assets.is_empty() && !b.assets.is_empty(),
        "FIXTURE: each version's bytes are an ASSET row"
    );
    let (export, members, ids) = archive_of(&fx.vault);
    let has = |id: &EntityId| ids.contains(&id.to_hex());
    assert!(
        has(&b.artifact) && has(&b.version.claim_id),
        "control: an artifact made from the Owner's own mail goes, with its version claim"
    );
    assert!(
        !has(&a.artifact) && !has(&a.version.claim_id),
        "an artifact whose version was made from the member's mail stays home, with its version claim"
    );
    assert!(
        a.assets.iter().all(|asset| !has(asset)),
        "bytes only that version uses stay home"
    );
    assert!(
        !mentions(&members, &m.to_hex()),
        "no byte of the member's row"
    );
    assert!(names_member_mailbox_in(&fx, &export));
}

#[test]
fn owner_copy_keeps_shared_bytes_one_whole_use_carries() {
    let (fx, (a, b)) = fixture_with(SharedVaultPreset::Family, |s| {
        let m = a_turn(s.vault, s.member_rows);
        let o = a_turn(s.vault, s.owner_rows);
        let a = artifact_made_by(
            s.vault,
            s.owner,
            "a.bin",
            b"shared-bytes",
            &made_by_naming(s.owner, &[m], None),
        );
        let b = artifact_made_by(
            s.vault,
            s.owner,
            "b.bin",
            b"shared-bytes",
            &made_by_naming(s.owner, &[o], None),
        );
        (a, b)
    });
    assert!(
        !a.assets.is_empty() && b.assets.is_empty(),
        "FIXTURE: one ASSET row, added by the first append"
    );
    let (_, _, ids) = archive_of(&fx.vault);
    let has = |id: &EntityId| ids.contains(&id.to_hex());
    assert!(has(&b.artifact), "control: the Owner-made artifact goes");
    assert!(
        !has(&a.artifact) && !has(&a.version.claim_id),
        "the artifact made from the member's mail stays home"
    );
    assert!(
        a.assets.iter().all(|asset| ids.contains(&asset.to_hex())),
        "the shared bytes go with the use that goes whole"
    );
}

#[test]
fn owner_copy_withholds_two_hop_side_provenance() {
    let (fx, (m, s_row, r_row, b_row, c_row)) = fixture_with(SharedVaultPreset::Family, |s| {
        let m = a_turn(s.vault, s.member_rows);
        let o = a_turn(s.vault, s.owner_rows);
        let s_row = artifact_made_by(
            s.vault,
            s.owner,
            "s.bin",
            b"s-bytes",
            &made_by_naming(s.owner, &[m], None),
        )
        .artifact;
        let r_row = artifact_made_by(
            s.vault,
            s.owner,
            "r.bin",
            b"r-bytes",
            &made_by_naming(s.owner, &[s_row], None),
        )
        .artifact;
        let b_row = artifact_made_by(
            s.vault,
            s.owner,
            "b.bin",
            b"b-bytes",
            &made_by_naming(s.owner, &[o], None),
        )
        .artifact;
        let c_row = artifact_made_by(
            s.vault,
            s.owner,
            "c.bin",
            b"c-bytes",
            &made_by_naming(s.owner, &[b_row], None),
        )
        .artifact;
        (m, s_row, r_row, b_row, c_row)
    });
    let (_, members, ids) = archive_of(&fx.vault);
    assert!(
        ids.contains(&b_row.to_hex()) && ids.contains(&c_row.to_hex()),
        "control: a two-hop chain of the Owner's own rows goes"
    );
    assert!(
        !ids.contains(&s_row.to_hex()),
        "S, made from the member's mail, stays home"
    );
    assert!(
        !ids.contains(&r_row.to_hex()),
        "R, made from S, stays home with it"
    );
    assert!(
        !mentions(&members, &m.to_hex()),
        "no byte of the member's row"
    );
}

#[test]
fn owner_copy_withholds_a_row_whose_birth_names_a_member_mailbox() {
    let (fx, (m, r_row, control)) = fixture_with(SharedVaultPreset::Family, |s| {
        let m = a_turn(s.vault, s.member_rows);
        let o = a_turn(s.vault, s.owner_rows);
        let about = a_person(s.vault);
        let r_row = claim_prompted_by(
            s.vault,
            s.owner,
            about,
            "profile.export_fixture_member",
            &[m],
        );
        let control = claim_prompted_by(
            s.vault,
            s.owner,
            about,
            "profile.export_fixture_owner",
            &[o],
        );
        (m, r_row, control)
    });
    let (_, members, ids) = archive_of(&fx.vault);
    assert!(
        ids.contains(&control.to_hex()),
        "control: a claim born from the Owner's own mail goes"
    );
    assert!(
        !ids.contains(&r_row.to_hex()),
        "a claim born from the member's mail stays home"
    );
    assert!(
        !mentions(&members, &m.to_hex()),
        "no byte of the member's row, in a birth, a handle or an edge"
    );
}

#[test]
fn owner_copy_withholds_an_artifact_born_from_a_member_ask() {
    let (fx, (m, a)) = fixture_with(SharedVaultPreset::Family, |s| {
        let m = a_turn(s.vault, s.member_rows);
        // The Ask alone: no input, so no birth; the version, its head, its
        // born-from row and its ledger claim name the TURN.
        let a = artifact_made_by(
            s.vault,
            s.owner,
            "a.bin",
            b"a-bytes",
            &made_by_naming(s.owner, &[], Some(MadeByTrigger::Ask(m))),
        );
        let born = s
            .vault
            .artifacts_born_from(&BornFromSource::Trigger(MadeByTrigger::Ask(m)))
            .expect("a born-from read");
        assert!(
            born.iter().any(|row| row.artifact_id == a.artifact),
            "FIXTURE: the artifact is born from the member's Ask"
        );
        assert!(
            s.vault
                .row_birth(&a.artifact)
                .expect("a birth read")
                .is_none(),
            "FIXTURE: the artifact has no birth"
        );
        (m, a)
    });
    let (_, members, ids) = archive_of(&fx.vault);
    assert!(
        !ids.contains(&a.artifact.to_hex()) && !ids.contains(&a.version.claim_id.to_hex()),
        "an artifact born from the member's Ask stays home, with its version claim"
    );
    assert!(
        a.assets.iter().all(|asset| !ids.contains(&asset.to_hex())),
        "bytes only that version uses stay home"
    );
    assert!(
        !mentions(&members, &m.to_hex()),
        "no byte of the member's row"
    );
}
