//! Pinned limit answers of the twelve paged lists (UC-13 PR 4a).
//!
//! Each list resolves its `limit` through rule R (zero refused) or rule O
//! (zero served as one row). A later commit moves each list's arithmetic
//! into one call of the shared resolver in
//! `crates/oneiron-base/src/request_limits.rs` (`page_limit_zero_refused`,
//! `page_limit_zero_as_one`) and must change no answer. This file pins
//! today's answer at `Some(0)`, `Some(1)` and `Some(max + 1)` (and `None`
//! where cheap) so it passes before and after that move. It never calls
//! the resolver fns.
//!
//! Public paths only:
//! `cargo test -p oneiron --all-features --test list_limit_rules`.

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::attempt_queue::AttemptId;
use oneiron::authority::{HostSlipIssuer, MachineRole};
use oneiron::claim::ScopedReadActorKey;
use oneiron::consent::AuthenticatedOwner;
use oneiron::conversation_dag::ReplyStripsRequest;
use oneiron::dreamer_runner::{
    ProgramCheckpointRequest, ProgramRunRequest, TurnProgramAdmissionRequest, program_checkpoint,
    program_run, turn_program_admission,
};
use oneiron::engine_executor::checkpoint_read::{
    CHECKPOINT_READ_MAX_LIMIT, CheckpointReadRequest, checkpoint_as_owner,
};
use oneiron::feeds::{
    FEED_READ_DEFAULT_LIMIT, FEED_READ_MAX_LIMIT, FeedPage, FeedRead, FeedReadRequest,
    FeedSelector, FeedSource, FeedStart, FeedSubscribeRequest,
};
use oneiron::lens::{RECORD_LINKS_TURN_PAGE_MAX, RecordLinksRequest};
use oneiron::mail_pack::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead, MailIdPage,
    MailListQuery, MailProvider, MailProviderWire, MailSourceConnectRequest, MailSourceKind,
    MailSyncSource, install_mail_calendar_pack_embedded,
};
use oneiron::memory::code_run_doors::{
    CODE_RUN_CORRECTIONS_MAX_STEPS, CodeRunCorrectionsRequest, CodeRunStepEvidenceRequest,
};
use oneiron::memory::wake_observation::{
    WAKE_OBSERVATION_PAGE_MAX, WakeObservationRequest, WakeObservationSelector,
};
use oneiron::memory::{
    GrantAskedRequest, MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, WitnessAssertions,
};
use oneiron::receipt::{AUTHORITY_AUDIT_MAX_LIMIT, AuthorityAuditQuery};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::snapshot_read::{StrengthObservationsPageRequest, strength_observations_page};
use oneiron::store::GateDecisionId;
use oneiron::{
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};
use std::sync::Arc;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// `crates/oneiron/src/dreamer_runner/program/read.rs` `PAGE_LIMIT`
/// (private): a turn program's admission and run pages hold 64 rows when
/// the request names no limit, and at most 64.
const PROGRAM_PAGE_LIMIT: u32 = 64;

/// `crates/oneiron/src/conversation_dag/quote_strips.rs` `PAGE_LIMIT`
/// (private): a reply-strip page holds 256 strips when the request names
/// no limit, and at most 256.
const QUOTE_STRIP_PAGE_LIMIT: usize = 256;

/// `crates/oneiron/src/mail_pack/search.rs` `MAX_SEARCH_HITS` (private):
/// the most hits one mail search page lands.
const MAIL_MAX_SEARCH_HITS: u32 = 100;

/// `crates/oneiron/src/mail_pack/search.rs` `DEFAULT_SEARCH_HITS`
/// (private): the hits one mail search page lands when the caller names
/// no limit.
const MAIL_DEFAULT_SEARCH_HITS: u32 = 25;

/// `crates/oneiron/src/memory/people_verbs/grants.rs`
/// `GRANTS_ASKED_PAGE_MAX` (private): the most rows one `grants.asked`
/// page holds.
const GRANTS_ASKED_PAGE_MAX: u32 = 100;

/// `crates/oneiron/src/memory/people_verbs/grants.rs`
/// `GRANTS_ASKED_PAGE_DEFAULT` (private): the rows one `grants.asked`
/// page holds when the caller names no limit.
const GRANTS_ASKED_PAGE_DEFAULT: u32 = 50;

/// `SnapshotReadSettings::DEFAULT.page_rows` (200): the strength
/// observations page holds this many claims when the request names no
/// limit, and at most this many. The owner can change it; these tests
/// run on a fresh vault where it stands at 200.
const SNAPSHOT_PAGE_ROWS_DEFAULT: u32 = 200;

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn open_owned_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn owner_proof(
    vault: &Vault,
    owner: EntityId,
) -> Result<AuthenticatedOwner, Box<dyn std::error::Error>> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

fn put_person(vault: &Vault, learned_at: u64) -> Result<EntityId, Box<dyn std::error::Error>> {
    let id = EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        learned_at,
        b"a person",
    )?;
    Ok(id)
}

/// The owner's read lane, as a client holds it: a slip the host root mints
/// for the owner, with the root's whole scope, verified and read through
/// `from_verified_slip`. Copied from `crates/oneiron/tests/feeds.rs`.
fn owner_key(vault: &Vault) -> Result<ScopedReadActorKey, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"list-limit-rules-host-secret")?;
    let root = vault.ensure_host_root_slip(&issuer)?;
    let issued_at = vault.capability_slip_now()?;
    let mut claims = root.claims.clone();
    claims.slip_id = [0x46; 32];
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".into());
    claims.issued_at = issued_at;
    claims.expires_at = issued_at + 3_600;
    claims.ttl_secs = 3_600;
    let slip = vault.mint_capability_slip(&issuer, claims)?;
    let challenge = b"list-limit-rules";
    let proof = issuer.binding_proof(&slip, challenge)?;
    let verified = vault.verify_capability_slip(&issuer.public_key(), &slip, challenge, &proof)?;
    Ok(ScopedReadActorKey::from_verified_slip(&verified)?)
}

fn changes_from(start: FeedStart) -> FeedSubscribeRequest {
    FeedSubscribeRequest {
        selector: FeedSelector {
            sources: vec![FeedSource::Changes],
            kinds: Vec::new(),
            entity_types: Vec::new(),
            predicates: Vec::new(),
        },
        start,
    }
}

fn read_feed_page(
    vault: &Vault,
    key: &ScopedReadActorKey,
    subscription: EntityId,
    limit: Option<usize>,
) -> Result<FeedPage, Box<dyn std::error::Error>> {
    match vault.feed_read(
        &vault.scoped_read(key.clone()),
        &FeedReadRequest {
            subscription,
            limit,
        },
    )? {
        FeedRead::Page(page) => Ok(page),
        FeedRead::Gap(gap) => panic!("a page, not a gap: {gap:?}"),
    }
}

/// Registers a Gmail credential under `custody_ref`, stored for the owner,
/// as the owner's custody door registers one. Copied from
/// `crates/oneiron/tests/mail_active_sources.rs`.
fn register_mail_credential(vault: &Vault, custody_ref: &str) -> TestResult {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from("connector:gmail")),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (Value::from("scopes"), Value::Array(vec![])),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (Value::from("name"), Value::from(custody_ref)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(b"test-mail-token".to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(1_u64)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
        (Value::from("model_reveal_allowed"), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body)?;
    vault.register_secret(decode_secret_custody_body(&bytes)?)?;
    Ok(())
}

/// The connect request for the owner's own Gmail mailbox `address`, backed
/// by the credential `custody_ref`. Copied from
/// `crates/oneiron/tests/mail_active_sources.rs`.
fn personal_mailbox(address: &str, custody_ref: &str) -> MailSourceConnectRequest {
    MailSourceConnectRequest {
        provider: MailProvider::Google,
        kind: MailSourceKind::PersonalMailbox,
        address: address.to_owned(),
        provider_account: address.to_owned(),
        custody_ref: custody_ref.to_owned(),
        members: Vec::new(),
        for_person: None,
        channel_identity_ref: None,
        copy: None,
        on_provider_delete: None,
        calendar_details: None,
    }
}

/// An owned vault with its host started and the Mail & Calendar pack
/// installed, as `crates/oneiron/tests/mail_active_sources.rs` opens one.
/// Answers the vault and its embedded owner.
fn open_mail_vault() -> Result<(tempfile::TempDir, Vault, EntityId), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = HostSlipIssuer::from_secret(b"list limit rules mail host")?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_host_root_slip(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let _installed =
        install_mail_calendar_pack_embedded(&vault.memory(owner, EdgeActorClass::Human))?;
    Ok((directory, vault, owner))
}

/// A mail wire that records the `limit` its `search_page` is asked and
/// finds nothing, so no message lands and no credential is read.
struct RecordingMailWire {
    seen: std::cell::Cell<u32>,
}

impl MailProviderWire for RecordingMailWire {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::Result<String> {
        Ok("anchor".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> oneiron::Result<MailIdPage> {
        Ok(MailIdPage {
            messages: Vec::new(),
            next_page: None,
        })
    }

    fn headers(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
    ) -> oneiron::Result<Option<MailHeaders>> {
        Ok(None)
    }

    fn full(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
    ) -> oneiron::Result<Option<MailFull>> {
        Ok(None)
    }

    fn history(
        &self,
        _source: &MailSyncSource,
        _anchor: &str,
        _page: Option<&str>,
    ) -> oneiron::Result<MailHistoryRead> {
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes: Vec::new(),
            next_page: None,
            anchor: "anchor".to_owned(),
        }))
    }

    fn search_page(
        &self,
        _source: &MailSyncSource,
        _query: &str,
        limit: u32,
        _page: Option<&str>,
    ) -> oneiron::Result<MailIdPage> {
        self.seen.set(limit);
        Ok(MailIdPage {
            messages: Vec::new(),
            next_page: None,
        })
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> oneiron::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// List 1, rule R: `checkpoint_projection`
/// (`crates/oneiron/src/engine_executor/checkpoint_read.rs:53`) refuses
/// `Some(0)` with "limit must be positive", serves any other ask at most
/// `CHECKPOINT_READ_MAX_LIMIT` rows, and an absent ask with
/// `CHECKPOINT_READ_DEFAULT_LIMIT`. Driven through
/// `checkpoint_as_owner` with an unknown run, which reads as absent.
#[test]
fn checkpoint_read_refuses_zero_and_reads_unknown_runs_as_absent_past_it() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let proof = owner_proof(&vault, owner)?;
    let run_ref = EntityId::now().to_hex();
    let read = |limit: Option<u32>| {
        checkpoint_as_owner(
            &memory,
            &proof,
            &CheckpointReadRequest {
                run_ref: run_ref.clone(),
                from_step: 0,
                limit,
            },
        )
    };
    let error = read(Some(0)).expect_err("a zero checkpoint limit is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    assert!(read(Some(1))?.is_none(), "an unknown run reads as absent");
    assert!(
        read(Some(CHECKPOINT_READ_MAX_LIMIT + 1))?.is_none(),
        "one past the max is accepted"
    );
    assert!(read(None)?.is_none(), "an absent limit is accepted too");
    Ok(())
}

/// List 2, rule R: `page_limit`
/// (`crates/oneiron/src/dreamer_runner/program/read.rs:735`) refuses
/// `Some(0)` with "limit must be positive" before any fixture lookup, and
/// serves any other ask at most `PAGE_LIMIT` (64, also the default).
/// Driven through `turn_program_admission` and `program_run` with unknown
/// ids, which read as absent.
#[test]
fn turn_program_admission_and_run_pages_refuse_zero_before_any_lookup() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let turn_ref = EntityId::now().to_hex();
    let admission = |limit: Option<u32>| {
        turn_program_admission(
            &memory,
            &TurnProgramAdmissionRequest {
                turn_ref: turn_ref.clone(),
                registration: None,
                cursor: None,
                limit,
            },
        )
    };
    let error = admission(Some(0)).expect_err("a zero admission limit is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    assert!(
        admission(Some(1))?.is_none(),
        "an unknown turn has no admissions"
    );
    assert!(
        admission(Some(PROGRAM_PAGE_LIMIT + 1))?.is_none(),
        "one past the max is accepted"
    );
    assert!(
        admission(None)?.is_none(),
        "an absent limit is accepted too"
    );

    let root = EntityId::now().to_hex();
    let run = |limit: Option<u32>| {
        program_run(
            &memory,
            &ProgramRunRequest {
                root: root.clone(),
                cursor: None,
                limit,
            },
        )
    };
    let error = run(Some(0)).expect_err("a zero run limit is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    assert!(run(Some(1))?.is_none(), "an unknown attempt has no program");
    assert!(
        run(Some(PROGRAM_PAGE_LIMIT + 1))?.is_none(),
        "one past the max is accepted"
    );
    assert!(run(None)?.is_none(), "an absent limit is accepted too");
    Ok(())
}

/// List 3, rule R: the program checkpoint page
/// (`crates/oneiron/src/dreamer_runner/program/read/checkpoint.rs:75`)
/// shares list 2's `page_limit`, so it refuses `Some(0)` with "limit must
/// be positive" before any fixture lookup. Driven through
/// `program_checkpoint` with an unknown attempt, which reads as absent.
#[test]
fn program_checkpoint_page_refuses_zero_before_any_lookup() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let root = EntityId::now().to_hex();
    let checkpoint = |limit: Option<u32>| {
        program_checkpoint(
            &memory,
            &ProgramCheckpointRequest {
                root: root.clone(),
                cursor: None,
                limit,
            },
        )
    };
    let error = checkpoint(Some(0)).expect_err("a zero checkpoint limit is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    assert!(
        checkpoint(Some(1))?.is_none(),
        "an unknown attempt has no checkpoint"
    );
    assert!(
        checkpoint(Some(PROGRAM_PAGE_LIMIT + 1))?.is_none(),
        "one past the max is accepted"
    );
    assert!(
        checkpoint(None)?.is_none(),
        "an absent limit is accepted too"
    );
    Ok(())
}

/// List 4, rule R: `step_page_limit`
/// (`crates/oneiron/src/memory/code_run_doors/mod.rs:249`) refuses
/// `Some(0)` with "limit must be positive" before any fixture lookup, and
/// serves any other ask at most `CODE_RUN_CORRECTIONS_MAX_STEPS` steps.
/// Driven through `code_run_corrections_as` (an unknown run holds an empty
/// page) and `code_run_step_evidence_as` (an unknown run reads as absent).
#[test]
fn code_run_correction_and_step_evidence_pages_refuse_zero() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let proof = owner_proof(&vault, owner)?;
    let run_ref = EntityId::now().to_hex();
    let corrections = |limit: Option<u32>| {
        memory.code_run_corrections_as(
            &proof,
            CodeRunCorrectionsRequest {
                run_ref: run_ref.clone(),
                after_step: None,
                limit,
            },
        )
    };
    let error = corrections(Some(0)).expect_err("a zero corrections limit is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    assert!(
        corrections(Some(1))?.records.is_empty(),
        "an unknown run holds no records"
    );
    assert!(
        corrections(Some(CODE_RUN_CORRECTIONS_MAX_STEPS + 1))?
            .records
            .is_empty(),
        "one past the max is accepted"
    );
    assert!(
        corrections(None)?.records.is_empty(),
        "an absent limit is accepted too"
    );

    let evidence = |limit: Option<u32>| {
        memory.code_run_step_evidence_as(
            &proof,
            CodeRunStepEvidenceRequest {
                run_ref: run_ref.clone(),
                after_step: None,
                limit,
            },
        )
    };
    let error = evidence(Some(0)).expect_err("a zero evidence limit is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "limit must be positive");
    assert!(
        evidence(Some(1))?.is_none(),
        "an unknown run holds no replay"
    );
    assert!(
        evidence(Some(CODE_RUN_CORRECTIONS_MAX_STEPS + 1))?.is_none(),
        "one past the max is accepted"
    );
    assert!(evidence(None)?.is_none(), "an absent limit is accepted too");
    Ok(())
}

/// List 5, rule R: `Vault::feed_read`
/// (`crates/oneiron/src/feeds/mod.rs:528`) refuses `Some(0)` with "a feed
/// read's limit is at least 1", serves `FEED_READ_DEFAULT_LIMIT` entries
/// per source when the request names no limit, and at most
/// `FEED_READ_MAX_LIMIT`. Driven on the Changes source with 257 writes
/// (plus the vault's own) behind a subscription from the beginning.
#[test]
fn feed_read_refuses_zero_and_cuts_each_source_at_its_maximum() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let key = owner_key(&vault)?;
    let subscription = vault
        .feed_subscribe(
            &vault.scoped_read(key.clone()),
            &changes_from(FeedStart::Beginning),
        )?
        .subscription;
    for learned_at in 1..=257 {
        put_person(&vault, learned_at)?;
    }
    let page = read_feed_page(&vault, &key, subscription, None)?;
    assert_eq!(
        page.entries.len(),
        FEED_READ_DEFAULT_LIMIT,
        "an absent limit serves the default"
    );
    assert!(page.more, "the writes fill a default page");
    let page = read_feed_page(&vault, &key, subscription, Some(1))?;
    assert_eq!(page.entries.len(), 1, "one asked, one served");
    let page = read_feed_page(&vault, &key, subscription, Some(FEED_READ_MAX_LIMIT + 1))?;
    assert_eq!(
        page.entries.len(),
        FEED_READ_MAX_LIMIT,
        "one past the max serves the max"
    );
    assert!(page.more, "the writes fill a maximum page");
    match vault.feed_read(
        &vault.scoped_read(key),
        &FeedReadRequest {
            subscription,
            limit: Some(0),
        },
    ) {
        Err(oneiron::Error::InvalidConfig(text)) => {
            assert_eq!(text, "a feed read's limit is at least 1");
        }
        Err(other) => panic!("a zero feed limit is refused as invalid config, not {other:?}"),
        Ok(_) => panic!("a zero feed limit is refused"),
    }
    Ok(())
}

/// List 6, rule R: the record-links turn page
/// (`crates/oneiron/src/lens/record_ref.rs:314`) refuses `Some(0)` with "a
/// page of a turn holds at least one message" before any fixture lookup,
/// and serves at most `RECORD_LINKS_TURN_PAGE_MAX` messages (also the
/// default). Driven through `Memory::record_links` with an unknown turn
/// (not found past the zero gate) and a witnessed 33-message turn.
#[test]
fn record_links_turn_page_refuses_zero_and_cuts_at_its_maximum() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let unknown = EntityId::now().to_hex();
    let links = |turn_ref: &str, after: Option<String>, limit: Option<u32>| {
        memory.record_links(&RecordLinksRequest {
            text: None,
            texts: None,
            turn_ref: Some(turn_ref.to_owned()),
            after,
            limit,
            filter: None,
        })
    };
    let error = links(&unknown, None, Some(0)).expect_err("a zero turn page is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "a page of a turn holds at least one message");
    let error = links(&unknown, None, Some(1)).expect_err("an unknown turn is not found");
    assert_eq!(error.code, MEMORY_CODE_NOT_FOUND);

    let mut messages = Vec::new();
    for order in 0..33_u32 {
        messages.push(WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: format!("message {order}"),
            parts: None,
            metadata: None,
            is_visible: true,
            order,
            quote: None,
        });
    }
    let turn = memory
        .witness(&WitnessTurn {
            conversation_ref: EntityId::now().to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages,
            occurred_at: 900,
            assertions: WitnessAssertions::default(),
        })?
        .turn_id
        .to_hex();
    let page = links(&turn, None, Some(1))?;
    assert_eq!(page.texts.len(), 1, "one asked, one served");
    let page = links(&turn, None, Some(RECORD_LINKS_TURN_PAGE_MAX as u32 + 1))?;
    assert_eq!(
        page.texts.len(),
        RECORD_LINKS_TURN_PAGE_MAX,
        "one past the max serves the max"
    );
    let after = page
        .next_after
        .clone()
        .expect("one message is left past a full page");
    let page = links(&turn, None, None)?;
    assert_eq!(
        page.texts.len(),
        RECORD_LINKS_TURN_PAGE_MAX,
        "an absent limit serves the default page"
    );
    assert!(
        page.next_after.is_some(),
        "one message is left past the default page"
    );
    let rest = links(&turn, Some(after), None)?;
    assert_eq!(rest.texts.len(), 1, "the cursor reads the one message left");
    assert_eq!(rest.next_after, None, "nothing is left past it");
    Ok(())
}

/// List 7, rule O: `mail_search_step`
/// (`crates/oneiron/src/mail_pack/search.rs:121`) asks its wire for
/// `limit.clamp(1, MAX_SEARCH_HITS)`, so a zero ask is served one row.
/// Driven with a wire that records the limit it was asked and finds
/// nothing, against a connected mailbox the owner reads.
#[test]
fn mail_search_step_serves_zero_as_one_and_caps_past_its_maximum() -> TestResult {
    let (_dir, vault, owner) = open_mail_vault()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    register_mail_credential(&vault, "test-mail-cred")?;
    let receipt =
        memory.mail_sources_connect(&personal_mailbox("mailbox@test.example", "test-mail-cred"))?;
    let source = EntityId::from_hex(&receipt.source.source_ref)?;
    let proof = owner_proof(&vault, owner)?;
    let wire = RecordingMailWire {
        seen: std::cell::Cell::new(u32::MAX),
    };
    let search = |limit: u32| vault.mail_search_step(&proof, source, &wire, "hello", None, limit);
    let report = search(0)?;
    assert_eq!(wire.seen.get(), 1, "a zero ask is served one row");
    assert_eq!(report.found, 0);
    let report = search(1)?;
    assert_eq!(wire.seen.get(), 1);
    assert_eq!(report.found, 0);
    let report = search(MAIL_DEFAULT_SEARCH_HITS)?;
    assert_eq!(wire.seen.get(), MAIL_DEFAULT_SEARCH_HITS);
    assert_eq!(report.found, 0);
    let report = search(MAIL_MAX_SEARCH_HITS + 1)?;
    assert_eq!(
        wire.seen.get(),
        MAIL_MAX_SEARCH_HITS,
        "one past the max asks the max"
    );
    assert_eq!(report.found, 0);
    Ok(())
}

/// List 8, rule O: `grants_asked`
/// (`crates/oneiron/src/memory/people_verbs/grants.rs:82`) serves
/// `limit.clamp(1, GRANTS_ASKED_PAGE_MAX)`, so a zero ask is served one
/// row, and an absent ask `GRANTS_ASKED_PAGE_DEFAULT`. Driven through
/// `Memory::grants_asked` with 101 pending requests addressed to the
/// owner.
#[test]
fn grants_asked_serves_zero_as_one_and_cuts_at_its_maximum() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let asker = EntityId::now();
    let space = EntityId::now();
    let created_at = vault.now_recorded_at();
    for _ in 0..GRANTS_ASKED_PAGE_MAX + 1 {
        vault.request_access_to(
            EntityId::now(),
            AccessGrant {
                authority_scope: oneiron_authority::federation::scope_codec::read_preset(),
                principal_ref: asker,
                scope: AccessGrantScope::Messages { space_ref: space },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at,
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
            Some(owner),
        )?;
    }
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let asked = |limit: Option<u32>| memory.grants_asked(&GrantAskedRequest { after: None, limit });
    let zero = asked(Some(0))?;
    assert_eq!(zero.requests.len(), 1, "a zero ask is served one row");
    assert!(zero.next_after.is_some(), "100 requests are left past it");
    let one = asked(Some(1))?;
    assert_eq!(one.requests.len(), 1);
    assert_eq!(
        zero.requests[0].request, one.requests[0].request,
        "zero serves the same row as one"
    );
    assert_eq!(zero.next_after, one.next_after);
    let default = asked(None)?;
    assert_eq!(
        default.requests.len(),
        GRANTS_ASKED_PAGE_DEFAULT as usize,
        "an absent limit serves the default"
    );
    assert!(default.next_after.is_some(), "51 requests are left past it");
    let capped = asked(Some(GRANTS_ASKED_PAGE_MAX + 1))?;
    assert_eq!(
        capped.requests.len(),
        GRANTS_ASKED_PAGE_MAX as usize,
        "one past the max serves the max"
    );
    assert!(capped.next_after.is_some(), "one request is left past it");
    Ok(())
}

/// List 9, rule O: `authority_audit`
/// (`crates/oneiron/src/receipt/authority_audit.rs:266`) serves
/// `limit.clamp(1, AUTHORITY_AUDIT_MAX_LIMIT)`, so a zero ask is served
/// one row. Driven through `Vault::authority_audit` on a fresh vault,
/// where a zero ask answers exactly what a one ask answers.
#[test]
fn authority_audit_serves_zero_as_one_row() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(&vault, owner)?;
    let audit = |limit: Option<usize>| {
        vault.authority_audit(
            &proof,
            &AuthorityAuditQuery {
                limit,
                ..AuthorityAuditQuery::default()
            },
        )
    };
    let zero = audit(Some(0))?;
    let one = audit(Some(1))?;
    assert_eq!(
        zero.rows, one.rows,
        "a zero ask serves the same rows as one"
    );
    assert!(zero.rows.len() <= 1, "a zero ask serves at most one row");
    let _ = audit(Some(AUTHORITY_AUDIT_MAX_LIMIT + 1))?;
    let _ = audit(None)?;
    Ok(())
}

/// List 10, rule R: `rooms_reply_strips`
/// (`crates/oneiron/src/conversation_dag/quote_strips.rs:417`) refuses
/// `Some(0)` with "reply strip limit must be positive" before any
/// fixture lookup, and serves any other ask at most `PAGE_LIMIT` (256)
/// strips. Driven with unknown room and thread ids, which read as not
/// found past the zero gate.
#[test]
fn reply_strips_refuse_zero_before_any_lookup() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let room_ref = EntityId::now().to_hex();
    let thread_ref = EntityId::now().to_hex();
    let strips = |limit: Option<usize>| {
        memory.rooms_reply_strips(&ReplyStripsRequest {
            room_ref: room_ref.clone(),
            thread_ref: thread_ref.clone(),
            after: None,
            limit,
        })
    };
    let error = strips(Some(0)).expect_err("a zero strip limit is refused");
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST);
    assert_eq!(error.message, "reply strip limit must be positive");
    for limit in [Some(1), Some(QUOTE_STRIP_PAGE_LIMIT + 1), None] {
        match strips(limit) {
            Err(error) => assert_eq!(
                error.code, MEMORY_CODE_NOT_FOUND,
                "limit {limit:?} is accepted past the zero gate"
            ),
            Ok(_) => panic!("an unknown thread is not found, at limit {limit:?}"),
        }
    }
    Ok(())
}

/// List 11, rule O: `dreamer_wake_observation`
/// (`crates/oneiron/src/dreamer_wake/observation/read.rs:50`) serves
/// `limit.clamp(1, WAKE_OBSERVATION_PAGE_MAX)`, so a zero ask is served
/// one row, and an absent ask `WAKE_OBSERVATION_PAGE_DEFAULT`. Driven
/// through `Vault::dreamer_wake_observation` with an unknown attempt,
/// which holds nothing at any limit.
#[test]
fn wake_observation_serves_zero_as_one_and_accepts_past_its_maximum() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let attempt = AttemptId::now();
    let observe = |limit: Option<usize>| {
        vault.dreamer_wake_observation(&WakeObservationRequest {
            selector: WakeObservationSelector::Attempt {
                attempt,
                wake: None,
            },
            limit,
            cursor: None,
        })
    };
    assert!(observe(Some(0))?.is_none(), "a zero ask is accepted");
    assert!(
        observe(Some(1))?.is_none(),
        "an unknown attempt holds nothing"
    );
    assert!(
        observe(Some(WAKE_OBSERVATION_PAGE_MAX + 1))?.is_none(),
        "one past the max is accepted"
    );
    assert!(observe(None)?.is_none(), "an absent limit is accepted too");
    Ok(())
}

/// List 12, rule O: the strength observations page
/// (`crates/oneiron/src/snapshot_read/strength_observations.rs:94`)
/// serves `limit.unwrap_or(page_rows).min(page_rows).max(1)`, so a zero
/// ask is served one row. Driven through
/// `strength_observations_page` on a fresh owned vault as its embedded
/// owner, where no claim is observed at any limit.
#[test]
fn strength_observations_serve_zero_as_one_and_accept_past_the_snapshot_bound() -> TestResult {
    let (_dir, vault) = open_owned_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let page = |limit: Option<u32>| {
        strength_observations_page(
            &memory,
            &StrengthObservationsPageRequest {
                cursor: None,
                limit,
            },
        )
    };
    assert!(
        page(Some(0))?.value.claims.is_empty(),
        "a zero ask is accepted"
    );
    assert!(
        page(Some(1))?.value.claims.is_empty(),
        "a fresh vault holds no observations"
    );
    assert!(
        page(Some(SNAPSHOT_PAGE_ROWS_DEFAULT + 1))?
            .value
            .claims
            .is_empty(),
        "one past the bound is accepted"
    );
    assert!(
        page(None)?.value.claims.is_empty(),
        "an absent limit is accepted too"
    );
    Ok(())
}
