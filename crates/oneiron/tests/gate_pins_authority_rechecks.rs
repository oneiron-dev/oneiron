//! OPUS-T0-F gate pins, PR 1 (Engine task 12 Nov 19:38): green pins for ten
//! write gates of OPUS-GATECENSUS's DEEP list (census/GATE-CENSUS.md, class
//! GAP-PASSES: real callers pass the gate today, and no running test drove
//! it from a door). Each test drives the door a real caller uses, with that
//! caller's input, through the gate, and reads the write back. A pin that
//! goes red is a live refusal of a real caller (GAP-BROKEN).
//!
//! Each test name starts with its census id, so `-- g11_` runs one gate's
//! pin alone.
//!
//! - G8 `CalendarConnectorOperation::revalidate_in_txn`: a calendar poll
//!   rechecks that its seat is registered and not killed.
//! - G9 `ChannelIdentitySelectionWriter::revalidate_in_txn`: an agent's
//!   channel selection rule write rechecks the agent.
//! - G11 `VoiceBankActor::revalidate_in_txn` (Creator arm): a designed voice
//!   pack write rechecks its agent creator.
//! - G18 `Memory::embedded_owner`: an owner-only embedded verb row.
//! - G32 `resident_of`: a resident skill fork carries one valid
//!   `residentActor`.
//! - G36 `spend_approve_once_in_txn`: the owner's hub configure spends its
//!   approve-once marker once.
//! - G41 `verify_deletion_authority_in_txn` and G117 `reject_fact_delete`:
//!   the owner's `vault.delete` of a NOTE.
//! - G83 `Memory::for_room_turn`: a room turn binds the room it writes into.
//! - G99 `check_restore_owner_in_txn`: the owner restores a retired shipped
//!   skill.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test gate_pins_authority_rechecks`.
#![cfg(oneiron_test_support)]

use oneiron::calendar::caldav::CALDAV_PROVIDER_KEY;
use oneiron::calendar::connectors::door::{
    CalendarConnectorConfigureRequest, CalendarConnectorOperation, configure,
};
use oneiron::calendar::connectors::{
    CALDAV_SYNC_ATTEMPT_KIND, CalendarConnectorError, CalendarConnectorSeatConfig,
    CalendarConnectorSyncPayload, CalendarRemoteTransport, CalendarSyncOutcome, RemoteSyncBatch,
    RemoteWriteReceipt, RemoteWriteRequest, run_calendar_connector_sync,
};
use oneiron::channel_identity_selection::{
    ChannelIdentityFace, RelationshipContext, SelectionRuleScope,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::core_write::ConversationCreateInput;
use oneiron::memory::channel_doors::{
    ChannelSelectionPatchInput, ChannelSelectionRuleInput, ChannelSelectionUpdateRequest,
};
use oneiron::memory::{SafeDeleteReason, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::skill_hub::{HubSyncPolicy, SkillHubKind, SkillHubRecord, SkillHubTrustTier};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::skill_hub_restore::restore_bootstrap_skills;
use oneiron::verbs::{
    HubSkillRequest, SkillHubPutRequest, VoiceBankClipInput, VoiceBankPackPutRequest,
    put_voice_bank_pack, skill_archive_as_owner, skill_hub_put_as_owner,
};
use oneiron::voice_identity::ref_bank::{VoiceRefOrigin, VoiceRefSubjectKind};
use oneiron::{AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed, so a red
/// pin names its door and the refusal's own words.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// A vault and its embedded owner. The vault closes before its directory.
struct Fixture {
    vault: Vault,
    owner: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    /// A seeded vault, opened as most hosts and tests open one.
    fn open() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        Ok(Self {
            vault,
            owner,
            _dir: dir,
        })
    }

    /// A seeded vault this process owns (the writer lease), as an embedded
    /// host opens it at each start, so the owner's handle carries the owner's
    /// proof.
    fn open_owned() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault =
            Vault::open_owned(dir.path(), VaultConfig::default()).map_err(at("open owned"))?;
        let _issuer = oneiron::test_support::provision_engine_machines(&vault);
        let owner = vault
            .ensure_embedded_owner_actor()
            .map_err(at("embedded owner"))?;
        Ok(Self {
            vault,
            owner,
            _dir: dir,
        })
    }

    /// The owner proof an owner door builds from the owner's credential.
    fn owner_proof(&self) -> TestResult<AuthenticatedOwner> {
        Ok(self
            .vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .map_err(at("owner proof"))?)
    }
}

/// A CalDAV remote whose collection has no change since the cursor. A poll
/// with nothing to apply writes nothing remote.
struct UnchangedCalDav;

impl CalendarRemoteTransport for UnchangedCalDav {
    fn provider_key(&self) -> &'static str {
        CALDAV_PROVIDER_KEY
    }

    fn pull(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _cursor: Option<&str>,
    ) -> Result<RemoteSyncBatch, CalendarConnectorError> {
        Ok(RemoteSyncBatch {
            next_cursor: Some("cursor-1".to_owned()),
            changes: Vec::new(),
        })
    }

    fn upsert(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _request: &RemoteWriteRequest,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        unreachable!("a poll with no change writes nothing remote")
    }

    fn delete(
        &self,
        _secret_ref: &str,
        _calendar_ref: &str,
        _href: &str,
        _expected_etag: Option<&str>,
        _uid: &str,
        _sequence: u32,
    ) -> Result<RemoteWriteReceipt, CalendarConnectorError> {
        unreachable!("a poll with no change deletes nothing remote")
    }
}

fn caldav_config() -> CalendarConnectorSeatConfig {
    CalendarConnectorSeatConfig {
        seat_ref: "seat:caldav:work".to_owned(),
        secret_ref: "caldav:work".to_owned(),
        system: "caldav-work".to_owned(),
        calendar_ref: "work".to_owned(),
        cadence_jitter_min_seconds: 300,
        cadence_jitter_max_seconds: 900,
    }
}

/// The CalDAV polls on the attempt queue, as their payloads.
fn caldav_polls(vault: &Vault) -> TestResult<Vec<CalendarConnectorSyncPayload>> {
    let mut polls = Vec::new();
    for record in AttemptQueue::new(vault)
        .list()
        .map_err(at("list attempts"))?
    {
        if record.kind == CALDAV_SYNC_ATTEMPT_KIND {
            polls.push(serde_json::from_slice(&record.payload)?);
        }
    }
    Ok(polls)
}

/// G8: the owner registers a CalDAV seat, and the feed poller runs it as
/// `calendar_host/feed_poll.rs` does: an operation over the registered row,
/// then one sync. The sync rechecks the seat in its own txn (seat live, not
/// killed), pulls, and queues the next poll from the returned cursor.
#[test]
fn g8_a_live_calendar_seat_poll_queues_its_next_poll() -> TestResult {
    let fixture = Fixture::open()?;
    let _issuer = oneiron::test_support::provision_engine_machines(&fixture.vault);
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let row = configure(
        &owner,
        &fixture.owner_proof()?,
        &CalendarConnectorConfigureRequest {
            config: caldav_config(),
            endpoint: "https://calendar.example.invalid/".to_owned(),
        },
    )
    .map_err(at("configure the CalDAV seat"))?;
    let operation = CalendarConnectorOperation::new(&fixture.vault, fixture.owner_proof()?, row)
        .map_err(at("the seat's operation"))?;
    let before = caldav_polls(&fixture.vault)?.len();
    let now = 1_780_000_000;
    let outcome = run_calendar_connector_sync(&fixture.vault, &operation, &UnchangedCalDav, now, 7)
        .map_err(at("the poll"))?;
    let (next_cursor, next_not_before) = match outcome {
        CalendarSyncOutcome::Reenqueued {
            next_cursor,
            next_not_before,
            ..
        } => (next_cursor, next_not_before),
        other => return Err(format!("the poll did not queue its next run: {other:?}").into()),
    };
    assert_eq!(next_cursor.as_deref(), Some("cursor-1"));
    assert!((now + 300..=now + 900).contains(&next_not_before));
    let polls = caldav_polls(&fixture.vault)?;
    assert_eq!(polls.len(), before + 1, "the poll queued one next poll");
    assert!(
        polls.contains(&CalendarConnectorSyncPayload {
            config: caldav_config(),
            cursor: Some("cursor-1".to_owned()),
            not_before: next_not_before,
        }),
        "the queued poll resumes from the pulled cursor: {polls:?}"
    );
    Ok(())
}

/// G9: an agent adds an amendable channel selection rule for a space through
/// its own handle, as the facade's agent caller does
/// (`channel_selection_update_as(None, ..)`). The writer recheck admits the
/// live agent, and the rule set gains the rule at the next revision.
#[test]
fn g9_an_agent_channel_selection_rule_lands() -> TestResult {
    let fixture = Fixture::open()?;
    let agent = define_agent(&fixture.vault).map_err(at("define the agent"))?;
    let revision = fixture
        .vault
        .stored_channel_identity_selection_rules()
        .map_err(at("rules before"))?
        .map_or(0, |rules| rules.revision);
    fixture
        .vault
        .memory(agent, EdgeActorClass::Agent)
        .channel_selection_update(ChannelSelectionUpdateRequest {
            expected_revision: revision,
            patch: ChannelSelectionPatchInput::Upsert {
                rule: ChannelSelectionRuleInput {
                    rule_id: "pin.agent.rule".to_owned(),
                    relationship: RelationshipContext::GroupSpace,
                    scope: SelectionRuleScope::Space {
                        space_ref: "space.alpha".to_owned(),
                    },
                    face: ChannelIdentityFace::AgentNamedAddress,
                    pinned_identity_ref: None,
                    priority: 10,
                    enabled: true,
                    agent_amendable: true,
                },
            },
        })
        .map_err(at("the agent's rule write"))?;
    let rules = fixture
        .vault
        .stored_channel_identity_selection_rules()
        .map_err(at("rules after"))?
        .ok_or("no stored rule set after the write")?;
    assert_eq!(rules.revision, revision + 1);
    let rule = rules
        .rows
        .iter()
        .find(|rule| rule.rule_id == "pin.agent.rule")
        .ok_or("the agent's rule is not stored")?;
    assert_eq!(rule.priority, 10);
    assert!(rule.enabled && rule.agent_amendable);
    Ok(())
}

/// G11: an agent banks a designed voice through the voice bank door. The
/// handle is not the owner's, so the door acts as the voice's creator, and
/// the bank's write txn rechecks that creator.
#[test]
fn g11_an_agent_banks_a_designed_voice_as_its_creator() -> TestResult {
    let fixture = Fixture::open()?;
    let agent = define_agent(&fixture.vault).map_err(at("define the agent"))?;
    let receipt = put_voice_bank_pack(
        &fixture.vault.memory(agent, EdgeActorClass::Agent),
        VoiceBankPackPutRequest {
            voice_id: "designed-voice-1".to_owned(),
            pack_id: "designed-pack-1".to_owned(),
            origin: VoiceRefOrigin::Designed {
                vendor: "design-tool".to_owned(),
            },
            clips: vec![VoiceBankClipInput {
                register: "neutral".to_owned(),
                media_type: "audio/wav".to_owned(),
                // base64 of the bytes [1, 2, 3]
                audio: "AQID".to_owned(),
                transcript: "reference".to_owned(),
            }],
        },
    )
    .map_err(at("the creator's pack put"))?;
    assert_eq!(receipt.voice_id, "designed-voice-1");
    let voice = fixture
        .vault
        .voice_identity("designed-voice-1")
        .map_err(at("voice read"))?
        .ok_or("the banked voice is not stored")?;
    assert_eq!(voice.owner, agent);
    assert_eq!(voice.pack_ids, vec!["designed-pack-1".to_owned()]);
    assert!(matches!(voice.subject_kind, VoiceRefSubjectKind::Designed));
    Ok(())
}

/// G18: the owner sets an owner-only setting through its embedded SDK verb
/// row; the row's call takes the embedded owner door first.
#[test]
fn g18_the_embedded_owner_sets_an_owner_only_setting() -> TestResult {
    let fixture = Fixture::open_owned()?;
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let set = invoke(
        &owner,
        "vault.settings.non_base_world_claim_fraction.set",
        json!({"fraction": 0.25}),
    )
    .map_err(at("the owner's set"))?;
    assert_eq!(set, json!({"fraction": 0.25}));
    let read = invoke(
        &owner,
        "vault.settings.non_base_world_claim_fraction",
        json!({}),
    )
    .map_err(at("the setting read"))?;
    assert_eq!(read, json!({"fraction": 0.25}));
    Ok(())
}

/// G32: a resident agent forks a stored skill through the resident fork
/// door, which stamps one `residentActor` on the fork; every encode of the
/// fork reads that stamp back through `resident_of`.
#[test]
fn g32_a_resident_skill_fork_lands_with_its_resident() -> TestResult {
    let fixture = Fixture::open()?;
    let agent = define_agent(&fixture.vault).map_err(at("define the agent"))?;
    let parent = EntityId::now();
    let record = SkillRecord::new(
        "pin.resident.parent",
        "A parent skill for the resident fork pin",
        "1.0.0",
        oneiron::ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        oneiron::ClaimSource::UserStated,
        0.9,
        false,
        true,
        Vec::new(),
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("gate-pin-fixture"),
        )]),
    );
    fixture
        .vault
        .put_skill_record(&parent, &record, TimeRange { start: 10, end: 10 }, 10)
        .map_err(at("put the parent skill"))?;
    let fork = EntityId::now();
    fixture
        .vault
        .fork_skill_for_resident(
            &agent,
            &parent,
            &fork,
            "pin.resident.fork",
            TimeRange { start: 20, end: 20 },
            20,
        )
        .map_err(at("the resident fork"))?;
    let stored = fixture
        .vault
        .get_skill_record(&fork)
        .map_err(at("fork read"))?
        .ok_or("the fork is not stored")?;
    assert_eq!(stored.skill_id, "pin.resident.fork");
    assert_eq!(stored.forked_from, Some(parent));
    let resident = stored
        .provenance
        .as_map()
        .into_iter()
        .flatten()
        .find(|(key, _)| key.as_str() == Some("residentActor"))
        .and_then(|(_, value)| value.as_str())
        .ok_or("the fork carries no residentActor")?;
    assert_eq!(resident, agent.to_hex());
    Ok(())
}

/// G36: the owner configures a skill hub through the hub door the facade
/// calls. The door mints an approve-once authorization, applies the hub row
/// and spends the authorization in one txn.
#[test]
fn g36_the_owner_configures_a_skill_hub_spending_its_approve_once() -> TestResult {
    let fixture = Fixture::open()?;
    let hub = EntityId::now();
    let input = SkillHubPutRequest {
        hub,
        kind: SkillHubKind::HttpIndex,
        endpoint: "https://example.invalid/index.json".to_owned(),
        trust_tier: SkillHubTrustTier::Community,
        sync_policy: HubSyncPolicy::ContentHashFrozen,
    };
    skill_hub_put_as_owner(&fixture.vault, &fixture.owner_proof()?, &input)
        .map_err(at("the owner's hub put"))?;
    let expected = SkillHubRecord::new(
        input.kind,
        &input.endpoint,
        input.trust_tier,
        input.sync_policy,
    )
    .map_err(at("the expected record"))?;
    let stored = fixture
        .vault
        .skill_hub_record(&hub)
        .map_err(at("hub read"))?;
    assert_eq!(format!("{stored:?}"), format!("{expected:?}"));
    Ok(())
}

fn person_body(name: &str) -> TestResult<Vec<u8>> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )?;
    Ok(body)
}

/// G41 and G117: the owner deletes a NOTE through `vault.delete`'s call,
/// `Memory::safe_delete`. The deletion gate checks the owner's authority
/// (G41), and the delete rail refuses only a TASK authority fact (G117).
#[test]
fn g41_g117_the_owner_deletes_a_note() -> TestResult {
    let fixture = Fixture::open()?;
    // Every delete loads this install's signing keys before its first
    // transaction, from the keystore a host installs after each open.
    fixture.vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let subject = EntityId::now();
    fixture
        .vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: 1_780_000_000,
                end: 1_780_000_000,
            },
            1_780_000_000,
            &person_body("delete pin subject")?,
        )
        .map_err(at("put the subject"))?;
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let note = owner
        .author_take(TakeTarget::Subject(subject), "a take the owner deletes")
        .map_err(at("author the NOTE"))?
        .id_hex;
    assert!(
        owner
            .get_entity(&note)
            .map_err(at("read before"))?
            .value
            .is_some()
    );
    let receipt = owner
        .safe_delete(&note, SafeDeleteReason::UserDelete)
        .map_err(at("the owner's delete"))?;
    assert!(receipt.existed);
    assert!(
        fixture
            .vault
            .is_deleted_shell(&EntityId::from_hex(&note)?)
            .map_err(at("shell read"))?,
        "the NOTE is a deleted shell"
    );
    assert!(
        owner
            .get_entity(&note)
            .map_err(at("read after"))?
            .value
            .is_none()
    );
    Ok(())
}

/// G83: the owner speaks in a room through a room turn handle, as the facade
/// binds every room call (`memory.for_room_turn(room)`), and reads the
/// message back through the same handle.
#[test]
fn g83_a_room_turn_writes_into_its_bound_room() -> TestResult {
    let fixture = Fixture::open_owned()?;
    let owner = fixture.vault.memory(fixture.owner, EdgeActorClass::Human);
    let room = EntityId::from_hex(
        &owner
            .conversations_create(&ConversationCreateInput {
                id: None,
                occurred_start: None,
                occurred_end: None,
                learned_at: None,
                body: json!({
                    "v": 1,
                    "kind": "group",
                    "member_ids": [fixture.owner.to_hex()],
                    "title": "room turn gate pin",
                }),
                text: None,
            })
            .map_err(at("create the room"))?
            .id,
    )?;
    let turn = EntityId::now();
    let message = EntityId::now();
    let handle = owner
        .for_room_turn(room)
        .map_err(at("bind the room turn"))?;
    let receipt = handle
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "room-gate-pin".into(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: fixture.vault.now_recorded_at(),
            assertions: Default::default(),
        })
        .map_err(at("speak in the room"))?;
    assert_eq!(receipt.turn_id, turn);
    let stored = handle
        .get_entity(&message.to_hex())
        .map_err(at("read the message"))?
        .value
        .ok_or("the message is not readable in its room")?;
    assert_eq!(stored.kind, "MESSAGE");
    assert!(format!("{stored:?}").contains("room-gate-pin"));
    Ok(())
}

/// The first Active shipped (bootstrap, learned_at 0) skill in id order.
fn first_active_bootstrap_skill(vault: &Vault) -> TestResult<(EntityId, SkillRecord)> {
    let export = vault.export_whole_vault(true).map_err(at("export"))?;
    let document = vault
        .read_whole_vault_archive(export.bytes())
        .map_err(at("read export"))?;
    let mut active = Vec::new();
    for bundle in &document.skills {
        if bundle.entity.learned_at != 0 {
            continue;
        }
        let id = EntityId::from_hex(&bundle.entity.id)?;
        let record = vault
            .get_skill_record(&id)
            .map_err(at("skill read"))?
            .ok_or("a listed skill has no record")?;
        if record.lifecycle_status == SkillLifecycle::Active {
            active.push((id, record));
        }
    }
    active.sort_by_key(|(id, _)| id.to_hex());
    active
        .into_iter()
        .next()
        .ok_or_else(|| "no Active shipped skill".into())
}

/// G99: the owner archives a shipped skill, then restores the shipped
/// defaults with the inputs the owner route passes (its proof, now, now).
/// The restore checks the owner first, then imports a fresh Candidate of the
/// retired skill from the bytes embedded in the engine. The test door runs
/// the restore's shipped-default step, which the public
/// `Vault::restore_default_skills` runs after fetching the pinned library.
#[test]
fn g99_the_owner_restores_a_retired_shipped_skill() -> TestResult {
    let fixture = Fixture::open()?;
    let proof = fixture.owner_proof()?;
    let (shipped, record) = first_active_bootstrap_skill(&fixture.vault)?;
    skill_archive_as_owner(&fixture.vault, &proof, &HubSkillRequest { entity: shipped })
        .map_err(at("the owner archives the shipped skill"))?;
    let at_now = fixture.vault.now_recorded_at();
    let restored = restore_bootstrap_skills(
        &fixture.vault,
        &proof,
        TimeRange {
            start: at_now,
            end: at_now,
        },
        at_now,
    )
    .map_err(at("the owner's restore"))?;
    let mut fresh = Vec::new();
    for id in &restored {
        let stored = fixture
            .vault
            .get_skill_record(id)
            .map_err(at("restored read"))?
            .ok_or("a restored id has no record")?;
        if stored.skill_id == record.skill_id {
            fresh.push((*id, stored));
        }
    }
    let [(id, stored)] = fresh.as_slice() else {
        return Err(format!(
            "expected one fresh {} among {restored:?}, found {}",
            record.skill_id,
            fresh.len()
        )
        .into());
    };
    assert_ne!(*id, shipped);
    assert_eq!(stored.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(stored.content_hash, record.content_hash);
    let again = restore_bootstrap_skills(
        &fixture.vault,
        &proof,
        TimeRange {
            start: at_now,
            end: at_now,
        },
        at_now,
    )
    .map_err(at("the owner's second restore"))?;
    assert!(
        again.is_empty(),
        "a second restore imports nothing: {again:?}"
    );
    Ok(())
}
