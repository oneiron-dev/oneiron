//! FIX SLIP-DOOR-DERIVED-SUMMARY-FENCE: a row carrying other rows' words
//! reads and exports only while the same slip door admits every word source.
//! The narrow slip refuses a live other-world claim but admits each base-world
//! twin; the top slip admits all nine derived roots.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test slip_door_word_sources`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use oneiron::claim::{ClaimSource, base_world_id, default_project_id};
use oneiron::conversation_dag::{ScopePath, ScopeSelector};
use oneiron::core_write::{ConversationCreateInput, DagRecordAppendInput};
use oneiron::federation::record_scope::{ScopeView, ScopedRecord};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::llm::DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES;
use oneiron::psych_profile::{
    PsychProfile, PsychProfileConfidence, PsychProfileSource, PsychProfileSourceWords,
};
use oneiron::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_ASSET, ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE, ENTITY_TYPE_NOTIFICATION,
    ENTITY_TYPE_PERSON, ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TURN,
    ENTITY_TYPE_WORLD,
};
use oneiron::store::revision_ref::RevisionRef;
use oneiron::test_doors::compaction_step_read::file_compaction_step;
use oneiron::test_doors::disclosure_word_sources::register_editor_source;
use oneiron::test_doors::scope_summary::mint_scope_summary;
use oneiron::test_doors::slip_door_word_sources::{
    file_compaction_intent, file_epoch_summary_from, file_finding_notice,
};
use oneiron::test_support::{bind_host_owner, provision_engine_machines};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentDefinitionSpec, create_agent_definition_as,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use rmpv::Value;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const AT: u64 = 100;
const OCCURRED: TimeRange = TimeRange { start: AT, end: AT };

struct Fixture {
    vault: Vault,
    owner: EntityId,
    person: EntityId,
    w_claim: EntityId,
    base_claim: EntityId,
    _dir: tempfile::TempDir,
}

fn open() -> TestResult<Fixture> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let issuer = provision_engine_machines(&vault);
    bind_host_owner(&vault, &issuer, owner)?;

    let world = EntityId::now();
    vault.put_entity(&world, ENTITY_TYPE_WORLD, OCCURRED, AT, b"world")?;
    let person = EntityId::now();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        OCCURRED,
        AT,
        b"profiled person",
    )?;
    let w_claim = put_claim(&vault, person, Some(world), "Prefers quiet mornings.")?;
    let base_claim = put_claim(&vault, person, None, "Prefers walking at noon.")?;
    Ok(Fixture {
        vault,
        owner,
        person,
        w_claim,
        base_claim,
        _dir: dir,
    })
}

fn put_claim(
    vault: &Vault,
    person: EntityId,
    world: Option<EntityId>,
    value: &str,
) -> TestResult<EntityId> {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(person),
        Value::from(value),
        0.9,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    body.world = world;
    vault.put_claim(&id, &body, OCCURRED, AT)?;
    Ok(id)
}

fn trunk_record(conversation: EntityId, parent: Option<&str>, text: &str) -> DagRecordAppendInput {
    DagRecordAppendInput {
        conversation: conversation.to_hex(),
        parent: parent.map(str::to_owned),
        reply_to: None,
        containing_turn: None,
        addr: None,
        to: None,
        advance: true,
        body: json!({"txt": text, "speaker": "user"}),
        text: None,
        occurred_start: None,
        occurred_end: None,
        learned_at: None,
        session: None,
        quote: None,
        thread_audience: None,
    }
}

impl Fixture {
    /// A fresh two-turn trunk and its scope summary, optionally edited from another row.
    fn scope_summary(&self, editor_source: Option<EntityId>) -> TestResult<(EntityId, EntityId)> {
        let host = self.vault.memory(self.owner, EdgeActorClass::Human);
        let receipt = host.conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: json!({}),
            text: None,
        })?;
        let conversation = EntityId::from_hex(&receipt.id)?;
        let first =
            host.conversations_records_append(&trunk_record(conversation, None, "the plan"))?;
        let second = host.conversations_records_append(&trunk_record(
            conversation,
            Some(&first.id),
            "the first step",
        ))?;
        let summary = mint_scope_summary(
            &self.vault,
            &ScopeSelector {
                conversation,
                session: None,
                path: ScopePath::Canonical,
                include_forks: false,
            },
            "The plan, and its first step.",
        )?;
        let trunk_turn = EntityId::from_hex(&first.id)?;
        let covers = self.vault.scope_summary_covers(&summary)?;
        assert!(covers.contains(&trunk_turn) && covers.contains(&EntityId::from_hex(&second.id)?));
        if let Some(source) = editor_source {
            register_editor_source(&self.vault, &summary, &source)?;
        }
        Ok((summary, trunk_turn))
    }

    fn land_summary(
        &self,
        editor_source: Option<EntityId>,
        as_record: bool,
    ) -> TestResult<EntityId> {
        let (summary, trunk_turn) = self.scope_summary(editor_source)?;
        let landed = self.vault.land_header(
            &summary,
            &trunk_turn,
            WriteActor::new(self.owner, EdgeActorClass::Human),
            as_record,
        )?;
        if as_record {
            Ok(landed.record.ok_or("as_record lands a reply TURN")?)
        } else {
            Ok(landed.claim)
        }
    }

    fn profile_from(&self, claim: EntityId) -> TestResult<EntityId> {
        let profile = PsychProfile::new(
            self.person,
            "compact",
            "Copied prose from the cited claim.",
            "Narrative about the person.",
            vec![claim],
            PsychProfileConfidence::new(0.9, 0.8, 0.7)?,
        )?
        .with_sources(vec![PsychProfileSource {
            revision_ref: claim,
            document_ref: claim,
            world_ref: None,
            document_revision: RevisionRef(*claim.as_bytes()),
            words: PsychProfileSourceWords::Record {
                content: [0x5C; 32],
            },
        }])?;
        let id = EntityId::now();
        self.vault.put_psych_profile(&id, &profile)?;
        Ok(id)
    }

    fn compactor(&self) -> TestResult<EntityId> {
        let proof = self
            .vault
            .memory(self.owner, EdgeActorClass::Human)
            .embedded_owner("vault.agents.create")?;
        let writer = EntityId::now();
        let definition: AgentDefinitionSpec = serde_json::from_value(json!({
            "agent_id": "scribe",
            "display_name": "scribe",
            "desc": "scribe",
            "version": "1",
            "ceiling": "auto",
        }))?;
        create_agent_definition_as(
            &self.vault,
            &proof,
            AgentDefinitionCreateRequest {
                agent_def_ref: writer,
                definition,
            },
        )?;
        Ok(writer)
    }

    /// Files a real step with an answer large enough to produce a response artifact.
    fn file_step_from(
        &self,
        writer: EntityId,
        source: EntityId,
    ) -> TestResult<(EntityId, EntityId)> {
        let before: BTreeSet<_> = self
            .vault
            .entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT)?
            .into_iter()
            .collect();
        let answer = "The rest of the window. ".repeat(DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES / 16);
        let claim = file_compaction_step(
            &self.vault,
            "chat-compaction",
            EntityId::now(),
            writer,
            vec![source],
            &answer,
        )?;
        let new: Vec<_> = self
            .vault
            .entities_by_type(ENTITY_TYPE_BLOB_ARTIFACT)?
            .into_iter()
            .filter(|id| !before.contains(id))
            .collect();
        let [artifact] = new.as_slice() else {
            return Err(format!("expected one new response artifact, got {new:?}").into());
        };
        assert!(self.vault.is_compaction_step_response_artifact(artifact)?);
        Ok((claim, *artifact))
    }

    /// Files a real step from `source` and returns the content ASSET holding
    /// its response's bytes. The answer names `source`, so each step's bytes,
    /// and so its content-addressed ASSET, are its own.
    fn response_asset_from(&self, writer: EntityId, source: EntityId) -> TestResult<EntityId> {
        let before: BTreeSet<_> = self
            .vault
            .entities_by_type(ENTITY_TYPE_ASSET)?
            .into_iter()
            .collect();
        let answer = format!(
            "{} {}",
            source.to_hex(),
            "The rest of the window. ".repeat(DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES / 16)
        );
        file_compaction_step(
            &self.vault,
            "chat-compaction",
            EntityId::now(),
            writer,
            vec![source],
            &answer,
        )?;
        let new: Vec<_> = self
            .vault
            .entities_by_type(ENTITY_TYPE_ASSET)?
            .into_iter()
            .filter(|id| !before.contains(id))
            .collect();
        let [asset] = new.as_slice() else {
            return Err(format!("expected one new content ASSET, got {new:?}").into());
        };
        Ok(*asset)
    }

    fn finding_from(&self, claim: EntityId) -> TestResult<EntityId> {
        Ok(file_finding_notice(&self.vault, claim, self.person, AT)?)
    }

    fn intent_from(&self, claim: EntityId) -> TestResult<EntityId> {
        Ok(file_compaction_intent(&self.vault, self.owner, claim)?)
    }

    fn epoch_from(&self, source: EntityId) -> TestResult<EntityId> {
        Ok(file_epoch_summary_from(
            &self.vault,
            self.owner,
            vec![source],
        )?)
    }

    fn assert_narrowed(&self, label: &str, withheld: EntityId, twin: EntityId) -> TestResult {
        assert_slip_doors(
            &self.vault,
            &narrow_slip(),
            &[("the W-only source CLAIM", self.w_claim), (label, withheld)],
            &[
                ("the base-world source CLAIM", self.base_claim),
                ("the readable twin", twin),
            ],
        )
    }
}

fn narrow_slip() -> Scope {
    let mut slip = Scope::top();
    slip.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(base_world_id())]));
    slip.audience = ScopeAxis::Some(BTreeSet::from([ScopeId(default_project_id())]));
    slip.bands = ScopeAxis::Some(BTreeSet::from([
        ENTITY_TYPE_AGENT_DEF,
        ENTITY_TYPE_ASSET,
        ENTITY_TYPE_BLOB_ARTIFACT,
        ENTITY_TYPE_CLAIM,
        ENTITY_TYPE_CONVERSATION,
        ENTITY_TYPE_MESSAGE,
        ENTITY_TYPE_NOTE,
        ENTITY_TYPE_NOTIFICATION,
        ENTITY_TYPE_PERSON,
        ENTITY_TYPE_PSYCH_PROFILE,
        ENTITY_TYPE_SUMMARY,
        ENTITY_TYPE_TURN,
        ENTITY_TYPE_WORLD,
    ]));
    slip
}

fn assert_slip_doors(
    vault: &Vault,
    slip: &Scope,
    absent: &[(&str, EntityId)],
    present: &[(&str, EntityId)],
) -> TestResult {
    let top = Scope::top();
    let read = vault.records_in_scope(&top, slip, &top, ScopeView::Normal)?;
    assert_rows(&read, "read", absent, present);
    let export = vault.export_records_in_scope(&top, slip, &top)?;
    assert_rows(&export, "export", absent, present);
    Ok(())
}

fn assert_rows(
    rows: &[ScopedRecord],
    door: &str,
    absent: &[(&str, EntityId)],
    present: &[(&str, EntityId)],
) {
    for (label, target) in absent {
        assert!(
            !rows.iter().any(|r| r.id == *target),
            "{label} must be absent at the {door} door",
        );
    }
    for (label, target) in present {
        assert!(
            rows.iter().any(|r| r.id == *target),
            "{label} must be present at the {door} door",
        );
    }
}

#[test]
fn a_scope_summary_leaves_with_its_sources() -> TestResult {
    let f = open()?;
    let (withheld, _) = f.scope_summary(Some(f.w_claim))?;
    let (twin, _) = f.scope_summary(None)?;
    f.assert_narrowed("the W-sourced scope summary", withheld, twin)
}

#[test]
fn a_merge_header_leaves_with_its_summary_sources() -> TestResult {
    let f = open()?;
    let withheld = f.land_summary(Some(f.w_claim), false)?;
    let twin = f.land_summary(None, false)?;
    f.assert_narrowed("the W-sourced merge header", withheld, twin)
}

#[test]
fn a_psych_profile_leaves_with_its_cited_claims() -> TestResult {
    let f = open()?;
    let withheld = f.profile_from(f.w_claim)?;
    let twin = f.profile_from(f.base_claim)?;
    f.assert_narrowed("the W-sourced psych profile", withheld, twin)
}

#[test]
fn a_reply_carrying_a_summary_leaves_with_its_sources() -> TestResult {
    let f = open()?;
    let withheld = f.land_summary(Some(f.w_claim), true)?;
    let twin = f.land_summary(None, true)?;
    f.assert_narrowed("the W-sourced reply TURN", withheld, twin)
}

#[test]
fn a_compaction_step_claim_leaves_with_its_sources() -> TestResult {
    let f = open()?;
    let writer = f.compactor()?;
    let (withheld, _) = f.file_step_from(writer, f.w_claim)?;
    let (twin, _) = f.file_step_from(writer, f.base_claim)?;
    f.assert_narrowed("the W-sourced compaction step claim", withheld, twin)
}

#[test]
fn a_compaction_response_leaves_with_its_sources() -> TestResult {
    let f = open()?;
    let writer = f.compactor()?;
    let (_, withheld) = f.file_step_from(writer, f.w_claim)?;
    let (_, twin) = f.file_step_from(writer, f.base_claim)?;
    f.assert_narrowed("the W-sourced compaction response", withheld, twin)
}

/// REVIEW-10629 round 2: the response's bytes also sit in a content ASSET
/// stamped with the base world; that ASSET leaves only beside its response
/// artifact's sources, as the artifact does.
#[test]
fn a_compaction_response_asset_leaves_with_its_sources() -> TestResult {
    let f = open()?;
    let writer = f.compactor()?;
    let withheld = f.response_asset_from(writer, f.w_claim)?;
    let twin = f.response_asset_from(writer, f.base_claim)?;
    assert_ne!(
        withheld, twin,
        "FIXTURE: each step's bytes have their own ASSET"
    );
    f.assert_narrowed("the W-sourced compaction response ASSET", withheld, twin)
}

#[test]
fn a_finding_notice_leaves_with_its_subjects() -> TestResult {
    let f = open()?;
    let withheld = f.finding_from(f.w_claim)?;
    let twin = f.finding_from(f.base_claim)?;
    f.assert_narrowed("the W-sourced finding notice", withheld, twin)
}

#[test]
fn a_compaction_intent_note_leaves_with_its_sources() -> TestResult {
    let f = open()?;
    let withheld = f.intent_from(f.w_claim)?;
    let twin = f.intent_from(f.base_claim)?;
    f.assert_narrowed("the W-sourced compaction intent note", withheld, twin)
}

#[test]
fn an_epoch_summary_leaves_with_its_sources_words() -> TestResult {
    let f = open()?;
    let withheld_turn = f.land_summary(Some(f.w_claim), true)?;
    let withheld = f.epoch_from(withheld_turn)?;
    let twin_turn = f.land_summary(None, true)?;
    let twin = f.epoch_from(twin_turn)?;
    f.assert_narrowed("the W-sourced epoch summary", withheld, twin)
}

#[test]
fn a_top_slip_reads_every_derived_row() -> TestResult {
    let f = open()?;
    let (summary, _) = f.scope_summary(Some(f.w_claim))?;
    let header = f.land_summary(Some(f.w_claim), false)?;
    let profile = f.profile_from(f.w_claim)?;
    let reply = f.land_summary(Some(f.w_claim), true)?;
    let (step, response) = f.file_step_from(f.compactor()?, f.w_claim)?;
    let finding = f.finding_from(f.w_claim)?;
    let intent = f.intent_from(f.w_claim)?;
    let epoch = f.epoch_from(reply)?;
    assert_slip_doors(
        &f.vault,
        &narrow_slip(),
        &[("the W-only source CLAIM", f.w_claim)],
        &[("the base-world source CLAIM", f.base_claim)],
    )?;
    assert_slip_doors(
        &f.vault,
        &Scope::top(),
        &[],
        &[
            ("the W-only source CLAIM", f.w_claim),
            ("the W-sourced scope summary", summary),
            ("the W-sourced merge header", header),
            ("the W-sourced psych profile", profile),
            ("the W-sourced reply TURN", reply),
            ("the W-sourced compaction step claim", step),
            ("the W-sourced compaction response", response),
            ("the W-sourced finding notice", finding),
            ("the W-sourced compaction intent note", intent),
            ("the W-sourced epoch summary", epoch),
        ],
    )
}
