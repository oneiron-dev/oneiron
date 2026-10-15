use std::cell::RefCell;

use super::*;

use crate::config::VaultConfig;
use crate::deletion::DeleteReason;
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::off_record::OffRecordBackendClass;
use crate::registry::ENTITY_TYPE_PERSON;

// ─── fixtures ───────────────────────────────────────────────────────────

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

const REFINED_TREE: &[(&str, &[u8])] = &[(
    "SKILL.md",
    b"---\nname: morning-routine-checklist\n---\n\n## When to use\n\nEvery morning.\n",
)];

fn tree(files: &[(&str, &[u8])]) -> Vec<HubFile> {
    files
        .iter()
        .map(|(path, content)| HubFile::new(*path, content.to_vec()))
        .collect()
}

fn tree_hash(files: &[(&str, &[u8])]) -> SkillContentHash {
    canonical_skill_tree_hash(files.iter().map(|(path, content)| (*path, *content)))
        .expect("fixture tree hashes")
}

/// The host-supplied refinement tier, doubled: it answers with a fixed skill
/// and records every brief it was handed, so a test can assert both what the
/// engine SHOWED it and whether it ran at all.
struct StubRefiner {
    refined: RefinedSkill,
    briefs: RefCell<Vec<SkillRefineBrief>>,
}

impl StubRefiner {
    fn new(skill_id: &str, files: Vec<HubFile>, verdict: RefineVerdict) -> Self {
        Self {
            refined: RefinedSkill {
                skill_id: skill_id.to_owned(),
                desc: "Run the morning routine checklist when the day starts".to_owned(),
                files,
                verdict,
            },
            briefs: RefCell::new(Vec::new()),
        }
    }

    fn minting(skill_id: &str, files: Vec<HubFile>) -> Self {
        Self::new(
            skill_id,
            files,
            RefineVerdict::Mint {
                justification: "nothing in the library covers this checklist".to_owned(),
            },
        )
    }

    fn calls(&self) -> usize {
        self.briefs.borrow().len()
    }
}

impl SkillRefiner for StubRefiner {
    fn refine(&self, brief: &SkillRefineBrief) -> Result<RefinedSkill> {
        self.briefs.borrow_mut().push(brief.clone());
        Ok(self.refined.clone())
    }
}

/// A refiner that supersedes its own merge target while it "thinks" — the
/// window between the shortlist read and the write transaction, which nothing
/// in-process covers because the tier belongs to the host.
struct SupersedingRefiner<'vault> {
    vault: &'vault Vault,
    target: EntityId,
    refined: RefinedSkill,
}

impl SkillRefiner for SupersedingRefiner<'_> {
    fn refine(&self, _brief: &SkillRefineBrief) -> Result<RefinedSkill> {
        let successor = EntityId::now();
        let mut revision = self
            .vault
            .get_skill_record(&self.target)?
            .expect("the target is seeded before the conversion runs");
        revision.version = "2.0.0".to_owned();
        revision.lifecycle_status = SkillLifecycle::Candidate;
        revision.content_hash = None;
        self.vault
            .put_skill_record(&successor, &revision, t(14), 15)?;
        admit(self.vault, &successor)?;
        self.vault
            .supersede_skill_record(&self.target, &successor, t(16), 17)?;
        Ok(self.refined.clone())
    }
}

/// Turns written by the PRODUCTION witness door: empty TURN containers whose
/// words live in MESSAGE children. Hand-assembling `spkr`/`txt` turns here
/// would arm the contract against a shape this road never actually selects.
fn witnessed_turns(vault: &Vault, lines: &[&str], now: u64) -> Vec<EntityId> {
    let actor = EntityId::now();
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            t(1),
            1,
            b"convert fixture actor",
        )
        .expect("seed actor");
    let facade = vault.memory(actor, EdgeActorClass::Human);
    let conversation = EntityId::now().to_hex();

    lines
        .iter()
        .enumerate()
        .map(|(index, line)| {
            let turn = EntityId::now();
            facade
                .witness(&WitnessTurn {
                    conversation_ref: conversation.clone(),
                    turn_ref: Some(turn.to_hex()),
                    messages: vec![WitnessMessage {
                        id: None,
                        author: WitnessAuthor::User,
                        message_type: "text".to_owned(),
                        content: (*line).to_owned(),
                        metadata: None,
                        is_visible: true,
                        order: 0,
                    }],
                    occurred_at: now + u64::try_from(index).expect("fixture turn counts are small"),
                })
                .expect("the witness door lands the turn");
            turn
        })
        .collect()
}

/// A skill already in the library, born on ANOTHER road (Dreamer distill:
/// generated, candidate, carrying its canonical content hash).
fn seed_extracted_skill(
    vault: &Vault,
    skill_id: &str,
    desc: &str,
    files: &[(&str, &[u8])],
) -> EntityId {
    seed_dependent_skill(vault, skill_id, desc, files, Vec::new())
}

/// [`seed_extracted_skill`] with a declared dependency contract — the thing a
/// revision of it must not silently drop.
fn seed_dependent_skill(
    vault: &Vault,
    skill_id: &str,
    desc: &str,
    files: &[(&str, &[u8])],
    dependencies: Vec<SkillDependency>,
) -> EntityId {
    let id = EntityId::now();
    let record = SkillRecord::new(
        skill_id,
        desc,
        "1.0.0",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.4,
        true,
        false,
        dependencies,
        Value::Map(vec![(Value::from("birth"), Value::from("dreamer_distill"))]),
    )
    .with_content_hash(tree_hash(files));
    vault
        .put_skill_record(&id, &record, t(10), 11)
        .expect("seed extracted skill");
    id
}

/// Admits a seeded revision (`candidate → active`) — the state a revision has
/// to be in before anything can supersede it.
fn admit(vault: &Vault, id: &EntityId) -> Result<()> {
    let mut record = vault.get_skill_record(id)?.expect("seeded record");
    record.lifecycle_status = SkillLifecycle::Active;
    vault.update_skill_record(id, &record, t(12), 13)
}

fn skill_count(vault: &Vault) -> usize {
    vault
        .entities_by_type(ENTITY_TYPE_SKILL)
        .expect("type index scan")
        .len()
}

fn provenance_str(record: &SkillRecord, key: &str) -> Option<String> {
    let Value::Map(entries) = &record.provenance else {
        return None;
    };
    entries
        .iter()
        .find(|(entry, _)| entry.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

// ─── the middle road lands a candidate ──────────────────────────────────

/// ARCH-0017 road 02: selected words become a `candidate` SKILL whose approval
/// is `approved` (initiation IS consent) and whose provenance carries the
/// STRUCTURED source linkage ONE-1447 reads back.
#[test]
fn conversion_lands_a_candidate_skill_with_structured_source_linkage() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let turns = witnessed_turns(
        &vault,
        &[
            "first I open the blinds and put the kettle on",
            "then I write the three things that matter today",
        ],
        1_775_000_000,
    );
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));

    let outcome = convert_messages_to_skill(
        &vault,
        &ConvertRequest::new(turns.clone()).with_hint("make this a checklist"),
        &refiner,
        t(20),
        21,
    )?;

    let ConvertOutcome::Created(id) = outcome else {
        panic!("a library with nothing alike in it mints: {outcome:?}");
    };
    let record = vault.get_skill_record(&id)?.expect("the record landed");

    assert_eq!(record.skill_id, "morning-routine-checklist");
    assert_eq!(
        record.lifecycle_status,
        SkillLifecycle::Candidate,
        "every birth path enters the one lifecycle machine at candidate"
    );
    assert_eq!(
        record.approval_status,
        ClaimApprovalStatus::Approved,
        "ARCH-0017: the user's initiation IS the consent for the conversion"
    );
    assert_eq!(record.source, ClaimSource::Generated);
    assert!(record.generated && !record.human_authored);
    assert_eq!(
        record.content_hash,
        Some(tree_hash(REFINED_TREE)),
        "identity is recomputed from the refined tree, never taken on trust"
    );
    assert!(
        (record.confidence
            - SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::Generated)
                .mean())
        .abs()
            < f32::EPSILON,
        "a converted skill starts on the Generated prior, not on an optimistic constant"
    );
    assert_eq!(
        provenance_str(&record, PROVENANCE_BIRTH_KEY).as_deref(),
        Some(CONVERT_BIRTH_PATH)
    );
    assert_eq!(
        provenance_str(&record, PROVENANCE_DEDUP_RATIONALE_KEY).as_deref(),
        Some("nothing in the library covers this checklist"),
        "the mint justification is receipted onto the record it justified"
    );
    assert_eq!(provenance_str(&record, PROVENANCE_MERGE_OF_KEY), None);

    // The linkage ONE-1447 depends on, read back through this module's reader.
    let mut sources = source_message_refs(&record)?;
    sources.sort_unstable();
    let mut expected: Vec<EntityId> = vault
        .edges_in(&turns[0])?
        .into_iter()
        .chain(vault.edges_in(&turns[1])?)
        .filter(|edge| edge.kind == EdgeKind::PartOf)
        .map(|edge| edge.target)
        .collect();
    expected.sort_unstable();
    assert_eq!(
        sources, expected,
        "the cited sources are the MESSAGE entities whose words were actually read"
    );
    assert_eq!(
        skill_convert_call_purpose(),
        CallPurpose::Other {
            name: SKILL_CONVERT_CALL_PURPOSE_NAME.to_owned()
        }
    );
    Ok(())
}

// ─── near duplicates land as gated proposals ────────────────────────────

/// Near-duplicate: the refined content lands as a `proposed` candidate revision
/// of the EXISTING skill — never an in-place edit of canon.
#[test]
fn a_near_duplicate_lands_a_gated_merge_proposal() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let existing = seed_dependent_skill(
        &vault,
        "morning-routine",
        "The morning routine: blinds, kettle, three priorities",
        &[("SKILL.md", b"# older morning routine\n")],
        vec![SkillDependency::with_min_version("kettle-safety", "1.0.0")],
    );
    let before = vault.get_skill_record(&existing)?.expect("seeded");
    assert!(
        !before.dependencies.is_empty(),
        "the dependency-inheritance assertion below only bites on a target that declares one"
    );
    let turns = witnessed_turns(
        &vault,
        &["blinds, kettle, then the three priorities"],
        1_775_000_000,
    );
    let refiner = StubRefiner::new(
        "morning-routine-checklist",
        tree(REFINED_TREE),
        RefineVerdict::MergeInto {
            existing,
            rationale: "same procedure, one step spelled out".to_owned(),
        },
    );

    let outcome =
        convert_messages_to_skill(&vault, &ConvertRequest::new(turns), &refiner, t(20), 21)?;

    let ConvertOutcome::MergeProposed {
        existing: target,
        proposal,
    } = outcome
    else {
        panic!("a near duplicate proposes rather than mints: {outcome:?}");
    };
    assert_eq!(target, existing);

    let record = vault.get_skill_record(&proposal)?.expect("proposal landed");
    assert_eq!(
        record.skill_id, before.skill_id,
        "a proposal continues the target's skill id, so the gate can supersede with it"
    );
    assert_ne!(
        record.version, before.version,
        "a revision needs its own version for supersession to be expressible"
    );
    assert_eq!(
        record.approval_status,
        ClaimApprovalStatus::Proposed,
        "the user consented to converting their words, not to rewriting a skill they did not name"
    );
    assert_eq!(record.lifecycle_status, SkillLifecycle::Candidate);
    assert_eq!(
        record.dependencies, before.dependencies,
        "a revision inherits the dependency contract it revises; admitting one that declares \
         none would amputate what its predecessor shipped with"
    );
    assert_eq!(
        provenance_str(&record, PROVENANCE_MERGE_OF_KEY).as_deref(),
        Some(existing.to_hex().as_str())
    );
    assert_eq!(
        provenance_str(&record, PROVENANCE_DEDUP_RATIONALE_KEY).as_deref(),
        Some("same procedure, one step spelled out"),
        "the near-dup rationale is receipted on the proposal it produced"
    );

    let after = vault
        .get_skill_record(&existing)?
        .expect("the target remains in the library");
    assert_eq!(after.skill_id, before.skill_id);
    assert_eq!(after.version, before.version);
    assert_eq!(after.content_hash, before.content_hash);
    assert_eq!(after.dependencies, before.dependencies);
    assert_eq!(after.approval_status, before.approval_status);
    assert_eq!(after.lifecycle_status, before.lifecycle_status);
    Ok(())
}

/// Refinement runs OUTSIDE the write transaction, so the target it diffed
/// against can be superseded while it runs. A proposal against a frozen revision
/// is dead on arrival — `supersede_skill_record` refuses a non-active old
/// revision — so the write door re-reads the target's LIFECYCLE, not only its
/// existence.
#[test]
fn a_target_superseded_during_refinement_is_refused_at_the_write_door() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let existing = seed_extracted_skill(
        &vault,
        "morning-routine",
        "The morning routine: blinds, kettle, three priorities",
        &[("SKILL.md", b"# older morning routine\n")],
    );
    admit(&vault, &existing)?;
    let turns = witnessed_turns(
        &vault,
        &["blinds, kettle, then the three priorities"],
        1_775_000_000,
    );
    let refiner = SupersedingRefiner {
        vault: &vault,
        target: existing,
        refined: RefinedSkill {
            skill_id: "morning-routine-checklist".to_owned(),
            desc: "Run the morning routine checklist when the day starts".to_owned(),
            files: tree(REFINED_TREE),
            verdict: RefineVerdict::MergeInto {
                existing,
                rationale: "same procedure, one step spelled out".to_owned(),
            },
        },
    };
    let before = skill_count(&vault);

    let error = convert_messages_to_skill(&vault, &ConvertRequest::new(turns), &refiner, t(40), 41)
        .expect_err("a proposal no gate could ever admit is refused, not landed");

    assert_eq!(error.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(
        vault
            .get_skill_record(&existing)?
            .expect("the target survives its own supersession")
            .lifecycle_status,
        SkillLifecycle::Superseded,
        "the fixture must really have frozen the target, or this is not the TOCTOU case"
    );
    assert_eq!(
        skill_count(&vault),
        before + 1,
        "the one new entity is the successor the refiner itself admitted; the conversion \
         wrote nothing"
    );
    Ok(())
}

// ─── the fence ──────────────────────────────────────────────────────────

/// Pipeline-inertness: a durable skill minted from a live room's words would
/// outlive the session promised to evaporate. Under ARCH-0052 P6 the refusal is
/// STRUCTURAL rather than a probe — this conversion holds a canonical `&Vault`,
/// which cannot address an overlay row at all — so the selection fails at the
/// type read, before the refiner tier is reached.
#[test]
fn live_room_refs_are_refused_before_the_refiner_runs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let before = skill_count(&vault);
    let session = vault
        .off_record_session_vault()
        .enter("sess-convert-room", OffRecordBackendClass::Local)?;
    let room_member = EntityId::now();
    {
        let overlay = session.overlay();
        let segment = overlay.install_txn_segment()?;
        overlay.put(
            crate::session_overlay::OverlayKeyspace::Entities,
            room_member.as_bytes(),
            b"live session overlay entity",
        )?;
        segment.commit()?;
    }
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));

    let error = convert_messages_to_skill(
        &vault,
        &ConvertRequest::new(vec![room_member]),
        &refiner,
        t(20),
        21,
    )
    .expect_err("a live room member is not convertible");
    assert_eq!(error.kind(), ErrorKind::EntityNotFound);
    assert_eq!(
        refiner.calls(),
        0,
        "the room's words must never reach the refinement tier"
    );
    assert_eq!(skill_count(&vault), before);
    session.close()?;
    Ok(())
}

// ─── selection shape ────────────────────────────────────────────────────

/// [`source_message_refs`] is the reader ONE-1447 hangs off: silent for records
/// born on another road, strict about a linkage that is present but malformed.
#[test]
fn source_message_refs_is_silent_off_this_road_and_strict_on_it() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let extracted = seed_extracted_skill(&vault, "elsewhere", "Born elsewhere", REFINED_TREE);
    let record = vault.get_skill_record(&extracted)?.expect("seeded");
    assert_eq!(source_message_refs(&record)?, Vec::new());

    let mut corrupt = record;
    corrupt.provenance = Value::Map(vec![(
        Value::from(PROVENANCE_SOURCE_MESSAGES_KEY),
        Value::from("not-an-array"),
    )]);
    assert_eq!(
        source_message_refs(&corrupt)
            .expect_err("a malformed linkage is corruption, not an absent linkage")
            .kind(),
        ErrorKind::InvalidSkillBody
    );
    Ok(())
}

// ─── ONE-1447: the stale fold ───────────────────────────────────────────

/// A converted skill that has been ADMITTED, plus the source messages it
/// cites. Admission matters: `active` is the state the lifecycle machine lets
/// the fold move, and the state whose loss of canon standing is observable.
fn converted_and_admitted(vault: &Vault, lines: &[&str]) -> (EntityId, Vec<EntityId>) {
    let turns = witnessed_turns(vault, lines, 1_775_000_000);
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));
    let outcome =
        convert_messages_to_skill(vault, &ConvertRequest::new(turns), &refiner, t(20), 21)
            .expect("the conversion lands");
    let ConvertOutcome::Created(skill) = outcome else {
        panic!("a library with nothing alike in it mints: {outcome:?}");
    };
    admit(vault, &skill).expect("the admission gate activates the candidate");
    let record = vault
        .get_skill_record(&skill)
        .expect("read back")
        .expect("the record landed");
    let sources = source_message_refs(&record).expect("the linkage reads back");
    assert_eq!(sources.len(), lines.len(), "one cited message per line");
    (skill, sources)
}

/// The whole ticket in one pass: a deleted source takes the skill it grounded
/// out of canon — visibly, with the cause on the record's note, and without
/// touching the record itself.
#[test]
fn a_deleted_source_stales_the_skill_it_grounded_without_losing_it() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (skill, sources) = converted_and_admitted(&vault, &["blinds, kettle", "then priorities"]);
    let before = vault.get_skill_record(&skill)?.expect("admitted record");
    assert_eq!(before.lifecycle_status, SkillLifecycle::Active);
    assert_eq!(skills_dependent_on_message(&vault, &sources[0])?, [skill]);

    assert!(
        vault
            .delete_own_room_record(sources[0], DeleteReason::UserHardDelete)?
            .existed,
        "the source existed"
    );

    let after = vault
        .get_skill_record(&skill)?
        .expect("staleness never deletes the skill");
    assert_eq!(after.lifecycle_status, SkillLifecycle::Stale);
    assert!(!after.lifecycle_status.loads_as_canon());
    assert_eq!(after.skill_id, before.skill_id);
    assert_eq!(after.version, before.version);
    assert_eq!(after.desc, before.desc);
    assert_eq!(after.content_hash, before.content_hash);
    assert_eq!(after.provenance, before.provenance);
    assert_eq!(after.dependencies, before.dependencies);
    assert_eq!(after.approval_status, before.approval_status);

    let note = skill_stale_note(&vault, &skill)?.expect("the cause is inspectable");
    assert_eq!(note.reason, STALE_REASON_SOURCE_MESSAGE_DELETED);
    assert_eq!(note.deleted_refs, vec![sources[0]]);
    Ok(())
}

#[test]
fn conversion_merge_preserves_workflow_and_refuses_callable_metadata_loss() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let existing = seed_extracted_skill(
        &vault,
        "morning-routine-checklist",
        "The morning routine: blinds, kettle, three priorities",
        &[("SKILL.md", b"# older morning routine\n")],
    );
    let mut target = vault.get_skill_record(&existing)?.expect("target");
    target.version = "2".into();
    target.role = crate::skill::SkillRole::Workflow;
    vault.update_skill_record(&existing, &target, t(12), 13)?;
    let turns = witnessed_turns(
        &vault,
        &["blinds, kettle, then the three priorities"],
        1_775_000_000,
    );
    let refiner = StubRefiner::new(
        "morning-routine-checklist",
        tree(REFINED_TREE),
        RefineVerdict::MergeInto {
            existing,
            rationale: "same workflow".into(),
        },
    );
    let ConvertOutcome::MergeProposed { proposal, .. } = convert_messages_to_skill(
        &vault,
        &ConvertRequest::new(turns.clone()),
        &refiner,
        t(20),
        21,
    )?
    else {
        panic!("merge proposes")
    };
    assert_eq!(
        vault.get_skill_record(&proposal)?.expect("proposal").role,
        crate::skill::SkillRole::Workflow
    );

    let mut callable = target;
    callable.version = "3".into();
    callable.role = crate::skill::SkillRole::Callable;
    callable.call = Some(crate::skill::SkillCallContract {
        reference: "scripts/run.js".into(),
        arguments: serde_json::json!({"value":"integer"}),
        returns: serde_json::json!({"value":"integer"}),
    });
    vault.update_skill_record(&existing, &callable, t(22), 23)?;
    let changed_refiner = StubRefiner::new(
        "morning-routine-checklist",
        vec![HubFile::new("SKILL.md", b"---\nname: morning-routine-checklist\n---\nA changed routine without callable contract.\n".to_vec())],
        RefineVerdict::MergeInto { existing, rationale: "same procedure".into() },
    );
    let err = convert_messages_to_skill(
        &vault,
        &ConvertRequest::new(turns),
        &changed_refiner,
        t(24),
        25,
    )
    .expect_err("a callable merge cannot omit its source contract");
    assert_eq!(err.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(
        vault
            .get_skill_record(&existing)?
            .expect("target after refusal")
            .role,
        crate::skill::SkillRole::Callable
    );
    Ok(())
}
