use std::cell::RefCell;

use super::*;

use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::error::ErrorKind;
use crate::facade::{WitnessAuthor, WitnessMessage, WitnessTurn};
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

    fn last_brief(&self) -> SkillRefineBrief {
        self.briefs
            .borrow()
            .last()
            .cloned()
            .expect("the refiner was called")
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
    let facade = vault.memory_facade(actor, EdgeActorClass::Human);
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

/// The refiner reasons over the selected WORDS and the nearest existing skills
/// — it cannot diff against a library it was never shown.
#[test]
fn the_refine_brief_carries_the_words_and_the_nearest_skills() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let neighbor = seed_extracted_skill(
        &vault,
        "morning-routine",
        "The morning routine: blinds, kettle, three priorities",
        &[("SKILL.md", b"# older morning routine\n")],
    );
    seed_extracted_skill(
        &vault,
        "invoice-chasing",
        "Chase unpaid invoices at quarter end",
        &[("SKILL.md", b"# invoices\n")],
    );
    let turns = witnessed_turns(&vault, &["blinds, kettle, then priorities"], 1_775_000_000);
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));

    convert_messages_to_skill(
        &vault,
        &ConvertRequest::new(turns).with_hint("keep the kettle step"),
        &refiner,
        t(20),
        21,
    )?;

    let brief = refiner.last_brief();
    assert_eq!(
        brief
            .said
            .iter()
            .filter_map(|spoken| spoken.text.clone())
            .collect::<Vec<_>>(),
        vec!["blinds, kettle, then priorities".to_owned()]
    );
    assert_eq!(brief.hint.as_deref(), Some("keep the kettle step"));
    assert_eq!(
        brief
            .neighbors
            .iter()
            .map(|candidate| candidate.entity)
            .collect::<Vec<_>>(),
        vec![neighbor],
        "only the skill sharing vocabulary with the selection is nearby"
    );
    Ok(())
}

// ─── one namespace, one identity ────────────────────────────────────────

/// Exact-tree duplicate: the second conversion refuses with a POINTER to the
/// holder, and mints no rival entity.
#[test]
fn identical_content_refuses_with_a_pointer_to_the_holder() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let turns = witnessed_turns(&vault, &["blinds, kettle, priorities"], 1_775_000_000);
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));
    let request = ConvertRequest::new(turns);

    let ConvertOutcome::Created(first) =
        convert_messages_to_skill(&vault, &request, &refiner, t(20), 21)?
    else {
        panic!("the first conversion mints");
    };
    let after_first = skill_count(&vault);

    let second = convert_messages_to_skill(&vault, &request, &refiner, t(30), 31)?;

    assert_eq!(second, ConvertOutcome::DupPointer(first));
    assert_eq!(
        skill_count(&vault),
        after_first,
        "a duplicate points at the holder instead of creating beside it"
    );
    Ok(())
}

/// The Dreamer-auto road and this manual road share ONE namespace: a manual
/// convert colliding with an auto-extracted skill dedups against it.
#[test]
fn manual_conversion_dedups_against_a_dreamer_extracted_skill() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let extracted = seed_extracted_skill(
        &vault,
        "morning-routine-checklist",
        "Extracted by the Dreamer from repeated morning turns",
        REFINED_TREE,
    );
    let turns = witnessed_turns(&vault, &["blinds, kettle, priorities"], 1_775_000_000);
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));

    let outcome =
        convert_messages_to_skill(&vault, &ConvertRequest::new(turns), &refiner, t(20), 21)?;

    assert_eq!(
        outcome,
        ConvertOutcome::DupPointer(extracted),
        "identical bytes are ONE skill whichever road they arrived on"
    );
    assert_eq!(skill_count(&vault), 1);
    Ok(())
}

/// The mechanical tier outranks the LLM tier: an insistent `Mint` over bytes
/// the library already holds still dedups.
#[test]
fn an_insistent_mint_verdict_cannot_buy_a_second_holder() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let holder = seed_extracted_skill(&vault, "already-here", "Already here", REFINED_TREE);
    let turns = witnessed_turns(&vault, &["blinds, kettle, priorities"], 1_775_000_000);
    let refiner = StubRefiner::minting("a-brand-new-name", tree(REFINED_TREE));

    let outcome =
        convert_messages_to_skill(&vault, &ConvertRequest::new(turns), &refiner, t(20), 21)?;

    assert_eq!(outcome, ConvertOutcome::DupPointer(holder));
    assert_eq!(skill_count(&vault), 1);
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
    assert_eq!(
        vault.get_skill_record(&existing)?.as_ref(),
        Some(&before),
        "proposing must not touch the skill it proposes against"
    );
    Ok(())
}

/// Grounding: a merge target the brief never offered was never diffed against,
/// so it cannot have been judged a near-duplicate.
#[test]
fn a_merge_target_outside_the_brief_is_refused() {
    let (_tmp, vault) = temp_vault();
    let unrelated = seed_extracted_skill(
        &vault,
        "invoice-chasing",
        "Chase unpaid invoices at quarter end",
        &[("SKILL.md", b"# invoices\n")],
    );
    let turns = witnessed_turns(&vault, &["blinds, kettle, priorities"], 1_775_000_000);
    let refiner = StubRefiner::new(
        "morning-routine-checklist",
        tree(REFINED_TREE),
        RefineVerdict::MergeInto {
            existing: unrelated,
            rationale: "asserted without having been shown it".to_owned(),
        },
    );

    let error = convert_messages_to_skill(&vault, &ConvertRequest::new(turns), &refiner, t(20), 21)
        .expect_err("an ungrounded merge target is refused");

    assert_eq!(error.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(skill_count(&vault), 1, "the refusal writes nothing");
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

/// Pipeline-inertness: a durable skill minted from fenced turns would outlive
/// the session promised to evaporate, so the refusal precedes the READ — the
/// refiner never runs at all.
///
/// Both ways in are pinned. `tag_turn_off_record` writes the fence on the TURN
/// id alone, so naming the turn's MESSAGE CHILD is a selection whose own row is
/// clear and whose words are the fenced ones — refused only because the probe
/// walks the `PartOf` container.
#[test]
fn fenced_refs_are_refused_before_the_refiner_runs() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let turns = witnessed_turns(&vault, &["said inside the fence"], 1_775_000_000);
    // Read before the fence goes up: tagging scrubs the turn's live-window
    // carriers, and this test is about the selection, not about that scrub.
    let child = vault
        .edges_in(&turns[0])?
        .into_iter()
        .find(|edge| edge.kind == EdgeKind::PartOf)
        .expect("the witness door writes the turn's words as a MESSAGE child")
        .target;
    vault.enter_off_record_session("sess-convert-fence", OffRecordBackendClass::Local)?;
    vault.tag_turn_off_record("sess-convert-fence", &turns[0])?;
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));

    for selected in [turns[0], child] {
        let error = convert_messages_to_skill(
            &vault,
            &ConvertRequest::new(vec![selected]),
            &refiner,
            t(20),
            21,
        )
        .expect_err("a fenced ref is refused");

        assert_eq!(error.kind(), ErrorKind::OffRecordFencedTurnWriteRejected);
        assert!(
            matches!(
                error,
                Error::OffRecordFencedTurnWriteRejected { turn_ref } if turn_ref == turns[0].to_hex()
            ),
            "the refusal names the FENCED turn, whichever id the selection typed"
        );
    }
    assert_eq!(
        refiner.calls(),
        0,
        "the fenced words must never reach the refinement tier"
    );
    assert_eq!(skill_count(&vault), 0);
    Ok(())
}

// ─── selection shape ────────────────────────────────────────────────────

/// A selection the door cannot honour: empty, repeated, non-conversational, or
/// carrying no words at all.
#[test]
fn an_unusable_selection_is_refused() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let turns = witnessed_turns(&vault, &["blinds, kettle, priorities"], 1_775_000_000);
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));

    for request in [
        ConvertRequest::new(Vec::new()),
        ConvertRequest::new(vec![turns[0], turns[0]]),
        ConvertRequest::new(vec![EntityId::now()]),
    ] {
        let error = convert_messages_to_skill(&vault, &request, &refiner, t(20), 21)
            .expect_err("an unusable selection is refused");
        assert!(matches!(
            error.kind(),
            ErrorKind::InvalidSkillBody | ErrorKind::EntityNotFound
        ));
    }

    // A wordless TURN: a real entity of the right type carrying nothing to
    // refine. Inventing a skill from silence is the failure mode this refuses.
    let silent = EntityId::now();
    vault.put_entity(&silent, ENTITY_TYPE_TURN, t(5), 5, b"")?;
    let error = convert_messages_to_skill(
        &vault,
        &ConvertRequest::new(vec![silent]),
        &refiner,
        t(20),
        21,
    )
    .expect_err("a wordless selection is refused");
    assert_eq!(error.kind(), ErrorKind::InvalidSkillBody);
    assert_eq!(refiner.calls(), 0);
    Ok(())
}

/// The MESSAGE arm: a user may select individual messages, not only turns.
#[test]
fn messages_may_be_selected_directly() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let message = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![
            (Value::from("author"), Value::from("user")),
            (
                Value::from("content"),
                Value::from("open the blinds, then the kettle"),
            ),
        ]),
    )
    .expect("fixture body encodes");
    vault.put_entity(&message, ENTITY_TYPE_MESSAGE, t(5), 5, &body)?;
    let refiner = StubRefiner::minting("morning-routine-checklist", tree(REFINED_TREE));

    let outcome = convert_messages_to_skill(
        &vault,
        &ConvertRequest::new(vec![message]),
        &refiner,
        t(20),
        21,
    )?;

    let ConvertOutcome::Created(id) = outcome else {
        panic!("a direct message selection mints: {outcome:?}");
    };
    let record = vault.get_skill_record(&id)?.expect("the record landed");
    assert_eq!(source_message_refs(&record)?, vec![message]);
    assert_eq!(
        refiner.last_brief().said[0].text.as_deref(),
        Some("open the blinds, then the kettle")
    );
    Ok(())
}

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
