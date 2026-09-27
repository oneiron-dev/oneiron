use super::*;
use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance};
use crate::edge::EdgeActorClass;
use crate::edit_roundtrip::pptx::PptxCommentAction;
use crate::edit_roundtrip::pptx::tests::support;
use crate::edit_settle::{SettleConsent, SettleOutcomeKind};
use crate::llm::decision::{AnswerContract, DecisionClass};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::test_util::{embedding_test_config, open_test_vault_with};
use crate::{TimeRange, WriteActor};
use std::cell::RefCell;

fn deck(count: usize) -> Vec<u8> {
    let mut parts = support::parts(false);
    let slide = parts.remove("ppt/slides/slide9.xml").unwrap();
    let p = super::super::pptx::tests::support::parts(false);
    let mut presentation = String::from_utf8(p["ppt/presentation.xml"].clone()).unwrap();
    let mut relationships =
        String::from_utf8(p["ppt/_rels/presentation.xml.rels"].clone()).unwrap();
    let first = "<p:sldId id=\"256\" r:id=\"theSlide\"/>";
    let mut entries = String::new();
    let mut links = String::new();
    let rel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    for i in 1..=count {
        entries.push_str(&format!("<p:sldId id=\"{}\" r:id=\"s{i}\"/>", 255 + i));
        links.push_str(&format!(
            "<Relationship Id=\"s{i}\" Type=\"{rel}/slide\" Target=\"slides/slide{i}.xml\"/>"
        ));
        // The relationship kind is the canonical Office relationship namespace.
        parts.insert(
            format!("ppt/slides/slide{i}.xml"),
            String::from_utf8(slide.clone())
                .unwrap()
                .replace("val=\"41\"", &format!("val=\"{}\"", 40 + i))
                .into_bytes(),
        );
    }
    presentation = presentation.replace(first, &entries);
    relationships = relationships.replace(
        &format!(
            "<Relationship Id=\"theSlide\" Type=\"{}/slide\" Target=\"slides/slide9.xml\"/>",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        ),
        &links,
    );
    let mut content_types = String::from_utf8(parts["[Content_Types].xml"].clone()).unwrap();
    let slide_override = "<Override PartName=\"/ppt/slides/slide9.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.presentationml.slide+xml\"/>";
    let overrides = (1..=count)
        .map(|i| slide_override.replace("slide9.xml", &format!("slide{i}.xml")))
        .collect::<String>();
    content_types = content_types.replace(slide_override, &overrides);
    parts.insert("[Content_Types].xml".into(), content_types.into_bytes());
    parts.insert("ppt/presentation.xml".into(), presentation.into_bytes());
    parts.insert(
        "ppt/_rels/presentation.xml.rels".into(),
        relationships.into_bytes(),
    );
    support::bytes(&parts)
}

fn units(count: usize) -> Vec<SlideReviewUnit> {
    (1..=count)
        .map(|i| SlideReviewUnit {
            target: PptxCommentTarget {
                slide: i as u64,
                slide_creation_id: Some(40 + i as u32),
                shape_creation_id: None,
                shape_fingerprint: None,
            },
            text: format!("Slide {i} claim and evidence"),
            review_image: vec![i as u8, 5],
            renderer: "fixture-renderer@1".into(),
        })
        .collect()
}
fn question() -> DecisionQuestion {
    DecisionQuestion {
        id: EntityId::now(),
        version: 2,
        text: "Does this claim overstate its cited evidence?".into(),
        class: DecisionClass::Judgment,
        contract: AnswerContract::Noul,
        accept_type: false,
    }
}
fn labels() -> SlideReviewLabels {
    SlideReviewLabels {
        yes: "Overstated".into(),
        no: "Supported".into(),
        low: "Low".into(),
        middle: "Medium".into(),
        high: "High".into(),
    }
}
fn dial() -> DecisionDial {
    DecisionDial {
        first: DecisionRung::Local,
        ceiling: DecisionRung::SystemOne,
        band: DecisionBand::default(),
    }
}
struct Provider {
    rung: DecisionRung,
    calls: RefCell<Vec<Vec<u64>>>,
    malformed: bool,
}
impl Provider {
    fn new(rung: DecisionRung) -> Self {
        Self {
            rung,
            calls: RefCell::new(Vec::new()),
            malformed: false,
        }
    }
}
impl SlideReviewProvider for Provider {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: self.rung,
            model: "fixture".into(),
            version: "2".into(),
        }
    }
    fn decide_batch(
        &self,
        _question: &DecisionQuestion,
        rows: &[SlideReviewUnit],
    ) -> Result<Vec<ProviderDecision>> {
        self.calls
            .borrow_mut()
            .push(rows.iter().map(|u| u.target.slide).collect());
        let mut answers: Vec<_> = rows
            .iter()
            .map(|row| {
                let slide = row.target.slide;
                if slide == 11 && self.rung == DecisionRung::SystemOne {
                    ProviderDecision {
                        answer: DecisionAnswer::Abstain,
                        probability: None,
                    }
                } else if self.rung == DecisionRung::Local && matches!(slide, 5 | 11 | 20) {
                    ProviderDecision {
                        answer: DecisionAnswer::Noul(true),
                        probability: Some(0.5),
                    }
                } else {
                    ProviderDecision {
                        answer: DecisionAnswer::Noul(slide % 2 == 0),
                        probability: Some(0.9),
                    }
                }
            })
            .collect();
        if self.malformed {
            answers[0].probability = Some(f64::NAN);
        }
        Ok(answers)
    }
}
fn review(input: &[u8], count: usize, run_ref: &str) -> SlideReviewRun {
    let local = Provider::new(DecisionRung::Local);
    let jev = Provider::new(DecisionRung::SystemOne);
    review_slides(
        input,
        Some(1),
        &SlideReviewRequest {
            units: &units(count),
            question: &question(),
            principal: EntityId::now(),
            answered_by: EntityId::now(),
            author: &PptxAuthor {
                guid: support::AUTHOR.into(),
                name: "Editor".into(),
            },
            dial: dial(),
            resident_dial: None,
            limits: SlideReviewLimits::default(),
            policy: &DecisionBandPolicy::default(),
            reversibility: Reversibility::ReversibleRead,
            labels: &labels(),
            providers: &[&local, &jev],
            run_ref,
            at: 1_700_000_000_123,
        },
    )
    .unwrap()
}

#[test]
fn twenty_slides_batch_fallback_abstention_and_comment_receipt_agree() {
    let input = deck(20);
    let local = Provider::new(DecisionRung::Local);
    let jev = Provider::new(DecisionRung::SystemOne);
    let asker = EntityId::now();
    let answerer = EntityId::now();
    let q = question();
    let mut policy = DecisionBandPolicy::default();
    policy
        .learn_shadow(&q, Reversibility::ReversibleRead, dial().band, 1)
        .unwrap();
    policy.enforce(&q, Reversibility::ReversibleRead).unwrap();
    let result = review_slides(
        &input,
        Some(1),
        &SlideReviewRequest {
            units: &units(20),
            question: &q,
            principal: asker,
            answered_by: answerer,
            author: &PptxAuthor {
                guid: support::AUTHOR.into(),
                name: "Editor".into(),
            },
            dial: dial(),
            resident_dial: None,
            limits: SlideReviewLimits::default(),
            policy: &policy,
            reversibility: Reversibility::ReversibleRead,
            labels: &labels(),
            providers: &[&local, &jev],
            run_ref: "20-slides",
            at: 1_700_000_000_123,
        },
    )
    .unwrap();
    assert_eq!(
        local
            .calls
            .borrow()
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [8, 8, 4]
    );
    assert_eq!(*jev.calls.borrow(), vec![vec![5], vec![11], vec![20]]);
    assert_eq!(result.abstained.len(), 1);
    assert_eq!(result.abstained[0].slide, 11);
    let proposal = result.proposal.unwrap();
    assert_eq!(proposal.manifest.slide_judgments.len(), 19);
    verify_judgments(&proposal).unwrap();
    super::super::pptx::verify_comment_proposal(&input, &proposal).unwrap();
    let parts = support::unpack(&proposal.new_bytes);
    for row in &proposal.manifest.slide_judgments {
        assert_eq!(row.decision.receipt.question, q.id);
        assert_eq!(row.decision.receipt.question_version, 2);
        assert_eq!(row.decision.receipt.band_version, 1);
        assert_eq!(row.band_mode, BandMode::Enforce);
        assert_eq!(row.decision.receipt.principal, asker);
        assert_eq!(row.judged_version, Some(1));
        assert_eq!(row.frontier, *blake3::hash(&input).as_bytes());
        assert_eq!(row.renderer, "fixture-renderer@1");
        let op = proposal
            .manifest
            .ops
            .iter()
            .find_map(|op| match op {
                super::super::EditOp::PptxComment { patch } if patch.thread_id == row.thread_id => {
                    Some(patch)
                }
                _ => None,
            })
            .unwrap();
        assert_eq!(op.asked_by, asker);
        assert_eq!(op.answered_by, answerer);
        let PptxCommentAction::Add { text, .. } = &op.action else {
            panic!("not add")
        };
        assert_eq!(text, &row.comment);
        assert!(
            parts
                .values()
                .any(|bytes| std::str::from_utf8(bytes).is_ok_and(|xml| xml.contains(text)))
        );
        let expected = if matches!(row.target.slide, 5 | 20) {
            2
        } else {
            1
        };
        assert_eq!(row.decision.receipt.providers.len(), expected);
    }
}

#[test]
fn malformed_response_and_duplicate_unit_never_yield_a_proposal() {
    let input = deck(2);
    let local = Provider {
        rung: DecisionRung::Local,
        calls: RefCell::new(Vec::new()),
        malformed: true,
    };
    let jev = Provider::new(DecisionRung::SystemOne);
    let call = |units: Vec<_>| {
        review_slides(
            &input,
            Some(1),
            &SlideReviewRequest {
                units: &units,
                question: &question(),
                principal: EntityId::now(),
                answered_by: EntityId::now(),
                author: &PptxAuthor {
                    guid: support::AUTHOR.into(),
                    name: "Editor".into(),
                },
                dial: dial(),
                resident_dial: None,
                limits: SlideReviewLimits::default(),
                policy: &DecisionBandPolicy::default(),
                reversibility: Reversibility::ReversibleRead,
                labels: &labels(),
                providers: &[&local, &jev],
                run_ref: "malformed",
                at: 1_700_000_000_123,
            },
        )
    };
    assert!(call(units(2)).is_err());
    let mut duplicate = units(2);
    duplicate[1] = duplicate[0].clone();
    assert!(call(duplicate).is_err());
}

fn vault_with_deck(input: &[u8]) -> (tempfile::TempDir, Vault, EntityId, WriteActor) {
    let (dir, vault) = open_test_vault_with(embedding_test_config());
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"reviewer",
        )
        .unwrap();
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    let artifact = EntityId::now();
    vault
        .put_blob_artifact(
            &artifact,
            &BlobArtifactBody::new(
                "deck.pptx",
                "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ),
            TimeRange { start: 2, end: 2 },
            2,
        )
        .unwrap();
    vault
        .append_blob_artifact_version(
            &artifact,
            input,
            &BlobVersionProvenance::UserUpload,
            actor,
            TimeRange { start: 3, end: 3 },
            3,
        )
        .unwrap();
    (dir, vault, artifact, actor)
}

#[test]
fn keep_receipt_survives_reopen_and_stale_preview_cannot_overwrite() {
    let input = deck(2);
    let (dir, vault, artifact, actor) = vault_with_deck(&input);
    let first = review(&input, 2, "review:kept").proposal.unwrap();
    let stale = review(&input, 2, "review:stale").proposal.unwrap();
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    let selected = vault
        .settle_select_edit_proposal(
            &artifact,
            &first,
            &consent,
            actor,
            TimeRange { start: 4, end: 4 },
            4,
        )
        .unwrap();
    assert_eq!(selected.version.version, 2);
    assert_eq!(selected.receipt.outcome, "selected");
    assert!(selected.receipt.fields["slide_judgments"].contains("fixture-renderer@1"));
    assert_eq!(
        vault
            .blob_artifact_settlement(&artifact, "review:kept")
            .unwrap()
            .unwrap()
            .pptx_judgments,
        first.manifest.slide_judgments
    );
    let old = vault
        .settle_select_edit_proposal(
            &artifact,
            &stale,
            &consent,
            actor,
            TimeRange { start: 5, end: 5 },
            5,
        )
        .unwrap();
    assert!(old.stranded_proposal.is_some());
    assert_eq!(old.receipt.outcome, "proposed");
    let stale_patch = match &stale.manifest.ops[0] {
        super::super::EditOp::PptxComment { patch } => patch,
        _ => panic!("expected comment"),
    };
    assert_ne!(stale_patch.asked_by, stale_patch.answered_by);
    assert_ne!(actor.entity_ref(), stale_patch.asked_by);
    let identities: serde_json::Value =
        serde_json::from_str(&old.receipt.fields["pptx_review_identities"]).unwrap();
    assert_eq!(identities[0]["asked_by"], stale_patch.asked_by.to_hex());
    assert_eq!(
        identities[0]["answered_by"],
        stale_patch.answered_by.to_hex()
    );
    assert_eq!(identities[0]["export_author_guid"], support::AUTHOR);
    assert_eq!(old.version.version, 2);
    assert_eq!(
        vault
            .blob_artifact_settlement(&artifact, "review:stale")
            .unwrap()
            .unwrap()
            .outcome,
        SettleOutcomeKind::Proposed
    );
    assert_eq!(
        vault
            .blob_artifact_settlement(&artifact, "review:stale")
            .unwrap()
            .unwrap()
            .pptx_judgments,
        stale.manifest.slide_judgments
    );
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &stale,
                &consent,
                actor,
                TimeRange { start: 6, end: 6 },
                6
            )
            .is_err()
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config()).unwrap();
    assert_eq!(
        reopened
            .blob_artifact_settlement(&artifact, "review:kept")
            .unwrap()
            .unwrap()
            .pptx_judgments,
        first.manifest.slide_judgments
    );
    assert_eq!(
        reopened
            .blob_artifact_settlement(&artifact, "review:stale")
            .unwrap()
            .unwrap()
            .pptx_review_identities[0]
            .answered_by,
        stale_patch.answered_by
    );
}

#[test]
fn forged_receipt_or_comment_is_refused_at_settle() {
    let input = deck(1);
    let (_dir, vault, artifact, actor) = vault_with_deck(&input);
    let mut forged = review(&input, 1, "review:forged").proposal.unwrap();
    forged.manifest.slide_judgments[0].decision.probability = Some(2.0);
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &forged,
                &consent,
                actor,
                TimeRange { start: 4, end: 4 },
                4
            )
            .is_err()
    );
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "review:forged")
            .unwrap()
            .is_none()
    );
    let mut forged = review(&input, 1, "review:forged-2").proposal.unwrap();
    if let super::super::EditOp::PptxComment { patch } = &mut forged.manifest.ops[0]
        && let PptxCommentAction::Add { text, .. } = &mut patch.action
    {
        text.push_str(" changed");
    }
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &forged,
                &consent,
                actor,
                TimeRange { start: 4, end: 4 },
                4
            )
            .is_err()
    );
    let mut false_enforce = review(&input, 1, "review:fake-enforce").proposal.unwrap();
    false_enforce.manifest.slide_judgments[0].band_mode = BandMode::Enforce;
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &false_enforce,
                &consent,
                actor,
                TimeRange { start: 4, end: 4 },
                4
            )
            .is_err()
    );
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "review:fake-enforce")
            .unwrap()
            .is_none()
    );
}

#[test]
fn discard_keeps_the_review_receipt_but_never_writes_comments() {
    let input = deck(1);
    let (dir, vault, artifact, actor) = vault_with_deck(&input);
    let proposal = review(&input, 1, "review:discard").proposal.unwrap();
    let result = vault
        .settle_discard_edit_proposal(
            &artifact,
            &proposal,
            &SettleConsent::OwnerConsent { brief_ref: None },
            actor,
            "not selected",
            4,
        )
        .unwrap();
    assert_eq!(result.receipt.outcome, "discarded");
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    let row = vault
        .blob_artifact_settlement(&artifact, "review:discard")
        .unwrap()
        .unwrap();
    assert_eq!(row.pptx_judgments, proposal.manifest.slide_judgments);
    assert_eq!(row.outcome, SettleOutcomeKind::Discarded);
    assert!(result.receipt.fields["slide_judgments"].contains("fixture-renderer@1"));
    let patch = match &proposal.manifest.ops[0] {
        super::super::EditOp::PptxComment { patch } => patch,
        _ => panic!("expected comment"),
    };
    let identities: serde_json::Value =
        serde_json::from_str(&result.receipt.fields["pptx_review_identities"]).unwrap();
    assert_eq!(identities[0]["asked_by"], patch.asked_by.to_hex());
    assert_eq!(identities[0]["answered_by"], patch.answered_by.to_hex());
    assert_ne!(actor.entity_ref(), patch.answered_by);
    drop(vault);
    let reopened = Vault::open(dir.path(), embedding_test_config()).unwrap();
    assert_eq!(
        reopened
            .blob_artifact_settlement(&artifact, "review:discard")
            .unwrap()
            .unwrap()
            .pptx_review_identities[0]
            .answered_by,
        patch.answered_by
    );
}

struct ShortProvider;
impl SlideReviewProvider for ShortProvider {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Local,
            model: "short".into(),
            version: "1".into(),
        }
    }
    fn decide_batch(
        &self,
        _: &DecisionQuestion,
        _: &[SlideReviewUnit],
    ) -> Result<Vec<ProviderDecision>> {
        Ok(Vec::new())
    }
}

#[test]
fn wrong_batch_cardinality_fails_closed() {
    let input = deck(2);
    let jev = Provider::new(DecisionRung::SystemOne);
    assert!(
        review_slides(
            &input,
            Some(1),
            &SlideReviewRequest {
                units: &units(2),
                question: &question(),
                principal: EntityId::now(),
                answered_by: EntityId::now(),
                author: &PptxAuthor {
                    guid: support::AUTHOR.into(),
                    name: "Editor".into()
                },
                dial: dial(),
                resident_dial: None,
                limits: SlideReviewLimits::default(),
                policy: &DecisionBandPolicy::default(),
                reversibility: Reversibility::ReversibleRead,
                labels: &labels(),
                providers: &[&ShortProvider, &jev],
                run_ref: "short-output",
                at: 1_700_000_000_123,
            }
        )
        .is_err()
    );
}

#[test]
fn relabeled_slide_review_cannot_bypass_authoritative_pptx_replay() {
    let input = deck(1);
    let (_dir, vault, artifact, actor) = vault_with_deck(&input);
    let mut proposal = review(&input, 1, "review:relabel").proposal.unwrap();
    proposal.format = super::super::OfficeFormat::Xlsx;
    proposal.manifest.format = super::super::OfficeFormat::Xlsx;
    proposal.manifest.ops.clear();
    proposal.manifest.touched_parts.clear();
    proposal.manifest.slide_judgments.clear();
    let mut parts = support::unpack(&input);
    support::with_text(
        &mut parts,
        "ppt/slides/slide1.xml",
        "Original text",
        "Undeclared slide edit",
    );
    proposal.new_bytes = support::bytes(&parts);
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &proposal,
                &SettleConsent::OwnerConsent { brief_ref: None },
                actor,
                TimeRange { start: 4, end: 4 },
                4
            )
            .is_err()
    );
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "review:relabel")
            .unwrap()
            .is_none()
    );
}

#[test]
fn same_comment_cannot_change_answer_primitive_at_either_settle_door() {
    let input = deck(1);
    let (_dir, vault, artifact, actor) = vault_with_deck(&input);
    let mut proposal = review(&input, 1, "review:wrong-primitive")
        .proposal
        .unwrap();
    // The low-level writer's labels allow a choice to render identically to Noul(true).
    proposal.manifest.slide_judgments[0].decision.answer =
        DecisionAnswer::Choice("Overstated".into());
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &proposal,
                &consent,
                actor,
                TimeRange { start: 4, end: 4 },
                4
            )
            .is_err()
    );
    assert!(
        vault
            .settle_discard_edit_proposal(&artifact, &proposal, &consent, actor, "invalid", 4)
            .is_err()
    );
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "review:wrong-primitive")
            .unwrap()
            .is_none()
    );
}

#[test]
fn missing_input_abstains_per_unit_and_all_missing_creates_no_proposal() {
    let input = deck(20);
    let local = Provider::new(DecisionRung::Local);
    let jev = Provider::new(DecisionRung::SystemOne);
    let question = question();
    let mut units = units(20);
    units[10].review_image.clear();
    let request = SlideReviewRequest {
        units: &units,
        question: &question,
        principal: EntityId::now(),
        answered_by: EntityId::now(),
        author: &PptxAuthor {
            guid: support::AUTHOR.into(),
            name: "Editor".into(),
        },
        dial: dial(),
        resident_dial: None,
        limits: SlideReviewLimits::default(),
        policy: &DecisionBandPolicy::default(),
        reversibility: Reversibility::ReversibleRead,
        labels: &labels(),
        providers: &[&local, &jev],
        run_ref: "review:missing-one",
        at: 1_700_000_000_123,
    };
    let result = review_slides(&input, Some(1), &request).unwrap();
    assert_eq!(
        result.abstained.iter().map(|u| u.slide).collect::<Vec<_>>(),
        [11]
    );
    assert_eq!(result.proposal.unwrap().manifest.slide_judgments.len(), 19);
    assert_eq!(
        local
            .calls
            .borrow()
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        [8, 8, 3]
    );
    for unit in &mut units {
        unit.text.clear();
    }
    let all_missing = SlideReviewRequest {
        units: &units,
        question: &question,
        principal: EntityId::now(),
        answered_by: EntityId::now(),
        author: &PptxAuthor {
            guid: support::AUTHOR.into(),
            name: "Editor".into(),
        },
        dial: dial(),
        resident_dial: None,
        limits: SlideReviewLimits::default(),
        policy: &DecisionBandPolicy::default(),
        reversibility: Reversibility::ReversibleRead,
        labels: &labels(),
        providers: &[&local, &jev],
        run_ref: "review:all-missing",
        at: 1_700_000_000_123,
    };
    let result = review_slides(&input, Some(1), &all_missing).unwrap();
    assert_eq!(result.abstained.len(), 20);
    assert!(result.proposal.is_none());
}

struct ChangingPin {
    calls: std::cell::Cell<usize>,
}
impl SlideReviewProvider for ChangingPin {
    fn pin(&self) -> ProviderPin {
        let count = self.calls.get();
        self.calls.set(count + 1);
        ProviderPin {
            rung: DecisionRung::Local,
            model: if count == 0 { "validated" } else { "" }.into(),
            version: "1".into(),
        }
    }
    fn decide_batch(
        &self,
        _: &DecisionQuestion,
        units: &[SlideReviewUnit],
    ) -> Result<Vec<ProviderDecision>> {
        Ok(units
            .iter()
            .map(|_| ProviderDecision {
                answer: DecisionAnswer::Noul(true),
                probability: Some(0.9),
            })
            .collect())
    }
}
#[test]
fn provider_pin_is_validated_once_and_snapshotted_for_every_unit() {
    let input = deck(2);
    let provider = ChangingPin {
        calls: std::cell::Cell::new(0),
    };
    let question = question();
    let result = review_slides(
        &input,
        Some(1),
        &SlideReviewRequest {
            units: &units(2),
            question: &question,
            principal: EntityId::now(),
            answered_by: EntityId::now(),
            author: &PptxAuthor {
                guid: support::AUTHOR.into(),
                name: "Editor".into(),
            },
            dial: DecisionDial {
                first: DecisionRung::Local,
                ceiling: DecisionRung::Local,
                band: DecisionBand::default(),
            },
            resident_dial: None,
            limits: SlideReviewLimits::default(),
            policy: &DecisionBandPolicy::default(),
            reversibility: Reversibility::ReversibleRead,
            labels: &labels(),
            providers: &[&provider],
            run_ref: "review:pin",
            at: 1_700_000_000_123,
        },
    )
    .unwrap();
    assert_eq!(provider.calls.get(), 1);
    for row in result.proposal.unwrap().manifest.slide_judgments {
        assert_eq!(row.decision.receipt.providers[0].model, "validated");
    }
}

fn many_judgment_proposal(input: &[u8], count: usize, run_ref: &str) -> super::super::EditProposal {
    let mut proposal = review(input, 1, run_ref).proposal.unwrap();
    let row = proposal.manifest.slide_judgments[0].clone();
    let op = proposal.manifest.ops[0].clone();
    proposal.manifest.slide_judgments.clear();
    proposal.manifest.ops.clear();
    for index in 0..count {
        let thread_id = EntityId::now();
        let mut next = row.clone();
        next.thread_id = thread_id;
        next.target.slide = index as u64 + 1;
        let mut patch = op.clone();
        if let super::super::EditOp::PptxComment { patch } = &mut patch {
            patch.thread_id = thread_id;
            patch.comment_id = thread_id;
            if let PptxCommentAction::Add { target, .. } = &mut patch.action {
                *target = next.target.clone();
            }
        }
        proposal.manifest.slide_judgments.push(next);
        proposal.manifest.ops.push(patch);
    }
    proposal
}

#[test]
fn settlement_row_limit_is_shared_by_encoder_decoder_select_and_discard() {
    let input = deck(1);
    let (_dir, vault, artifact, actor) = vault_with_deck(&input);
    let consent = SettleConsent::OwnerConsent { brief_ref: None };
    let valid = many_judgment_proposal(&input, MAX_JUDGMENTS, "review:limit");
    assert!(validate_judgment_rows(&valid.manifest.slide_judgments).is_ok());
    // Discard writes the maximum valid ledger row, which must decode again.
    let discarded = vault
        .settle_discard_edit_proposal(&artifact, &valid, &consent, actor, "limit", 4)
        .unwrap();
    assert_eq!(discarded.receipt.outcome, "discarded");
    assert_eq!(
        vault
            .blob_artifact_settlement(&artifact, "review:limit")
            .unwrap()
            .unwrap()
            .pptx_judgments
            .len(),
        MAX_JUDGMENTS
    );
    let too_many = many_judgment_proposal(&input, MAX_JUDGMENTS + 1, "review:over-limit");
    assert!(
        vault
            .settle_discard_edit_proposal(&artifact, &too_many, &consent, actor, "over", 5)
            .is_err()
    );
    assert!(
        vault
            .settle_select_edit_proposal(
                &artifact,
                &too_many,
                &consent,
                actor,
                TimeRange { start: 5, end: 5 },
                5
            )
            .is_err()
    );
    assert!(
        vault
            .blob_artifact_settlement(&artifact, "review:over-limit")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        vault
            .blob_artifact_head(&artifact)
            .unwrap()
            .unwrap()
            .version,
        1
    );
    let mut duplicate = many_judgment_proposal(&input, 2, "review:duplicate");
    duplicate.manifest.slide_judgments[1].thread_id =
        duplicate.manifest.slide_judgments[0].thread_id;
    assert!(
        vault
            .settle_discard_edit_proposal(&artifact, &duplicate, &consent, actor, "duplicate", 6)
            .is_err()
    );
    let mut aliases = many_judgment_proposal(&input, 2, "review:aliases");
    aliases.manifest.slide_judgments[0].target.shape_creation_id = Some(support::SHAPE.into());
    aliases.manifest.slide_judgments[1].target.slide = 1;
    aliases.manifest.slide_judgments[1].target.shape_creation_id =
        Some(support::SHAPE.to_ascii_lowercase());
    assert!(validate_judgment_rows(&aliases.manifest.slide_judgments).is_err());
}

struct InBandProvider {
    rung: DecisionRung,
    calls: std::cell::Cell<usize>,
}
impl InBandProvider {
    fn new(rung: DecisionRung) -> Self {
        Self {
            rung,
            calls: std::cell::Cell::new(0),
        }
    }
}
impl SlideReviewProvider for InBandProvider {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: self.rung,
            model: "band-fixture".into(),
            version: "1".into(),
        }
    }
    fn decide_batch(
        &self,
        _: &DecisionQuestion,
        rows: &[SlideReviewUnit],
    ) -> Result<Vec<ProviderDecision>> {
        self.calls.set(self.calls.get() + 1);
        Ok(rows
            .iter()
            .map(|_| ProviderDecision {
                answer: DecisionAnswer::Noul(true),
                probability: Some(0.5),
            })
            .collect())
    }
}

#[test]
fn shared_shadow_and_enforce_policy_stamp_version_and_move_only_one_rung() {
    let input = deck(1);
    let q = question();
    let local = InBandProvider::new(DecisionRung::Local);
    let jev = InBandProvider::new(DecisionRung::SystemOne);
    let big = InBandProvider::new(DecisionRung::Big);
    let mut policy = DecisionBandPolicy::default();
    let learned = DecisionBand {
        low: 0.4,
        high: 0.6,
    };
    policy
        .learn_shadow(&q, Reversibility::ReversibleRead, learned, 3)
        .unwrap();
    let run = |policy: &DecisionBandPolicy, run_ref: &str| {
        review_slides(
            &input,
            Some(1),
            &SlideReviewRequest {
                units: &units(1),
                question: &q,
                principal: EntityId::now(),
                answered_by: EntityId::now(),
                author: &PptxAuthor {
                    guid: support::AUTHOR.into(),
                    name: "Editor".into(),
                },
                dial: DecisionDial {
                    first: DecisionRung::Local,
                    ceiling: DecisionRung::Big,
                    band: DecisionBand::default(),
                },
                resident_dial: None,
                limits: SlideReviewLimits::default(),
                policy,
                reversibility: Reversibility::ReversibleRead,
                labels: &labels(),
                providers: &[&local, &jev, &big],
                run_ref,
                at: 1_700_000_000_123,
            },
        )
        .unwrap()
    };
    let shadow = run(&policy, "review:shadow").proposal.unwrap();
    let row = &shadow.manifest.slide_judgments[0];
    assert_eq!(row.band_mode, BandMode::Shadow);
    assert_eq!(row.decision.receipt.band_version, 3);
    assert_eq!(row.decision.receipt.band, learned);
    assert_eq!(row.decision.receipt.providers.len(), 1);
    assert_eq!(
        (local.calls.get(), jev.calls.get(), big.calls.get()),
        (1, 0, 0)
    );
    policy.enforce(&q, Reversibility::ReversibleRead).unwrap();
    let enforced = run(&policy, "review:enforce").proposal.unwrap();
    let row = &enforced.manifest.slide_judgments[0];
    assert_eq!(row.band_mode, BandMode::Enforce);
    assert_eq!(row.decision.receipt.providers.len(), 2);
    assert!(row.decision.in_band);
    assert_eq!(
        (local.calls.get(), jev.calls.get(), big.calls.get()),
        (2, 1, 0)
    );
    verify_judgments(&enforced).unwrap();
}

#[test]
fn resident_dial_cannot_widen_owner_dial_or_change_band() {
    let input = deck(1);
    let q = question();
    let local = InBandProvider::new(DecisionRung::Local);
    let jev = InBandProvider::new(DecisionRung::SystemOne);
    let owner = dial();
    let widened = DecisionDial {
        first: DecisionRung::Rule,
        ceiling: DecisionRung::Big,
        band: owner.band,
    };
    let request = SlideReviewRequest {
        units: &units(1),
        question: &q,
        principal: EntityId::now(),
        answered_by: EntityId::now(),
        author: &PptxAuthor {
            guid: support::AUTHOR.into(),
            name: "Editor".into(),
        },
        dial: owner,
        resident_dial: Some(widened),
        limits: SlideReviewLimits::default(),
        policy: &DecisionBandPolicy::default(),
        reversibility: Reversibility::ReversibleRead,
        labels: &labels(),
        providers: &[&local, &jev],
        run_ref: "review:widen",
        at: 1_700_000_000_123,
    };
    assert!(review_slides(&input, Some(1), &request).is_err());
    assert_eq!(local.calls.get(), 0);
}

#[test]
fn vault_review_uses_manifest_limits_and_route_not_a_wider_request() {
    let input = deck(2);
    let (_dir, vault, artifact, _actor) = vault_with_deck(&input);
    let mut manifest = crate::gate::default_policy_manifest();
    let rmpv::Value::Map(mut entries) = rmpv::decode::read_value(&mut manifest.as_slice()).unwrap()
    else {
        unreachable!()
    };
    entries.retain(|(key, _)| key.as_str() != Some("slide_review_policy"));
    let row = |values: Vec<(&str, rmpv::Value)>| {
        rmpv::Value::Map(values.into_iter().map(|(k, v)| (k.into(), v)).collect())
    };
    entries.push((
        "slide_review_policy".into(),
        rmpv::Value::Array(vec![
            row(vec![
                ("scope", "precedence".into()),
                ("value", "nested_narrowing".into()),
            ]),
            row(vec![
                ("scope", "vault".into()),
                ("batch_size", 1_u64.into()),
                ("max_units", 1_u64.into()),
                ("max_text_bytes", 2048_u64.into()),
                ("max_image_bytes", 4096_u64.into()),
            ]),
            row(vec![
                ("scope", "route".into()),
                ("first", "local".into()),
                ("ceiling", "local".into()),
            ]),
        ]),
    ));
    manifest.clear();
    rmpv::encode::write_value(&mut manifest, &rmpv::Value::Map(entries)).unwrap();
    crate::test_util::put_policy_manifest_bytes(&vault, EntityId::now(), &manifest).unwrap();
    let local = Provider::new(DecisionRung::Local);
    let jev = Provider::new(DecisionRung::SystemOne);
    let q = question();
    let author = PptxAuthor {
        guid: support::AUTHOR.into(),
        name: "Editor".into(),
    };
    let labels = labels();
    let policy = DecisionBandPolicy::default();
    let two = units(2);
    let mut request = SlideReviewRequest {
        units: &two,
        question: &q,
        principal: EntityId::now(),
        answered_by: EntityId::now(),
        author: &author,
        dial: dial(),
        resident_dial: None,
        limits: SlideReviewLimits::default(),
        policy: &policy,
        reversibility: Reversibility::ReversibleRead,
        labels: &labels,
        providers: &[&local, &jev],
        run_ref: "review:manifest",
        at: 1_700_000_000_123,
    };
    // Both the vault unit cap and its route are stricter than this request.
    assert!(
        vault
            .review_blob_artifact_slides(&artifact, &request)
            .is_err()
    );
    assert!(local.calls.borrow().is_empty());
    let one = units(1);
    request.units = &one;
    request.dial.ceiling = DecisionRung::Local;
    let local_only = [&local as &dyn SlideReviewProvider];
    request.providers = &local_only;
    let result = vault
        .review_blob_artifact_slides(&artifact, &request)
        .unwrap();
    assert_eq!(result.proposal.unwrap().manifest.slide_judgments.len(), 1);
    assert_eq!(*local.calls.borrow(), vec![vec![1]]);
}
