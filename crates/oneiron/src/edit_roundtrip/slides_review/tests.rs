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
