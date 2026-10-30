//! Typed slide and shape review execution.
//! Entry: `review_slides`.
//! Review model types and shared evidence helpers remain in the parent.

use super::*;

/// Whether a `width` by `height` image is drawn at the slide's own aspect,
/// within 1%: what a render of the whole slide is.
pub(super) fn whole_slide((width, height): (u32, u32), (cx, cy): (i64, i64)) -> bool {
    width > 0
        && height > 0
        && cx > 0
        && cy > 0
        && ((f64::from(width) / f64::from(height)) / (cx as f64 / cy as f64) - 1.0).abs() <= 0.01
}

/// One question over selected slide/shape units, one decide() call per unit
/// under the run's deadline, in batches of the limits' batch size: a batch
/// starts only while the run has time left, and each unit of one the
/// deadline did not reach is refused for it, in order (FIX 9819). The ladder routes each call (its first rung, one
/// step up for a cause, a skipped empty rung, the cut rule) and writes its
/// receipt; an abstention lists its unit with that receipt. A Human ceiling is
/// refused: the landing is a comment proposal, not a person's queue. Errors and
/// malformed output leave no partial proposal behind.
pub fn review_slides(
    base: &SlideReviewBase<'_>,
    request: &SlideReviewRequest<'_>,
) -> std::result::Result<SlideReviewRun, SlideReviewError> {
    let SlideReviewRequest {
        units,
        question,
        principal,
        answered_by,
        author,
        dial,
        resident_dial,
        limits,
        policy,
        reversibility,
        labels,
        decider,
        evidence,
        budget,
        deadline,
        run_ref,
        at,
    } = *request;
    question.validate()?;
    let dial = resident_dial.map_or(Ok(dial), |resident| dial.narrow(resident))?;
    dial.band.validate()?;
    if !limits.valid() {
        return Err(invalid("invalid slide review limits").into());
    }
    let band_policy = policy.resolve(question, reversibility, dial.band)?;
    labels.validate()?;
    if dial.first > dial.ceiling || dial.ceiling == DecisionRung::Human || budget.is_zero() {
        return Err(invalid("invalid slide review selection or dial").into());
    }
    let inspection = inspect_pptx(base.bytes)?;
    if !inspection.signature_parts.is_empty() {
        return Err(PptxError::SignedPackage.into());
    }
    // A resource refusal is the engine's error (FIX 10587), never an invalid deck.
    let package = Package::open(
        base.bytes,
        base.package_limits,
        &crate::office_body::document_resources(),
    )
    .map_err(|error| {
        crate::office_body::document_error(error.resource(), "slide review package")
    })?;
    let view = DeckView::read(&package).map_err(|error| {
        crate::office_body::document_error(error.resource(), "slide review deck view")
    })?;
    // A located answer is kept in slide EMU when the deck gives its size.
    let slide_size = if question.contract.locates() {
        TemplateView::read(&package)
            .map_err(|error| {
                crate::office_body::document_error(error.resource(), "slide review deck size")
            })?
            .slide_size
    } else {
        None
    };
    let frontier = *blake3::hash(base.bytes).as_bytes();
    let deck = EvidenceVersion {
        id: base.artifact,
        body_hash: frontier,
    };
    let evidence: Vec<EntityId> = evidence
        .iter()
        .copied()
        .chain(std::iter::once(base.artifact))
        .collect();
    let mut seen = HashSet::new();
    let mut abstained = Vec::new();
    let mut refused = Vec::new();
    let mut judgments = Vec::new();
    let mut patches = Vec::new();
    for batch in units.chunks(limits.batch_size) {
        // Every unit is still checked; one of a batch the run's deadline
        // did not reach is refused for it, never dropped or asked late.
        let reached = Instant::now() < deadline;
        for unit in batch {
            let target = &unit.target;
            let shape_key = target
                .shape_creation_id
                .as_deref()
                .map(canonical_guid)
                .transpose()?;
            let slide = target
                .slide
                .checked_sub(1)
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| view.slides.get(index));
            let identity = inspection
                .slides
                .iter()
                .find(|slide| slide.slide == target.slide);
            let (Some(slide), Some(identity)) = (slide, identity) else {
                return Err(invalid("invalid slide review unit").into());
            };
            if slide.part != identity.part
                || slide.sld_id != identity.sld_id
                || target
                    .slide_creation_id
                    .is_some_and(|id| slide.creation_id != Some(id))
                || !seen.insert((target.slide, shape_key.clone()))
                || unit.image.len() > limits.max_image_bytes
                || unit.renderer.len() > 256
            {
                return Err(
                    invalid("invalid slide review unit or exceeded evidence budget").into(),
                );
            }
            if !reached {
                refused.push(refusal(target, SlideUnitRefusalReason::RunDeadline));
                continue;
            }
            let read = match read_unit(slide, identity, target, shape_key.as_deref()) {
                Ok(read) => read,
                Err(reason) => {
                    refused.push(refusal(target, reason));
                    continue;
                }
            };
            // An unavailable image is not a negative answer or a malformed call.
            if unit.image.is_empty() || unit.renderer.trim().is_empty() {
                abstained.push(SlideAbstention {
                    target: target.clone(),
                    decision: None,
                });
                continue;
            }
            // A decision reads an image whole or not at all: none is scaled to fit.
            if unit.image.len() > MAX_DECISION_IMAGE_BYTES {
                refused.push(refusal(target, SlideUnitRefusalReason::EvidenceBudget));
                continue;
            }
            // A render's pixel size, which a located answer maps onto the slide.
            let (medium, rendered) = match &unit.image {
                SlideReviewImage::Rendered(bytes) => {
                    let Some(media_type) = image_media_type(bytes) else {
                        refused.push(refusal(target, SlideUnitRefusalReason::UnreadableImage));
                        continue;
                    };
                    let image = ImageBytes {
                        bytes: bytes.clone(),
                        media_type: media_type.to_owned(),
                    };
                    let Ok(reference) = ImageRef::of(deck.clone(), &image, None) else {
                        refused.push(refusal(target, SlideUnitRefusalReason::UnreadableImage));
                        continue;
                    };
                    let size = (reference.width, reference.height);
                    let medium = ResolvedMedia::Image {
                        name: REVIEW_IMAGE.to_owned(),
                        reference,
                        image,
                    };
                    (medium, Some(size))
                }
                SlideReviewImage::Stored(medium) => (medium.clone(), None),
            };
            // The host's decider says which rung its pixels or audio ride to, if any.
            let call = MediaCall::of(dial, vec![medium], |images, audio| {
                decider.first_taking_media(question, dial, images, audio)
            })
            .map_err(|_| invalid("invalid slide review image"))?;
            let render_hash = call
                .entries
                .first()
                .map(|entry| medium_hash(&entry.reference))
                .ok_or_else(|| invalid("invalid slide review image"))?;
            // A Box or Point question locates in pixels: with none sent, nothing is
            // asked.
            if call.images.is_empty() && question.contract.locates() {
                abstained.push(SlideAbstention {
                    target: target.clone(),
                    decision: None,
                });
                continue;
            }
            let state = call
                .state(serde_json::json!({
                    "unit": {
                        "slide": target.slide,
                        "sld_id": slide.sld_id,
                        "slide_creation_id": slide.creation_id,
                        "shape_creation_id": shape_key,
                        "shape_id": read.anchor.shape.as_ref().and_then(|shape| shape.shape_id),
                        "shape_name": read.name,
                    },
                    "text": read.text,
                    "renderer": unit.renderer,
                }))
                .map_err(|_| invalid("slide review unit state"))?;
            let state_bytes =
                serde_json::to_vec(&state).map_err(|_| invalid("slide review unit state"))?;
            if read.text.len() > limits.max_text_bytes
                || state_bytes.len() > MAX_DECISION_STATE_BYTES
            {
                refused.push(refusal(target, SlideUnitRefusalReason::EvidenceBudget));
                continue;
            }
            let now = Instant::now();
            let clock =
                RetrievalDeadline::hard(now, budget.min(deadline.saturating_duration_since(now)));
            let unit_call = UnitCall {
                question,
                principal,
                evidence: &evidence,
                images: &call.images,
                audio: &call.audio,
                state: &state,
                dial: call.dial,
                policy,
                reversibility,
                deadline: &clock,
                // A slide review's dial stops below the person.
                ask_to: None,
                correlation: None,
            };
            // A Box or Point question asks presence first: its coordinates stand
            // with the presence step beside them, or a confident no stands alone.
            let (mut decision, mut presence, answered, answer_contract) =
                if question.contract.locates() {
                    let located = decider.decide_located(&unit_call)?;
                    let answered = located.answer != DecisionAnswer::Abstain;
                    let contract = if located.location.is_some() {
                        question.contract.clone()
                    } else {
                        AnswerContract::Noul
                    };
                    let (decision, presence) = located.split();
                    (decision, presence, answered, contract)
                } else {
                    let decision = decider.decide_unit(&unit_call)?;
                    let answered = decision.answer != DecisionAnswer::Abstain;
                    (decision, None, answered, question.contract.clone())
                };
            // The deck at its frontier, then each other version an image or a
            // clip the ladder was shown is of (a rendered image is of the deck
            // itself).
            let pin_versions = |decision: &mut TypedDecision| {
                decision.receipt.evidence_versions = std::iter::once(deck.clone())
                    .chain(
                        call.images
                            .iter()
                            .map(|image| image.evidence.clone())
                            .chain(call.audio.iter().map(|clip| clip.evidence.clone()))
                            .filter(|version| *version != deck),
                    )
                    .collect();
            };
            pin_versions(&mut decision);
            if let Some(presence) = &mut presence {
                pin_versions(presence);
            }
            if !answered {
                abstained.push(SlideAbstention {
                    target: target.clone(),
                    decision: Some(decision),
                });
                continue;
            }
            let probability = decision
                .probability
                .ok_or_else(|| invalid("missing review probability"))?;
            let location = rendered
                .zip(slide_size)
                .filter(|&(pixels, size)| whole_slide(pixels, size))
                .and_then(|(_, size)| SlideLocation::of(&decision.answer, size));
            let thread_id = EntityId::now();
            let comment = labels.comment(&decision.answer, probability, decision.receipt.band);
            patches.push(PptxCommentPatch {
                asked_by: principal,
                answered_by,
                author: author.clone(),
                thread_id,
                comment_id: thread_id,
                at,
                action: PptxCommentAction::Add {
                    target: target.clone(),
                    text: comment.clone(),
                },
            });
            judgments.push(SlideJudgment {
                thread_id,
                target: target.clone(),
                anchor: read.anchor,
                decision,
                answer_contract,
                presence,
                location,
                band_mode: band_policy.mode,
                renderer: unit.renderer.clone(),
                frontier,
                media: call.entries,
                render_hash,
                evidence_hash: *blake3::hash(&state_bytes).as_bytes(),
                judged_version: base.version,
                comment,
                labels: labels.clone(),
            });
        }
    }
    if patches.is_empty() {
        return Ok(SlideReviewRun {
            proposal: None,
            abstained,
            refused,
            read_rows: Vec::new(),
        });
    }
    let mut proposal = run_comment_roundtrip(base.bytes, &patches, run_ref)?;
    proposal.base_version = base.version;
    proposal.manifest.slide_judgments = judgments;
    proposal.manifest.slide_question = Some(question.clone());
    Ok(SlideReviewRun {
        proposal: Some(proposal),
        abstained,
        refused,
        read_rows: Vec::new(),
    })
}

/// A slide unit reads every text-bearing shape in document order; a shape unit
/// reads its one shape, which the writer must be able to anchor at its own
/// verified slide-space top-left.
pub(super) fn read_unit(
    slide: &SlideView,
    identity: &PptxSlideIdentity,
    target: &PptxCommentTarget,
    shape_key: Option<&str>,
) -> std::result::Result<UnitRead, SlideUnitRefusalReason> {
    let mut anchor = SlideReviewAnchor {
        slide_part: slide.part.clone(),
        sld_id: slide.sld_id,
        slide_fingerprint: slide.content_fingerprint,
        render_fingerprint: slide.render_fingerprint,
        shape: None,
    };
    let Some(key) = shape_key else {
        let text = slide
            .shapes
            .iter()
            .filter_map(shape_text)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        return Ok(UnitRead {
            text,
            anchor,
            name: None,
        });
    };
    let shape = match slide
        .shapes
        .iter()
        .filter(|shape| shape.creation_id.as_deref() == Some(key))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => return Err(SlideUnitRefusalReason::MissingShape),
        [shape] => *shape,
        _ => return Err(SlideUnitRefusalReason::AmbiguousShape),
    };
    let written = match identity
        .shapes
        .iter()
        .filter(|shape| shape.creation_id.as_deref() == Some(key))
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => return Err(SlideUnitRefusalReason::MissingShape),
        [written] => *written,
        _ => return Err(SlideUnitRefusalReason::AmbiguousShape),
    };
    if target
        .shape_fingerprint
        .is_some_and(|fingerprint| fingerprint != written.fingerprint)
    {
        return Err(SlideUnitRefusalReason::TargetChanged);
    }
    if written.position.is_none() {
        return Err(SlideUnitRefusalReason::UnresolvedGeometry);
    }
    anchor.shape = Some(ShapeReviewAnchor {
        node_part: shape.node.part.clone(),
        node_index: shape.node.index as u64,
        shape_id: shape.id,
        fingerprint: shape.content_fingerprint,
    });
    Ok(UnitRead {
        text: shape_text(shape).unwrap_or_default(),
        anchor,
        name: shape.name.clone(),
    })
}

pub(super) fn refusal(
    target: &PptxCommentTarget,
    reason: SlideUnitRefusalReason,
) -> SlideUnitRefusal {
    let offer = (target.shape_creation_id.is_some()
        && !matches!(
            reason,
            SlideUnitRefusalReason::EvidenceBudget
                | SlideUnitRefusalReason::UnreadableImage
                | SlideUnitRefusalReason::RunDeadline
        ))
    .then(|| PptxCommentTarget {
        shape_creation_id: None,
        shape_fingerprint: None,
        ..target.clone()
    });
    SlideUnitRefusal {
        target: target.clone(),
        reason,
        offer,
    }
}

/// A render's media type, from its signature: PNG or JPEG only.
pub(super) fn image_media_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else {
        None
    }
}
