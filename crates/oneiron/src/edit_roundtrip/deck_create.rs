//! Deck creation from an approved outline (ARCH-0077, "Create: an approved
//! argument, then a design").
//!
//! The outline is a brief NOTE (`plugin/brief`) whose markdown holds the
//! closed outline JSON, as a `json` fenced block or the whole body. A person
//! keeps it: the keep maps every evidence pin this engine can address (a
//! cited CLAIM's, or a note document span named without one) through its
//! note cursors (a span that no longer maps is marked drifted, its quote
//! kept), parses the result against the closed schema, and freezes the note
//! frontier, the exact outline bytes and their hash. Beside the bytes and
//! outside their hash it keeps what it observed of each such pin: the cited
//! CLAIM's lifecycle, the cited document's frontier, whether the span maps
//! (FIX 9813, 9814). Editing the note or moving cited CLAIM evidence makes
//! the keep stale; a stale keep never runs. Evidence that changes otherwise
//! is reported beside the keep, never as another keep to make.
//!
//! Each requested design direction compiles the kept outline against its
//! template into one design spec linked to the outline: plans summarised,
//! never live decks (FIX 9604). Creation compiles against the chosen
//! template, checks the plan, emits a checked candidate and lands it as the
//! first version of a new deck artifact. Its creation record names the kept
//! outline as born-from, identifies the template, and keeps the slides,
//! write set, omitted blocks, fit status and the estimates with the faces
//! that measured them.

use std::collections::BTreeMap;

mod evidence_pins;
mod store;
use evidence_pins::{EngineSpan, cited_lifecycle, engine_span, hex, note_pin, pins, pins_mut};
pub(crate) use store::outline_pins;

use oneiron_docedit::design_plan::{
    AssetBinding, Brief, CompileError, Fallback, KeptBrief, MediaType, Outcome, compile_with_fonts,
};
use oneiron_docedit::emit::{EmitInputs, StoredAsset, check_template, emit};
use oneiron_docedit::fonts::FontBook;
use oneiron_docedit::graphic::{AssetRecord, GraphicLimits, Origin};
use oneiron_docedit::retained_opc::Package;
use serde_json::Value;

use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::note::{NotePin, NoteSpanResolution};
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::side_table::{self, Named, SideTable};
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;

const PPTX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.presentationml.presentation";

pub(crate) type CompiledDirections = (
    DesignSpec,
    Vec<Option<oneiron_docedit::design_plan::DesignPlan>>,
    Vec<Vec<oneiron_docedit::design_plan::Decision>>,
);

const OUTLINE_KEEPS: SideTable<EntityId, KeptOutline, Named> =
    SideTable::new(&side_table::DECK_OUTLINE_KEEP);
const DESIGN_SPECS: SideTable<EntityId, DesignSpec, Named> =
    SideTable::new(&side_table::DECK_DESIGN_SPEC);
const CREATIONS: SideTable<EntityId, DeckCreationRecord, Named> =
    SideTable::new(&side_table::DECK_CREATION);

/// Removes the deck rows keyed by an erased entity: a note's kept outline and
/// design spec, an artifact's creation record and native-id history.
/// Registered in `deletion/derived_rows.rs`.
pub(crate) fn erase_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    discard_payload_in_txn(store, txn, entity)?;
    super::deck::erase_in_txn(store, txn, entity)
}

/// The owner's discard of a world copy (FIX 14534, Engine 11-06 08:34 call
/// 4 = A): a note's kept outline and design spec and an artifact's creation
/// record go; its managed native-id history stays as identifier-only
/// immutable history.
pub(crate) fn discard_payload_in_txn(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    OUTLINE_KEEPS.delete(store, txn, entity)?;
    DESIGN_SPECS.delete(store, txn, entity)?;
    CREATIONS.delete(store, txn, entity)?;
    Ok(())
}

pub use crate::blob_artifact::deck_creation::record::{
    ArtifactVersionRef, CitedClaimLifecycle, CreatedEstimate, CreatedInput, CreatedSlide,
    DeckCreateError, DeckCreateOutcome, DeckCreateRequest, DeckCreationRecord, DesignDirection,
    DesignSpec, DirectionOutcome, DirectionSlide, EvidenceChange, EvidenceObservation, KeptOutline,
    OutlineFreshness,
};

fn invalid(message: &'static str) -> DeckCreateError {
    DeckCreateError::Outline(message)
}

impl crate::Vault {
    /// Keep the outline brief at its current frontier: map its evidence,
    /// check the closed schema, and freeze the exact bytes and hash.
    pub fn keep_deck_outline(
        &self,
        note: EntityId,
        actor: WriteActor,
    ) -> std::result::Result<KeptOutline, DeckCreateError> {
        self.try_with_write_txn_grouped(|txn| self.keep_deck_outline_in_txn(txn, note, actor))
    }

    pub(crate) fn keep_deck_outline_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        note: EntityId,
        actor: WriteActor,
    ) -> std::result::Result<KeptOutline, DeckCreateError> {
        let document = crate::note::deck_outline_document_in_txn(self, txn, note)?;
        let mut outline: Value = serde_json::from_str(outline_text(&document.markdown))
            .map_err(|_| invalid("the brief holds no outline JSON"))?;
        self.map_evidence_in_txn(txn, &mut outline, true)?;
        let evidence = self.observe_evidence_in_txn(txn, &outline)?;
        let bytes = serde_json::to_vec(&outline).map_err(|_| invalid("outline encoding"))?;
        Brief::parse(&bytes).map_err(CompileError::from)?;
        let kept = KeptOutline {
            note,
            version: hex(&document.frontier),
            frontier: document.frontier,
            content_hash: *blake3::hash(&bytes).as_bytes(),
            bytes,
            kept_by: actor.entity_ref(),
            kept_at: self.now_recorded_at(),
            evidence,
        };
        OUTLINE_KEEPS.put(&self.store, txn, &note, &kept)?;
        DESIGN_SPECS.delete(&self.store, txn, &note)?;
        Ok(kept)
    }

    /// The current keep of an outline, if any.
    pub fn kept_deck_outline(&self, note: EntityId) -> Result<Option<KeptOutline>> {
        let txn = self.store.env.read_txn()?;
        OUTLINE_KEEPS.get(&self.store, &txn, &note)
    }

    pub(crate) fn kept_deck_outline_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        note: EntityId,
    ) -> Result<Option<KeptOutline>> {
        OUTLINE_KEEPS.get(&self.store, txn, &note)
    }

    /// Whether the keep still describes the outline and its evidence.
    pub fn deck_outline_freshness(
        &self,
        note: EntityId,
    ) -> std::result::Result<OutlineFreshness, DeckCreateError> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        self.deck_outline_freshness_in_txn(&txn, note)
    }

    pub(crate) fn deck_outline_freshness_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        note: EntityId,
    ) -> std::result::Result<OutlineFreshness, DeckCreateError> {
        let Some(kept) = OUTLINE_KEEPS.get(&self.store, txn, &note)? else {
            return Ok(OutlineFreshness::NotKept);
        };
        let document = crate::note::deck_outline_document_in_txn(self, txn, note)?;
        let held: Value =
            serde_json::from_slice(&kept.bytes).map_err(|_| invalid("kept outline encoding"))?;
        if document.frontier != kept.frontier {
            // The frontier moved: a title edit or surrounding-markdown whitespace
            // leaves the outline JSON itself unchanged. Re-parse the current outline
            // exactly as the keep does and compare the parsed JSON against the held
            // outline; only an outline difference is an edit (FIX 355). Drift is the
            // evidence check below's verdict, not this comparison's.
            let current: Value = match serde_json::from_str(outline_text(&document.markdown)) {
                Ok(current) => current,
                Err(_) => return Ok(OutlineFreshness::Edited),
            };
            if !outline_content_equal(&held, &current) {
                return Ok(OutlineFreshness::Edited);
            }
            // Equal: fall through to the evidence-drift check below.
        }
        // Only a cited CLAIM's span gates the keep, as it always has; any
        // other change is reported beside it (`deck_outline_evidence_in_txn`).
        let mut remapped = held.clone();
        self.map_evidence_in_txn(txn, &mut remapped, false)?;
        let (mut before, mut after) = (Vec::new(), Vec::new());
        pins(&held, &mut |pin| before.push(pin.get("drift").cloned()));
        pins(&remapped, &mut |pin| after.push(pin.get("drift").cloned()));
        let moved: Vec<usize> = before
            .iter()
            .zip(&after)
            .enumerate()
            .filter(|(_, (was, now))| was != now)
            .map(|(index, _)| index)
            .collect();
        Ok(if moved.is_empty() {
            OutlineFreshness::Fresh
        } else {
            OutlineFreshness::EvidenceMoved { pins: moved }
        })
    }

    /// What changed in the keep's cited evidence since it was kept, beside
    /// the freshness that gates it: a cited CLAIM's lifecycle, a source's
    /// frontier, a span the engine maps differently (FIX 9813, 9814). Empty
    /// with no keep.
    pub(crate) fn deck_outline_evidence_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        note: EntityId,
    ) -> std::result::Result<Vec<EvidenceChange>, DeckCreateError> {
        let Some(kept) = OUTLINE_KEEPS.get(&self.store, txn, &note)? else {
            return Ok(Vec::new());
        };
        let held: Value =
            serde_json::from_slice(&kept.bytes).map_err(|_| invalid("kept outline encoding"))?;
        Ok(self
            .observe_evidence_in_txn(txn, &held)?
            .into_iter()
            .filter_map(|now| {
                let kept = kept.evidence.iter().find(|seen| seen.pin == now.pin)?;
                (*kept != now).then(|| EvidenceChange {
                    kept: kept.clone(),
                    now,
                })
            })
            .collect())
    }

    /// Compile the fresh kept outline against every requested template and
    /// store the directions as the outline's design spec.
    pub fn design_deck_directions(
        &self,
        note: EntityId,
        templates: &[ArtifactVersionRef],
        assets: &BTreeMap<String, ArtifactVersionRef>,
        fonts: &[ArtifactVersionRef],
    ) -> std::result::Result<DesignSpec, DeckCreateError> {
        self.try_with_write_txn_grouped(|txn| {
            self.design_deck_directions_in_txn(txn, note, templates, assets, fonts)
                .map(|(spec, _, _)| spec)
        })
    }

    pub(crate) fn design_deck_directions_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        note: EntityId,
        templates: &[ArtifactVersionRef],
        assets: &BTreeMap<String, ArtifactVersionRef>,
        fonts: &[ArtifactVersionRef],
    ) -> std::result::Result<CompiledDirections, DeckCreateError> {
        if templates.is_empty() {
            return Err(invalid("at least one design direction"));
        }
        let kept = self.fresh_outline_in_txn(txn, note)?;
        let limits = self.docedit_package_limits_in_txn(txn)?;
        let book = self.font_book_in_txn(txn, fonts)?;
        let bindings = self.asset_bindings_in_txn(txn, assets)?;
        let mut directions = Vec::new();
        let mut plans = Vec::new();
        let mut questions = Vec::new();
        for template in templates {
            let bytes = self.version_bytes_in_txn(txn, template)?;
            let package = Package::open(&bytes, limits, &crate::office_body::document_resources())
                .map_err(|error| {
                    // A resource refusal is the engine's error (FIX 10587).
                    error.resource().map_or_else(
                        || invalid("template package"),
                        |refusal| {
                            DeckCreateError::Vault(crate::office_body::document_refused(refusal))
                        },
                    )
                })?;
            check_template(&package)?;
            let outcome = compile_with_fonts(&kept_brief(&kept), &package, &bindings, &book)?;
            questions.push(match &outcome {
                Outcome::Ask(decisions) => decisions.clone(),
                Outcome::Plan(_) => Vec::new(),
            });
            plans.push(match &outcome {
                Outcome::Plan(plan) => {
                    plan.check(&kept_brief(&kept), &package)?;
                    Some((**plan).clone())
                }
                Outcome::Ask(_) => None,
            });
            directions.push(DesignDirection {
                template: *template,
                template_hash: *blake3::hash(&bytes).as_bytes(),
                outcome: match outcome {
                    Outcome::Ask(decisions) => DirectionOutcome::Ask {
                        pages: decisions
                            .into_iter()
                            .map(|decision| decision.page)
                            .collect(),
                    },
                    Outcome::Plan(plan) => {
                        let estimates = plan.slides().iter().flat_map(|slide| &slide.fit.estimates);
                        let measured = estimates.clone().filter(|e| e.font.is_some()).count();
                        DirectionOutcome::Plan {
                            slides: plan
                                .slides()
                                .iter()
                                .map(|slide| DirectionSlide {
                                    page: slide.page.clone(),
                                    layout: slide.layout.clone(),
                                    fallback: slide.fallback.map(fallback_name),
                                })
                                .collect(),
                            omitted: plan
                                .trace()
                                .iter()
                                .filter(|entry| {
                                    entry.outcome
                                        == oneiron_docedit::design_plan::TraceOutcome::Omitted
                                })
                                .map(|entry| entry.block.clone())
                                .collect(),
                            measured,
                            estimated: estimates.count() - measured,
                        }
                    }
                },
            });
        }
        let spec = DesignSpec {
            note,
            content_hash: kept.content_hash,
            directions,
        };
        DESIGN_SPECS.put(&self.store, txn, &note, &spec)?;
        Ok((spec, plans, questions))
    }

    /// The design spec linked to an outline, if any.
    pub fn deck_design_spec(&self, note: EntityId) -> Result<Option<DesignSpec>> {
        let txn = self.store.env.read_txn()?;
        DESIGN_SPECS.get(&self.store, &txn, &note)
    }

    /// Create one deck from the fresh kept outline over `template`, and land
    /// it as the first version of a new artifact with its creation record.
    pub fn create_deck_from_outline(
        &self,
        request: &DeckCreateRequest<'_>,
    ) -> std::result::Result<DeckCreateOutcome, DeckCreateError> {
        self.try_with_write_txn_grouped(|txn| self.create_deck_from_outline_in_txn(txn, request))
    }

    pub(crate) fn create_deck_from_outline_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        request: &DeckCreateRequest<'_>,
    ) -> std::result::Result<DeckCreateOutcome, DeckCreateError> {
        for (_, record) in CREATIONS.scan_from(&self.store, wtxn, b"")? {
            if record.run_ref == request.run_ref && record.made_by == request.made_by {
                return Err(invalid("this deck creation run was already consumed"));
            }
        }
        let txn = &*wtxn;
        let kept = self.fresh_outline_in_txn(txn, request.outline)?;
        let limits = self.docedit_package_limits_in_txn(txn)?;
        let (book, font_inputs) = self.font_book_with_inputs_in_txn(txn, request.fonts)?;
        let bindings = self.asset_bindings_in_txn(txn, request.assets)?;
        let template_bytes = self.version_bytes_in_txn(txn, &request.template)?;
        let template = Package::open(
            &template_bytes,
            limits,
            &crate::office_body::document_resources(),
        )
        .map_err(|error| {
            // A resource refusal is the engine's error (FIX 10587), never an invalid template.
            error.resource().map_or_else(
                || invalid("template package"),
                |refusal| DeckCreateError::Vault(crate::office_body::document_refused(refusal)),
            )
        })?;
        let brief = kept_brief(&kept);
        let plan = match compile_with_fonts(&brief, &template, &bindings, &book)? {
            Outcome::Ask(decisions) => {
                return Ok(DeckCreateOutcome::Ask {
                    pages: decisions
                        .into_iter()
                        .map(|decision| decision.page)
                        .collect(),
                });
            }
            Outcome::Plan(plan) => plan,
        };
        let (records, asset_inputs) = self.asset_records_in_txn(txn, request.assets, &kept)?;
        let stored: BTreeMap<String, StoredAsset<'_>> = records
            .iter()
            .map(|(asset, (record, bytes))| {
                (
                    asset.clone(),
                    StoredAsset {
                        record,
                        bytes: Some(bytes.as_slice()),
                    },
                )
            })
            .collect();
        let candidate = emit(
            &plan,
            &EmitInputs {
                kept: brief,
                template: &template,
                assets: &stored,
                names: request.names,
                limits: GraphicLimits::default(),
            },
        )?;
        let now = self.now_recorded_at();
        let occurred = TimeRange {
            start: now,
            end: now,
        };
        let artifact = self.new_entity_id()?;
        let body =
            encode_blob_artifact_body(&BlobArtifactBody::new(request.name, PPTX_MEDIA_TYPE))?;
        let template_hash = *blake3::hash(&template_bytes).as_bytes();
        // The first version's made_by: the kept outline is the prompt, the
        // template version an input, and the replay key binds both hashes.
        let made_by = MadeBy {
            inputs: vec![
                MadeByInput {
                    row: kept.note,
                    role: MadeByInputRole::Prompt,
                },
                MadeByInput {
                    row: request.template.artifact,
                    role: MadeByInputRole::Input,
                },
            ],
            process: MadeByProcess {
                actor: request
                    .made_by
                    .unwrap_or_else(|| request.actor.entity_ref()),
                class: MadeByClass::Concluded,
                identity: "deck.create".to_owned(),
                version: "1".to_owned(),
                params_hash: blake3::hash(&[kept.content_hash, template_hash].concat())
                    .to_hex()
                    .to_string(),
            },
            at: now,
            trigger: request.trigger.clone(),
        };
        // The artifact, its first version and the creation record land in
        // one transaction, or none of them does.
        let record = {
            crate::ports::EntityStore::port_entity_put(
                self,
                wtxn,
                &artifact,
                &crate::ports::EntityRecord {
                    entity_type: ENTITY_TYPE_BLOB_ARTIFACT,
                    occurred,
                    learned_at: now,
                    row_version: 0,
                    body,
                },
            )?;
            let version = self.append_blob_artifact_version_made_by_in_txn(
                wtxn,
                &artifact,
                None,
                &candidate.bytes,
                &BlobVersionProvenance::AgentRun {
                    run_ref: request.run_ref.to_owned(),
                },
                &made_by,
                request.actor,
                occurred,
                now,
            )?;
            let record = DeckCreationRecord {
                artifact,
                version: version.version,
                content_hash: version.content_hash,
                outline: kept.note,
                outline_version: kept.version.clone(),
                outline_hash: kept.content_hash,
                template: request.template,
                template_hash,
                asset_inputs,
                font_inputs,
                run_ref: request.run_ref.to_owned(),
                made_by: request.made_by,
                slides: candidate
                    .report
                    .slides
                    .iter()
                    .map(|slide| CreatedSlide {
                        part: slide.part.clone(),
                        sld_id: slide.sld_id,
                        page: slide.page.clone(),
                        layout: slide.layout.clone(),
                    })
                    .collect(),
                write_set: candidate.report.write_set.clone(),
                omitted: candidate.report.omitted.clone(),
                fit_unverified: candidate.fit.as_ref().err().map_or_else(Vec::new, |fit| {
                    fit.units
                        .iter()
                        .map(|unit| (unit.slide.clone(), unit.block.clone(), unit.shape))
                        .collect()
                }),
                estimates: plan
                    .slides()
                    .iter()
                    .flat_map(|slide| &slide.fit.estimates)
                    .map(|estimate| CreatedEstimate {
                        block: estimate.block.clone(),
                        need: estimate.need,
                        room: estimate.room,
                        font: estimate.font.clone(),
                    })
                    .collect(),
                created_at: now,
            };
            CREATIONS.put(&self.store, wtxn, &artifact, &record)?;
            record
        };
        Ok(DeckCreateOutcome::Created(Box::new(record)))
    }

    pub(crate) fn decline_deck_outline_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        note: EntityId,
    ) -> Result<()> {
        OUTLINE_KEEPS.delete(&self.store, txn, &note)?;
        DESIGN_SPECS.delete(&self.store, txn, &note)?;
        Ok(())
    }

    pub(crate) fn deck_design_spec_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        note: EntityId,
    ) -> Result<Option<DesignSpec>> {
        DESIGN_SPECS.get(&self.store, txn, &note)
    }

    /// The creation record of a deck this engine created, if any.
    pub fn deck_creation_record(&self, artifact: EntityId) -> Result<Option<DeckCreationRecord>> {
        let txn = self.store.env.read_txn()?;
        CREATIONS.get(&self.store, &txn, &artifact)
    }
}

fn kept_brief(kept: &KeptOutline) -> KeptBrief<'_> {
    KeptBrief {
        version: &kept.version,
        content_hash: kept.content_hash,
        bytes: &kept.bytes,
    }
}

fn fallback_name(fallback: Fallback) -> String {
    match fallback {
        Fallback::OrdinaryShapes => "ordinary_shapes".to_owned(),
        Fallback::Split => "split".to_owned(),
        Fallback::Composition(composition) => format!("composition:{composition:?}"),
        Fallback::Ask => "ask".to_owned(),
    }
}

/// The outline JSON in a brief's markdown: its first `json` fenced block,
/// else the whole body.
fn outline_text(markdown: &str) -> &str {
    markdown
        .split_once("```json")
        .and_then(|(_, rest)| rest.split_once("```"))
        .map_or(markdown.trim(), |(block, _)| block.trim())
}

/// Whether two parsed outlines hold the same content: the engine's `drift`
/// flags are the evidence check's live verdict, not outline content (FIX 355).
fn outline_content_equal(held: &Value, current: &Value) -> bool {
    fn without_drift(value: &Value) -> Value {
        let mut stripped = value.clone();
        pins_mut(&mut stripped, &mut |pin| {
            // Only the engine's verdict is ignored: a cited CLAIM's pin
            // always, and a claimless note span, exactly the set
            // map_evidence_in_txn writes. A caller-owned drift flag on an
            // external or opaque pin stays content, so changing it reads as
            // an outline edit (blind review of #4387).
            let engine_mapped = note_pin(pin).is_some()
                || engine_span(pin).is_some_and(|span| span.claim.is_none());
            if engine_mapped && let Some(object) = pin.as_object_mut() {
                object.remove("drift");
            }
        });
        stripped
    }
    without_drift(held) == without_drift(current)
}
