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
use oneiron_docedit::emit::{EmitError, EmitInputs, Names, StoredAsset, check_template, emit};
use oneiron_docedit::fonts::{FontBook, FontError};
use oneiron_docedit::graphic::{AssetRecord, GraphicLimits, Origin};
use oneiron_docedit::retained_opc::Package;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::blob_artifact::{BlobArtifactBody, BlobVersionProvenance, encode_blob_artifact_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::note::{NotePin, NoteSpanResolution};
use crate::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess, MadeByTrigger,
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
    OUTLINE_KEEPS.delete(store, txn, entity)?;
    DESIGN_SPECS.delete(store, txn, entity)?;
    CREATIONS.delete(store, txn, entity)?;
    super::deck::erase_in_txn(store, txn, entity)
}

/// One blob artifact version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactVersionRef {
    pub artifact: EntityId,
    pub version: u64,
}

/// A person's keep of an outline: the frontier, the exact outline bytes with
/// drift mapped at keep, and their hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct KeptOutline {
    pub note: EntityId,
    pub frontier: Vec<u8>,
    /// The kept version as the design plan binds it: the frontier in hex.
    pub version: String,
    pub bytes: Vec<u8>,
    pub content_hash: [u8; 32],
    pub kept_by: EntityId,
    pub kept_at: u64,
    /// What the engine observed of each pin it can address at the keep,
    /// outside the bytes and their hash (FIX 9813, 9814).
    #[serde(default)]
    pub evidence: Vec<EvidenceObservation>,
}

/// Whether a keep still describes its outline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutlineFreshness {
    Fresh,
    NotKept,
    /// The note changed after the keep.
    Edited,
    /// Cited evidence moved: these pins, in document order, map differently.
    EvidenceMoved {
        pins: Vec<usize>,
    },
}

/// A cited CLAIM's lifecycle as the engine observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CitedClaimLifecycle {
    Active,
    Superseded,
    Retracted,
}

/// What the engine observed of one evidence pin it can address: a note
/// document span, with or without a cited CLAIM (FIX 9813, 9814).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceObservation {
    /// The pin, in document order, as [`OutlineFreshness::EvidenceMoved`]
    /// counts them.
    pub pin: usize,
    /// The cited document's frontier; `None` once it no longer resolves.
    pub source_frontier: Option<Vec<u8>>,
    /// The cited CLAIM's lifecycle; `None` when the pin names none or it no
    /// longer reads.
    pub lifecycle: Option<CitedClaimLifecycle>,
    /// Whether the span still maps onto live characters with its quote.
    pub mapped: bool,
}

/// One pin whose evidence changed since the keep: what the keep saw, and
/// what the engine sees now. It is reported, never a keep to make again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EvidenceChange {
    pub kept: EvidenceObservation,
    pub now: EvidenceObservation,
}

/// One design direction: a template and what the kept outline becomes on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignDirection {
    pub template: ArtifactVersionRef,
    /// BLAKE3 of the template version's bytes.
    pub template_hash: [u8; 32],
    pub outcome: DirectionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectionOutcome {
    Plan {
        slides: Vec<DirectionSlide>,
        /// Optional blocks the plan leaves out.
        omitted: Vec<String>,
        /// Estimates a real face measured, and those the em rule made.
        measured: usize,
        estimated: usize,
    },
    /// Pages no layout rung holds: another template or a design change.
    Ask { pages: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DirectionSlide {
    pub page: String,
    pub layout: String,
    /// The ladder step that made the slide; `None` is the capability match.
    pub fallback: Option<String>,
}

/// The design spec linked to one kept outline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DesignSpec {
    pub note: EntityId,
    /// The keep the directions were compiled from.
    pub content_hash: [u8; 32],
    pub directions: Vec<DesignDirection>,
}

/// The receipt of one created deck.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DeckCreationRecord {
    pub artifact: EntityId,
    pub version: u64,
    pub content_hash: [u8; 32],
    /// Born-from: the kept outline.
    pub outline: EntityId,
    pub outline_version: String,
    pub outline_hash: [u8; 32],
    pub template: ArtifactVersionRef,
    pub template_hash: [u8; 32],
    pub run_ref: String,
    pub made_by: Option<EntityId>,
    pub slides: Vec<CreatedSlide>,
    pub write_set: Vec<String>,
    pub omitted: Vec<String>,
    /// Units whose fit emission cannot decide: `(slide, block, shape)`.
    pub fit_unverified: Vec<(String, String, u32)>,
    pub estimates: Vec<CreatedEstimate>,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CreatedSlide {
    pub part: String,
    pub sld_id: u32,
    pub page: String,
    pub layout: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CreatedEstimate {
    pub block: String,
    pub need: i64,
    pub room: i64,
    /// The face that measured it; `None` for the em rule.
    pub font: Option<String>,
}

/// One creation run.
#[derive(Debug, Clone)]
pub struct DeckCreateRequest<'a> {
    pub outline: EntityId,
    pub template: ArtifactVersionRef,
    /// Brief asset id to the held PNG, JPEG or SVG version it binds.
    pub assets: &'a BTreeMap<String, ArtifactVersionRef>,
    /// Font files (TrueType, OpenType or collections) to measure text with.
    pub fonts: &'a [ArtifactVersionRef],
    pub names: Names<'a>,
    /// The new artifact's name.
    pub name: &'a str,
    pub run_ref: &'a str,
    pub made_by: Option<EntityId>,
    /// The task or ask the creation answers: the deck's born-from.
    pub trigger: Option<MadeByTrigger>,
    pub actor: WriteActor,
}

#[derive(Debug, Clone)]
pub enum DeckCreateOutcome {
    Created(Box<DeckCreationRecord>),
    /// Pages no rung holds; nothing was written.
    Ask {
        pages: Vec<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum DeckCreateError {
    #[error(transparent)]
    Vault(#[from] Error),
    #[error("the outline is not usable: {0}")]
    Outline(&'static str),
    #[error(transparent)]
    Compile(#[from] CompileError),
    #[error(transparent)]
    Emit(#[from] EmitError),
    #[error(transparent)]
    Font(#[from] FontError),
}

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
        if crate::note::deck_outline_document_in_txn(self, txn, note)?.frontier != kept.frontier {
            return Ok(OutlineFreshness::Edited);
        }
        let held: Value =
            serde_json::from_slice(&kept.bytes).map_err(|_| invalid("kept outline encoding"))?;
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
        let book = self.font_book_in_txn(txn, request.fonts)?;
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
        let records = self.asset_records_in_txn(txn, request.assets, &kept)?;
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
