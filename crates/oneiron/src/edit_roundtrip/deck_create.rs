//! Deck creation from an approved outline (ARCH-0077, "Create: an approved
//! argument, then a design").
//!
//! The outline is a brief NOTE (`plugin/brief`) whose markdown holds the
//! closed outline JSON, as a `json` fenced block or the whole body. A person
//! keeps it: the keep maps every evidence pin that names a cited CLAIM
//! through its note cursors (a span that no longer maps is marked drifted,
//! its quote kept), parses the result against the closed schema, and freezes
//! the note frontier, the exact outline bytes and their hash. Editing the
//! note or moving cited evidence makes the keep stale; a stale keep never
//! runs.
//!
//! Up to three design directions compile the kept outline against
//! alternative templates into one design spec linked to the outline: plans
//! summarised, never three live decks. Creation compiles against the chosen
//! template, checks the plan, emits a checked candidate and lands it as the
//! first version of a new deck artifact. Its creation record names the kept
//! outline as born-from, identifies the template, and keeps the slides,
//! write set, omitted blocks, fit status and the estimates with the faces
//! that measured them.

use std::collections::BTreeMap;

use oneiron_docedit::design_plan::{
    AssetBinding, Brief, CompileError, Fallback, KeptBrief, MediaType, Outcome, compile_with_fonts,
};
use oneiron_docedit::emit::{EmitError, EmitInputs, Names, StoredAsset, emit};
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
/// Design directions in one spec.
pub const MAX_DIRECTIONS: usize = 3;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactVersionRef {
    pub artifact: EntityId,
    pub version: u64,
}

/// A person's keep of an outline: the frontier, the exact outline bytes with
/// drift mapped at keep, and their hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeptOutline {
    pub note: EntityId,
    pub frontier: Vec<u8>,
    /// The kept version as the design plan binds it: the frontier in hex.
    pub version: String,
    pub bytes: Vec<u8>,
    pub content_hash: [u8; 32],
    pub kept_by: EntityId,
    pub kept_at: u64,
}

/// Whether a keep still describes its outline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// One design direction: a template and what the kept outline becomes on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesignDirection {
    pub template: ArtifactVersionRef,
    /// BLAKE3 of the template version's bytes.
    pub template_hash: [u8; 32],
    pub outcome: DirectionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectionSlide {
    pub page: String,
    pub layout: String,
    /// The ladder step that made the slide; `None` is the capability match.
    pub fallback: Option<String>,
}

/// The design spec linked to one kept outline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesignSpec {
    pub note: EntityId,
    /// The keep the directions were compiled from.
    pub content_hash: [u8; 32],
    pub directions: Vec<DesignDirection>,
}

/// The receipt of one created deck.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatedSlide {
    pub part: String,
    pub sld_id: u32,
    pub page: String,
    pub layout: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        let document = self.note_document(note)?;
        let mut outline: Value = serde_json::from_str(outline_text(&document.markdown))
            .map_err(|_| invalid("the brief holds no outline JSON"))?;
        self.map_evidence(&mut outline)?;
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
        };
        self.with_write_txn_grouped(|wtxn| OUTLINE_KEEPS.put(&self.store, wtxn, &note, &kept))?;
        Ok(kept)
    }

    /// The current keep of an outline, if any.
    pub fn kept_deck_outline(&self, note: EntityId) -> Result<Option<KeptOutline>> {
        let txn = self.store.env.read_txn()?;
        OUTLINE_KEEPS.get(&self.store, &txn, &note)
    }

    /// Whether the keep still describes the outline and its evidence.
    pub fn deck_outline_freshness(
        &self,
        note: EntityId,
    ) -> std::result::Result<OutlineFreshness, DeckCreateError> {
        let Some(kept) = self.kept_deck_outline(note)? else {
            return Ok(OutlineFreshness::NotKept);
        };
        if self.note_document(note)?.frontier != kept.frontier {
            return Ok(OutlineFreshness::Edited);
        }
        let held: Value =
            serde_json::from_slice(&kept.bytes).map_err(|_| invalid("kept outline encoding"))?;
        let mut remapped = held.clone();
        self.map_evidence(&mut remapped)?;
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

    /// Compile the fresh kept outline against up to three templates and
    /// store the directions as the outline's design spec.
    pub fn design_deck_directions(
        &self,
        note: EntityId,
        templates: &[ArtifactVersionRef],
        assets: &BTreeMap<String, ArtifactVersionRef>,
        fonts: &[ArtifactVersionRef],
    ) -> std::result::Result<DesignSpec, DeckCreateError> {
        if templates.is_empty() || templates.len() > MAX_DIRECTIONS {
            return Err(invalid("one to three design directions"));
        }
        let kept = self.fresh_outline(note)?;
        let limits = self.docedit_package_limits()?;
        let book = self.font_book(fonts)?;
        let bindings = self.asset_bindings(assets)?;
        let mut directions = Vec::new();
        for template in templates {
            let bytes = self.version_bytes(template)?;
            let package = Package::open(&bytes, limits).map_err(|_| invalid("template package"))?;
            let outcome = compile_with_fonts(&kept_brief(&kept), &package, &bindings, &book)?;
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
        self.with_write_txn_grouped(|wtxn| DESIGN_SPECS.put(&self.store, wtxn, &note, &spec))?;
        Ok(spec)
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
        let kept = self.fresh_outline(request.outline)?;
        let limits = self.docedit_package_limits()?;
        let book = self.font_book(request.fonts)?;
        let bindings = self.asset_bindings(request.assets)?;
        let template_bytes = self.version_bytes(&request.template)?;
        let template =
            Package::open(&template_bytes, limits).map_err(|_| invalid("template package"))?;
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
        let records = self.asset_records(request.assets, &kept)?;
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
        let record = self.with_write_txn_grouped(|wtxn| {
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
            Ok(record)
        })?;
        Ok(DeckCreateOutcome::Created(Box::new(record)))
    }

    /// The creation record of a deck this engine created, if any.
    pub fn deck_creation_record(&self, artifact: EntityId) -> Result<Option<DeckCreationRecord>> {
        let txn = self.store.env.read_txn()?;
        CREATIONS.get(&self.store, &txn, &artifact)
    }

    fn fresh_outline(&self, note: EntityId) -> std::result::Result<KeptOutline, DeckCreateError> {
        match self.deck_outline_freshness(note)? {
            OutlineFreshness::Fresh => {}
            OutlineFreshness::NotKept => return Err(invalid("the outline is not kept")),
            OutlineFreshness::Edited => {
                return Err(invalid("the outline changed after its keep; keep it again"));
            }
            OutlineFreshness::EvidenceMoved { .. } => {
                return Err(invalid(
                    "cited evidence moved after the keep; keep it again",
                ));
            }
        }
        self.kept_deck_outline(note)?
            .ok_or_else(|| invalid("the outline is not kept"))
    }

    /// Set each evidence pin's `drift` from its note cursors. A pin without
    /// a cited CLAIM, or whose ids and cursors are not this engine's, keeps
    /// the caller's flag.
    fn map_evidence(&self, outline: &mut Value) -> std::result::Result<(), DeckCreateError> {
        let mut result = Ok(());
        pins_mut(outline, &mut |pin| {
            if result.is_err() {
                return;
            }
            let Some(note_pin) = note_pin(pin) else {
                return;
            };
            let drifted = !matches!(
                self.resolve_note_pin(&note_pin),
                Ok(NoteSpanResolution::Mapped { .. })
            );
            if let Some(object) = pin.as_object_mut() {
                object.insert("drift".to_owned(), Value::Bool(drifted));
            } else {
                result = Err(invalid("evidence pin is not an object"));
            }
        });
        result
    }

    fn version_bytes(&self, at: &ArtifactVersionRef) -> Result<Vec<u8>> {
        self.read_blob_artifact_version(&at.artifact, at.version)?
            .ok_or(Error::EntityNotFound)
    }

    fn font_book(
        &self,
        fonts: &[ArtifactVersionRef],
    ) -> std::result::Result<FontBook, DeckCreateError> {
        let mut book = FontBook::new();
        for font in fonts {
            book.add(self.version_bytes(font)?)?;
        }
        Ok(book)
    }

    fn asset_bindings(
        &self,
        assets: &BTreeMap<String, ArtifactVersionRef>,
    ) -> std::result::Result<BTreeMap<String, AssetBinding>, DeckCreateError> {
        assets
            .iter()
            .map(|(asset, at)| {
                Ok((
                    asset.clone(),
                    AssetBinding {
                        handle: at.artifact.to_hex(),
                        media: self.asset_media(at)?,
                    },
                ))
            })
            .collect()
    }

    fn asset_media(
        &self,
        at: &ArtifactVersionRef,
    ) -> std::result::Result<MediaType, DeckCreateError> {
        let body = self
            .get_blob_artifact(&at.artifact)?
            .ok_or(Error::EntityNotFound)?;
        match body.media_type.as_str() {
            "image/png" => Ok(MediaType::Png),
            "image/jpeg" => Ok(MediaType::Jpeg),
            "image/svg+xml" => Ok(MediaType::Svg),
            _ => Err(invalid("an asset must be PNG, JPEG or SVG")),
        }
    }

    /// Held assets as admitted records with their bytes; the description is
    /// the brief's intended content for the asset.
    fn asset_records(
        &self,
        assets: &BTreeMap<String, ArtifactVersionRef>,
        kept: &KeptOutline,
    ) -> std::result::Result<BTreeMap<String, (AssetRecord, Vec<u8>)>, DeckCreateError> {
        let brief = Brief::parse(&kept.bytes).map_err(CompileError::from)?;
        let mut out = BTreeMap::new();
        for (asset, at) in assets {
            let metadata = self
                .blob_artifact_version_metadata(&at.artifact, at.version)?
                .ok_or(Error::EntityNotFound)?;
            let description = brief
                .assets
                .iter()
                .find(|held| held.id == *asset)
                .map(|held| held.content.clone())
                .ok_or_else(|| invalid("a bound asset is not in the outline"))?;
            out.insert(
                asset.clone(),
                (
                    AssetRecord {
                        artifact: at.artifact.to_hex(),
                        version: at.version,
                        content_hash: metadata.content_hash,
                        media: self.asset_media(at)?,
                        origin: Origin::Held,
                        provenance: vec![format!(
                            "blob:{}@{}:{}",
                            at.artifact.to_hex(),
                            at.version,
                            metadata.provenance.as_str()
                        )],
                        rights: Vec::new(),
                        description,
                    },
                    self.version_bytes(at)?,
                ),
            );
        }
        Ok(out)
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

/// A pin this engine can map: a cited CLAIM and a note document by entity
/// id, its frontier and cursors in hex.
fn note_pin(pin: &Value) -> Option<NotePin> {
    let text = |key: &str| pin.get(key).and_then(Value::as_str);
    let quote_hash = unhex(text("quote_hash")?)?;
    Some(NotePin {
        claim: EntityId::from_hex(text("claim")?).ok()?,
        document: EntityId::from_hex(text("document")?).ok()?,
        frontier: unhex(text("version")?)?,
        start_cursor: unhex(text("start")?)?,
        end_cursor: unhex(text("end")?)?,
        quote_hash: quote_hash.try_into().ok()?,
        quote_text: text("quote")?.to_owned(),
    })
}

/// Every evidence pin in document order: an object with a quote hash.
fn pins(value: &Value, visit: &mut impl FnMut(&Value)) {
    match value {
        Value::Object(map) if map.contains_key("quote_hash") => visit(value),
        Value::Object(map) => map.values().for_each(|child| pins(child, visit)),
        Value::Array(items) => items.iter().for_each(|child| pins(child, visit)),
        _ => {}
    }
}

fn pins_mut(value: &mut Value, visit: &mut impl FnMut(&mut Value)) {
    match value {
        Value::Object(map) if map.contains_key("quote_hash") => visit(value),
        Value::Object(map) => map.values_mut().for_each(|child| pins_mut(child, visit)),
        Value::Array(items) => items.iter_mut().for_each(|child| pins_mut(child, visit)),
        _ => {}
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
        .collect()
}
