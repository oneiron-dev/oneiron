//! `vault.artifacts.body.deck.preview`: the asked slides of a deck's head,
//! or of an open fork's merge candidate over the head (the deck
//! `vault.artifacts.body.deck.review` reviews), drawn by the host's review
//! renderer (ARCH-0077 "Review images") from the export that deck projects
//! now ([`crate::Vault::export_pptx_body`]). Nothing lands and nothing is
//! proposed, whatever the export gate says. The images are provisional: a
//! review renderer's drawing is neither the PowerPoint oracle's evidence nor
//! a reason to open the gate. An embedded vault has no renderer, so it
//! refuses.
//!
//! Drawn slides are kept by the vault, the export's memo key, the renderer
//! and the draw's view ([`DRAWN`]): a call on an unchanged deck projects and
//! converts nothing, and draws only the slides no earlier call drew.
//!
//! A deck whose drawing holds a lifted secret draws for the vault owner, and
//! for an agent that says `why` once a grant covers its keys, judged on every
//! read, a kept drawing's included (OF-067, FIX 2941). Every other reader is
//! refused, any ask its read filed kept. The keys judged are those of what
//! is drawn, read in the snapshot the deck is (FIX 9994, 9995): its texts',
//! and those the marks of the retained package it draws over, of that
//! package's parts and of each picture it resolves name. A text, a picture,
//! and a mark in the package or a part count only where the asked slides
//! draw them (FIX 10453, FIX 12234).
//!
//! The memory a preview allocates is admitted to the host's renderer before
//! it is (FIX 7653, [`SlideRenderer::admit`]): the copy the package keeps,
//! the export, the kept drawings it copies and each slide's base64. Each is
//! named allocated, at what it came to, once made, and bytes read before
//! their size was known (the package, each picture) are named allocated as
//! read, with no wait (FIX 8240, [`SlideRenderer::materialized`]). Every
//! named slide is still drawn; only a real floor or the render's deadline
//! refuses, typed by the host.
mod drawn_parts;

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{live, open_record};
use crate::Vault;
use crate::edit_roundtrip::VaultAssets;
use crate::edit_roundtrip::slides_review::{SlideRenderer, review_image_key};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::record_references::admit_row_references;
use crate::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult,
};
use crate::secret_custody::SecretSight;
use crate::typed_body::LiftedSources;
use drawn_parts::{PackageMarks, drawn_nodes, drawn_parts, drawn_pictures, drawn_strings};
use oneiron_docedit::deck::DeckView;
use oneiron_docedit::edit::transaction::{AssetRef, Assets};
use oneiron_docedit::graphic::AssetRecord;
use oneiron_docedit::live::deck_export::export_key;
use oneiron_docedit::live::{
    ExportKey, ExportOutcome, ExportProfile, HeldAssets, LiveDeck, project,
};
use oneiron_docedit::retained_opc::Package;

const ROW: &str = "vault.artifacts.body.deck.preview";

/// The most image bytes [`DRAWN`] holds, across every vault and deck; past
/// it the least recently read export's slides go first (CALLS "OF-510 deck
/// preview cache"). A budget for what is kept, never for what is drawn: a
/// preview past it still answers every slide it names.
const DRAWN_BYTES: usize = 64 << 20;

/// How long an export's drawn slides stay in [`DRAWN`] once no call reads
/// them (CALLS "OF-510 deck preview cache").
const DRAWN_IDLE: Duration = Duration::from_secs(30 * 60);

/// The drawn slides of one vault's export under one renderer, for one view:
/// the vault's id, the export's memo key hash, the renderer's name and the
/// [`DrawView`].
type Slot = ([u8; 32], [u8; 32], String, DrawView);

/// Whom a drawing is kept for (FIX 2941). A reader masked from lifted keys
/// never selects a drawing made for the owner or a granted agent; the view
/// separates output only, and grants nothing: each read is judged first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DrawView {
    /// Drawn for the owner, or for an agent a grant covers on this read.
    Raw,
    /// Drawn for a reader masked from lifted keys: a deck that holds none.
    Masked,
}

/// The slides previews drew, by [`Slot`]. Held in memory only: a restart
/// draws again.
static DRAWN: Mutex<Drawn> = Mutex::new(Drawn {
    entries: BTreeMap::new(),
    bytes: 0,
});

/// `vault.artifacts.body.deck.preview`: the slides to draw, each named once,
/// 1-based in the deck's order (hidden slides count).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeckPreviewRequest {
    pub artifact_ref: String,
    /// An open fork of the deck: its merge candidate over the head is drawn,
    /// as `vault.artifacts.body.deck.review` reviews it, instead of the head.
    #[serde(default)]
    pub fork_ref: Option<String>,
    pub slides: Vec<u64>,
    /// Why an agent needs a deck whose text holds a lifted secret drawn:
    /// with it, the deck draws for that agent once a grant covers its keys,
    /// for this read alone, and its ask goes to the owner otherwise.
    #[serde(default)]
    pub why: Option<String>,
}

/// The slides a deck preview drew, and the projection they show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckPreview {
    /// The head the export projected; for a fork, the head its candidate
    /// replays onto.
    pub frontier: Vec<u8>,
    pub profile: String,
    pub projector: String,
    /// BLAKE3 of the export's memo key, in hex.
    pub export_key: String,
    /// The renderer's identity: its version and raster settings.
    pub renderer: String,
    /// Always true: fonts, autofit and image effects differ from
    /// PowerPoint's.
    pub provisional: bool,
    pub slides: Vec<DeckPreviewSlide>,
}

/// One drawn slide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckPreviewSlide {
    pub slide: u64,
    /// `image/png`, or `image/jpeg`.
    pub media_type: String,
    /// The image's BLAKE3 in hex, as a review image is keyed.
    pub image_hash: String,
    pub content_base64: String,
}

impl Memory<'_> {
    /// `vault.artifacts.body.deck.preview`: draw the asked slides of the
    /// deck's head, or of a fork's merge candidate, with the host's review
    /// renderer, `None` where there is none. Slides an earlier call drew of
    /// the same export for the same view are not drawn again. A deck whose
    /// text holds a lifted secret draws for the owner, and for an agent that
    /// says `why` once a grant covers its keys on this read; it is refused to
    /// every other reader, any ask the read filed kept (FIX 2941).
    pub fn artifacts_body_deck_preview(
        &self,
        input: &DeckPreviewRequest,
        renderer: Option<&dyn SlideRenderer>,
    ) -> MemoryResult<DeckPreview> {
        let Some(renderer) = renderer else {
            return Err(MemoryError::new(
                MEMORY_CODE_MODEL_UNAVAILABLE,
                format!("{ROW} draws with a host's review renderer, and this vault has none"),
                &["Call it through a server with LibreOffice (soffice) and pdftoppm on its PATH."],
            ));
        };
        // Every slide named is drawn, however many (FIX 6565, Rule 5).
        if input.slides.is_empty() {
            return Err(MemoryError::bad_request(format!(
                "{ROW} names at least one slide"
            )));
        }
        admit_row_references(self, ROW, input, &["/artifact_ref", "/fork_ref"])?;
        let artifact = self.body_ref(&input.artifact_ref)?;
        let fork = input
            .fork_ref
            .as_deref()
            .map(|fork| self.body_ref(fork))
            .transpose()?;
        // A drawn slide cannot show a lifted key as its handle: a deck that
        // holds one draws for the owner, or for an agent a grant covers that
        // says why (OF-067, FIX 2941).
        let masked = self.reads_lifted_keys_masked()?;
        let vault = self.vault();
        let projection =
            vault.deck_projection(&artifact, fork.as_ref(), &input.slides, renderer)?;
        let key = projection.key.hash();
        // Whether this read needs sight is the snapshot drawn's to say, its
        // texts, retained package, parts and pictures (FIX 9995, 9994), each
        // where the asked slides draw it (FIX 10453, FIX 12234), and it is
        // judged on this read before a kept drawing is read or one drawn.
        let held_back = masked && !projection.lifted.is_empty();
        let view = if !masked {
            DrawView::Raw
        } else if !held_back {
            DrawView::Masked
        } else if input.why.is_none() {
            return Err(lifted_refusal());
        } else if self.typed_body_read_sight(
            &artifact,
            &key,
            &projection.lifted,
            input.why.as_deref(),
        )? == SecretSight::Granted
        {
            DrawView::Raw
        } else {
            return Err(lifted_refusal());
        };
        let slot: Slot = (
            *vault.vault_id().as_bytes(),
            key,
            renderer.name().to_owned(),
            view,
        );
        // The kept drawings this call takes are admitted before they are
        // copied, outside the cache's lock (FIX 7653); one the cache changed
        // meanwhile past that room is drawn again instead.
        let room = DRAWN
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .held_bytes(&slot, &input.slides);
        if room > 0 {
            renderer.admit(len(room))?;
        }
        let held = DRAWN.lock().unwrap_or_else(PoisonError::into_inner).held(
            &slot,
            &input.slides,
            room,
            Instant::now(),
        );
        // The copies taken are named allocated, outside the cache's lock, and
        // the room they did not use, a miss's whole, given back (FIX 8240).
        if room > 0 {
            let copied = held.as_ref().map_or(0, |(_, images, _)| {
                images.values().map(Vec::len).fold(0, usize::saturating_add)
            });
            renderer.materialized(len(room), len(copied));
        }
        // The rows the answer is drawn from (FIX 5455): the package the deck
        // projects over, read now, and the live-born pictures' assets of the
        // export the slides were drawn from, which a held entry kept.
        let mut listed = projection.rows.clone();
        let (count, mut images, export) = match held {
            Some((count, images, rows)) => {
                listed.extend(rows);
                (count, images, None)
            }
            None => {
                let (export, assets) = vault.project_preview(&artifact, &projection, renderer)?;
                let count = Package::open(
                    &export.bytes,
                    vault.docedit_package_limits()?,
                    &crate::office_body::document_resources(),
                )
                .ok()
                .and_then(|package| DeckView::read(&package).ok())
                .map(|view| u64::try_from(view.slides.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| failed("the deck's export could not be read back"))?;
                (count, BTreeMap::new(), Some((export, assets)))
            }
        };
        let mut named = BTreeSet::new();
        for &slide in &input.slides {
            if slide == 0 || slide > count || !named.insert(slide) {
                return Err(MemoryError::bad_request(format!(
                    "slide {slide} is not one of the deck's {count} slides, or is named twice"
                )));
            }
        }
        let missing: Vec<u64> = input
            .slides
            .iter()
            .copied()
            .filter(|slide| !images.contains_key(slide))
            .collect();
        // The slides drawn now, and the rows they were drawn from, for the
        // cache.
        let mut fresh = None;
        if !missing.is_empty() {
            let (export, assets) = match export {
                Some(export) => export,
                None => vault.project_preview(&artifact, &projection, renderer)?,
            };
            let drawn = renderer.render(&export.bytes, &missing)?;
            if drawn.len() != missing.len() {
                return Err(failed("the renderer drew another number of slides"));
            }
            let kept = [projection.rows.as_slice(), assets.as_slice()].concat();
            fresh = Some((missing.clone(), kept));
            listed.extend(assets);
            images.extend(missing.into_iter().zip(drawn));
        }
        let slides = input
            .slides
            .iter()
            .map(|&slide| {
                let image = images
                    .get(&slide)
                    .ok_or_else(|| failed("a named slide was not drawn"))?;
                // Its base64 is admitted before it is made (FIX 7653), and
                // named allocated, at its length, once it is (FIX 8240).
                let estimate = base64_bytes(image.len());
                renderer.admit(estimate)?;
                let content_base64 = base64::engine::general_purpose::STANDARD.encode(image);
                renderer.materialized(estimate, len(content_base64.len()));
                Ok(DeckPreviewSlide {
                    slide,
                    media_type: if image.starts_with(&[0xFF, 0xD8, 0xFF]) {
                        "image/jpeg"
                    } else {
                        "image/png"
                    }
                    .to_owned(),
                    image_hash: review_image_key(image),
                    content_base64,
                })
            })
            .collect::<MemoryResult<Vec<_>>>();
        // The slides drawn now are kept for a later call, moved into the
        // cache once the answer is made rather than copied, so keeping them
        // allocates nothing past what was admitted (FIX 7653).
        if let Some((drawn, kept)) = fresh {
            let drawn = drawn
                .into_iter()
                .filter_map(|slide| Some((slide, images.remove(&slide)?)))
                .collect();
            DRAWN.lock().unwrap_or_else(PoisonError::into_inner).keep(
                slot,
                count,
                drawn,
                kept,
                Instant::now(),
            );
        }
        let slides = slides?;
        self.produced_from(listed);
        Ok(DeckPreview {
            frontier: projection.frontier,
            export_key: blake3::Hash::from(key).to_hex().to_string(),
            profile: projection.key.profile,
            projector: projection.key.projector,
            renderer: renderer.name().to_owned(),
            provisional: true,
            slides,
        })
    }
}

/// The deck a preview draws, the package it projects over, and the export's
/// memo key, read before anything is projected.
struct Projection {
    /// The head the deck reads at; a fork's candidate replays onto it.
    frontier: Vec<u8>,
    deck: LiveDeck,
    package: Package,
    key: ExportKey,
    /// The rows `package` was read as: its retained or imported version's
    /// CLAIM and ASSET (FIX 5455).
    rows: Vec<EntityId>,
    /// The keys what is drawn holds, read in the snapshot the deck was: its
    /// lifted texts' (FIX 2941), and those the marks of the retained package,
    /// of its parts and of each resolved picture name (FIX 9994), each where
    /// the asked slides draw it (FIX 10453, FIX 12234).
    lifted: LiftedSources,
    /// The bytes of the package `package` was read from.
    source_bytes: u64,
    /// The live-born pictures' assets, resolved in that snapshot: the
    /// export draws exactly the bytes whose marks were judged.
    assets: HeldAssets,
    /// The rows each resolved asset is (FIX 5455).
    asset_rows: Vec<EntityId>,
    /// The picture bytes resolved.
    pictures: u64,
}

impl Vault {
    /// The deck at its head, or with `fork` that open fork's actual merged
    /// candidate over the head, as [`Vault::pptx_body_fork_review`] reads it,
    /// judged for the asked `slides`. The package's bytes are admitted to
    /// `renderer` (FIX 7653).
    fn deck_projection(
        &self,
        artifact: &EntityId,
        fork: Option<&EntityId>,
        slides: &[u64],
        renderer: &dyn SlideRenderer,
    ) -> Result<Projection> {
        let source = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let (head, retained, deck, (lifted, narrowed, marks), (assets, asset_rows, pictures)) = {
            let txn = self.store.env.read_txn()?;
            let texts = self.typed_body_lifted_sources_in_txn(&txn, artifact)?;
            let (head, body) = self.deck_head(&txn, artifact)?;
            let candidate = match fork {
                Some(fork) => {
                    let record = open_record(&self.store, &txn, artifact, fork)?;
                    let work = self.deck_fork(&txn, &record)?;
                    let report = self.deck_preflight(&txn, artifact, &body.deck, &record, &work)?;
                    Some(report.candidate)
                }
                None => None,
            };
            let retained = body.retained;
            let deck = candidate.unwrap_or(body.deck);
            let listing = ListingAssets {
                held: VaultAssets {
                    vault: self,
                    txn: &txn,
                },
                rows: RefCell::new(Vec::new()),
                renderer,
                admitted: Cell::new(0),
                files: RefCell::new(Vec::new()),
            };
            let assets = HeldAssets::resolve(&listing, &[&deck]);
            // What the drawing is made of besides the texts: the retained
            // package by its pinned hash, each part as the deck pins it, and
            // each picture's bytes (FIX 9994). The package's and the parts'
            // marks count where the asked slides draw them (FIX 10453).
            let pinned = retained.map_or(source.source_hash, |retained| retained.hash);
            let marks = PackageMarks::read_in_txn(&self.store, &txn, &pinned, &deck)?;
            let files = listing.files.take();
            let lifted = self.lifted_sources_with_files_in_txn(&txn, texts, &files)?;
            // The texts' and the pictures' keys where the asked slides draw
            // them, read in the same snapshot (FIX 12234); `None` where the
            // mapping cannot tell, so the drawing judges every text and
            // picture as before.
            let narrowed = drawn_nodes(&deck, slides)
                .map(|drawn| {
                    let texts = self.typed_body_lifted_sources_drawn_in_txn(
                        &txn,
                        artifact,
                        &drawn_strings(&deck, &drawn),
                    )?;
                    let mut hashes = BTreeSet::new();
                    for image in drawn_pictures(&deck, &drawn) {
                        if let Some((_, bytes)) = assets.resolve(&image) {
                            hashes.insert(*blake3::hash(&bytes).as_bytes());
                        }
                    }
                    self.lifted_sources_with_files_in_txn(
                        &txn,
                        texts,
                        &hashes.into_iter().collect::<Vec<_>>(),
                    )
                })
                .transpose()?;
            let resolved = (assets, listing.rows.into_inner(), listing.admitted.get());
            (head, retained, deck, (lifted, narrowed, marks), resolved)
        };
        let (bytes, rows) = self.deck_source_listing(artifact, &source, retained)?;
        // The package, its size known only once read whole, is named
        // allocated as read; the copy its retained form keeps is admitted
        // before it is made, and named allocated once it is (FIX 8240).
        let source_bytes = len(bytes.len());
        renderer.materialized(0, source_bytes);
        renderer.admit(source_bytes)?;
        let package = Package::open(
            &bytes,
            self.docedit_package_limits()?,
            &crate::office_body::document_resources(),
        )
        .map_err(|error| {
            crate::office_body::document_error(
                error.resource(),
                "the PPTX package could not be read",
            )
        })?;
        renderer.materialized(source_bytes, source_bytes);
        // The narrowed texts and pictures count where the parts mapping
        // tells too; where it cannot (a live-born slide, an unreadable
        // archive) every text and picture counts as before (FIX 12234).
        let base = match (narrowed, drawn_parts(&deck, slides, &package).is_some()) {
            (Some(narrowed), true) => narrowed,
            _ => lifted,
        };
        let lifted = base.with_keys(marks.drawn_keys(&deck, slides, &package, &bytes));
        let key = export_key(
            &deck,
            &package,
            &artifact.to_hex(),
            &ExportProfile::default(),
        )
        .map_err(live)?;
        Ok(Projection {
            frontier: head.frontier,
            deck,
            package,
            key,
            rows,
            lifted,
            source_bytes,
            assets,
            asset_rows,
            pictures,
        })
    }

    /// The export `projection` keys, over the pictures it resolved in its
    /// snapshot, beside the rows each is (FIX 5455). The export is admitted
    /// before it is made (FIX 7653, FIX 8240).
    fn project_preview(
        &self,
        artifact: &EntityId,
        projection: &Projection,
        renderer: &dyn SlideRenderer,
    ) -> Result<(ExportOutcome, Vec<EntityId>)> {
        // The export writes the package's parts and its pictures again: that
        // much is admitted before it is made, and what it came to named
        // allocated in its place once it is (FIX 8240).
        let estimate = projection.source_bytes.saturating_add(projection.pictures);
        renderer.admit(estimate)?;
        let export = project(
            &projection.deck,
            &projection.package,
            &artifact.to_hex(),
            &ExportProfile::default(),
            &projection.assets,
        )
        .map_err(live)?;
        renderer.materialized(estimate, len(export.bytes.len()));
        Ok((export, projection.asset_rows.clone()))
    }
}

/// [`VaultAssets`], listing the rows of each picture asset it resolves: the
/// image artifact, the version CLAIM and the ASSET, read in its transaction.
/// Each picture's bytes are named allocated to the renderer as soon as they
/// are read, with no wait (FIX 7653, FIX 8240).
struct ListingAssets<'v, 't, 'r> {
    held: VaultAssets<'v, 't>,
    rows: RefCell<Vec<EntityId>>,
    renderer: &'r dyn SlideRenderer,
    /// The picture bytes read so far.
    admitted: Cell<u64>,
    /// The BLAKE3 of each picture's bytes, whose marks the read judges.
    files: RefCell<Vec<[u8; 32]>>,
}

impl Assets for ListingAssets<'_, '_, '_> {
    fn resolve(&self, asset: &AssetRef) -> Option<(AssetRecord, Vec<u8>)> {
        let resolved = self.held.resolve(asset)?;
        let artifact = EntityId::from_hex(&resolved.0.artifact).ok()?;
        let version = self
            .held
            .vault
            .blob_artifact_version_metadata_in_txn(self.held.txn, &artifact, resolved.0.version)
            .ok()??;
        let asset_row =
            crate::blob_artifact::blob_artifact_asset_entity_id(&version.content_hash).ok()?;
        let bytes = len(resolved.1.len());
        self.renderer.materialized(0, bytes);
        self.admitted.set(self.admitted.get().saturating_add(bytes));
        self.rows
            .borrow_mut()
            .extend([artifact, version.claim_id, asset_row]);
        self.files
            .borrow_mut()
            .push(*blake3::hash(&resolved.1).as_bytes());
        Some(resolved)
    }
}

/// The drawn slides, and the image bytes they hold.
struct Drawn {
    entries: BTreeMap<Slot, Entry>,
    bytes: usize,
}

/// One export's drawn slides under one renderer.
struct Entry {
    /// The export's slide count.
    slides: u64,
    images: BTreeMap<u64, Vec<u8>>,
    read_at: Instant,
    /// The rows the drawn export was read from: its package's version and
    /// each live-born picture's asset (FIX 5455). Ids only.
    rows: BTreeSet<EntityId>,
}

impl Entry {
    fn bytes(&self) -> usize {
        self.images.values().map(Vec::len).sum()
    }
}

impl Drawn {
    /// The bytes of the drawings of `asked` it holds for `slot`, counted
    /// without copying them, so the copies [`Self::held`] makes are admitted
    /// first (FIX 7653).
    fn held_bytes(&self, slot: &Slot, asked: &[u64]) -> usize {
        self.entries.get(slot).map_or(0, |entry| {
            asked
                .iter()
                .filter_map(|slide| entry.images.get(slide))
                .map(Vec::len)
                .fold(0, usize::saturating_add)
        })
    }

    /// The export's slide count, those of `asked` it holds drawn that fit in
    /// `room` bytes, and the rows they were drawn from, when it holds the
    /// export; entries idle past [`DRAWN_IDLE`] go first. A drawing past
    /// `room` is left out, to be drawn again.
    fn held(
        &mut self,
        slot: &Slot,
        asked: &[u64],
        room: usize,
        now: Instant,
    ) -> Option<(u64, BTreeMap<u64, Vec<u8>>, Vec<EntityId>)> {
        let mut freed = 0;
        self.entries.retain(|_, entry| {
            let kept = now.duration_since(entry.read_at) < DRAWN_IDLE;
            if !kept {
                freed += entry.bytes();
            }
            kept
        });
        self.bytes = self.bytes.saturating_sub(freed);
        let entry = self.entries.get_mut(slot)?;
        entry.read_at = now;
        let mut left = room;
        let images = asked
            .iter()
            .filter_map(|&slide| {
                let image = entry.images.get(&slide)?;
                left = left.checked_sub(image.len())?;
                Some((slide, image.clone()))
            })
            .collect();
        Some((entry.slides, images, entry.rows.iter().copied().collect()))
    }

    /// Keep `drawn`, moved in, for the export of `slides` slides, beside the
    /// rows it was drawn from; past [`DRAWN_BYTES`], the least recently read
    /// exports go.
    fn keep(
        &mut self,
        slot: Slot,
        slides: u64,
        drawn: Vec<(u64, Vec<u8>)>,
        rows: Vec<EntityId>,
        now: Instant,
    ) {
        let entry = self.entries.entry(slot).or_insert_with(|| Entry {
            slides,
            images: BTreeMap::new(),
            read_at: now,
            rows: BTreeSet::new(),
        });
        entry.read_at = now;
        entry.rows.extend(rows);
        for (slide, image) in drawn {
            self.bytes = self.bytes.saturating_add(image.len());
            if let Some(old) = entry.images.insert(slide, image) {
                self.bytes = self.bytes.saturating_sub(old.len());
            }
        }
        while self.bytes > DRAWN_BYTES {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.read_at)
                .map(|(slot, _)| slot.clone())
            else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(entry.bytes());
            }
        }
    }
}

/// `n` bytes, as a renderer admits them.
fn len(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// The bytes `n` image bytes take as base64: four for each three begun, or
/// every byte there is when that does not fit.
fn base64_bytes(n: usize) -> u64 {
    u64::try_from(n)
        .ok()
        .and_then(|n| n.div_ceil(3).checked_mul(4))
        .unwrap_or(u64::MAX)
}

/// A lifted deck read by a reader no grant opens it to on this read.
fn lifted_refusal() -> MemoryError {
    MemoryError::bad_request(format!(
        "{ROW} draws a deck whose text holds a lifted secret for the vault owner, or for an agent that says why once a grant covers its keys"
    ))
}

fn failed(reason: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{ROW}: {reason}"),
        &["Report this deck preview failure."],
    )
}
