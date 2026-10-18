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
//! Drawn slides are kept by the vault, the export's memo key and the
//! renderer ([`DRAWN`]): a call on an unchanged deck projects and converts
//! nothing, and draws only the slides no earlier call drew.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{invalid, live, open_record};
use crate::Vault;
use crate::edit_roundtrip::VaultAssets;
use crate::edit_roundtrip::slides_review::{SlideRenderer, review_image_key};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::record_references::admit_row_references;
use crate::memory::{
    MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult,
};
use oneiron_docedit::deck::DeckView;
use oneiron_docedit::live::deck_export::export_key;
use oneiron_docedit::live::{
    ExportKey, ExportOutcome, ExportProfile, HeldAssets, LiveDeck, preflight, project,
};
use oneiron_docedit::retained_opc::Package;

const ROW: &str = "vault.artifacts.body.deck.preview";

/// The most slides one preview draws (CALLS "OF-510 deck preview").
const MAX_SLIDES: usize = 20;

/// The most image bytes [`DRAWN`] holds, across every vault and deck; past
/// it the least recently read export's slides go first (CALLS "OF-510 deck
/// preview cache").
const DRAWN_BYTES: usize = 64 << 20;

/// How long an export's drawn slides stay in [`DRAWN`] once no call reads
/// them (CALLS "OF-510 deck preview cache").
const DRAWN_IDLE: Duration = Duration::from_secs(30 * 60);

/// The drawn slides of one vault's export under one renderer: the vault's
/// id, the export's memo key hash and the renderer's name.
type Slot = ([u8; 32], [u8; 32], String);

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
    /// the same export are not drawn again.
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
        if input.slides.is_empty() || input.slides.len() > MAX_SLIDES {
            return Err(MemoryError::bad_request(format!(
                "a deck preview names 1 to {MAX_SLIDES} slides"
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
        // holds one draws for the owner alone (OF-067).
        if self.reads_lifted_keys_masked()?
            && !self.vault().typed_body_lifted_keys(&artifact)?.is_empty()
        {
            return Err(MemoryError::bad_request(format!(
                "{ROW} draws a deck whose text holds a lifted secret for the vault owner only"
            )));
        }
        let vault = self.vault();
        let projection = vault.deck_projection(&artifact, fork.as_ref())?;
        let key = projection.key.hash();
        let slot: Slot = (
            *vault.vault_id().as_bytes(),
            key,
            renderer.name().to_owned(),
        );
        let held = DRAWN.lock().unwrap_or_else(PoisonError::into_inner).held(
            &slot,
            &input.slides,
            Instant::now(),
        );
        let (count, mut images, export) = match held {
            Some((count, images)) => (count, images, None),
            None => {
                let export = vault.project_preview(&artifact, &projection)?;
                let count = Package::open(&export.bytes, vault.docedit_package_limits()?)
                    .ok()
                    .and_then(|package| DeckView::read(&package).ok())
                    .map(|view| u64::try_from(view.slides.len()).unwrap_or(u64::MAX))
                    .ok_or_else(|| failed("the deck's export could not be read back"))?;
                (count, BTreeMap::new(), Some(export))
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
        if !missing.is_empty() {
            let export = match export {
                Some(export) => export,
                None => vault.project_preview(&artifact, &projection)?,
            };
            let drawn = renderer.render(&export.bytes, &missing)?;
            if drawn.len() != missing.len() {
                return Err(failed("the renderer drew another number of slides"));
            }
            let drawn: Vec<(u64, Vec<u8>)> = missing.into_iter().zip(drawn).collect();
            DRAWN.lock().unwrap_or_else(PoisonError::into_inner).keep(
                slot,
                count,
                &drawn,
                Instant::now(),
            );
            images.extend(drawn);
        }
        let slides = input
            .slides
            .iter()
            .map(|&slide| {
                let image = images
                    .remove(&slide)
                    .ok_or_else(|| failed("a named slide was not drawn"))?;
                Ok(DeckPreviewSlide {
                    slide,
                    media_type: if image.starts_with(&[0xFF, 0xD8, 0xFF]) {
                        "image/jpeg"
                    } else {
                        "image/png"
                    }
                    .to_owned(),
                    image_hash: review_image_key(&image),
                    content_base64: base64::engine::general_purpose::STANDARD.encode(&image),
                })
            })
            .collect::<MemoryResult<Vec<_>>>()?;
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
}

impl Vault {
    /// The deck at its head, or with `fork` that open fork's merge candidate
    /// over the head, as [`Vault::pptx_body_fork_review`] reads it.
    fn deck_projection(&self, artifact: &EntityId, fork: Option<&EntityId>) -> Result<Projection> {
        let source = self
            .office_body_head(artifact)?
            .ok_or(Error::EntityNotFound)?;
        let (head, body, candidate) = {
            let txn = self.store.env.read_txn()?;
            let (head, body) = self.deck_head(&txn, artifact)?;
            let candidate = match fork {
                Some(fork) => {
                    let record = open_record(&self.store, &txn, artifact, fork)?;
                    let work = self.deck_fork(&txn, &record)?;
                    Some(preflight(&body.deck, &work).map_err(live)?.candidate)
                }
                None => None,
            };
            (head, body, candidate)
        };
        let package = Package::open(
            &self.deck_source(artifact, &source, body.retained)?,
            self.docedit_package_limits()?,
        )
        .map_err(|_| invalid("the PPTX package could not be read"))?;
        let deck = candidate.unwrap_or(body.deck);
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
        })
    }

    /// The export `projection` keys, its live-born pictures' assets read
    /// now.
    fn project_preview(
        &self,
        artifact: &EntityId,
        projection: &Projection,
    ) -> Result<ExportOutcome> {
        let assets = {
            let txn = self.store.env.read_txn()?;
            HeldAssets::resolve(
                &VaultAssets {
                    vault: self,
                    txn: &txn,
                },
                &[&projection.deck],
            )
        };
        project(
            &projection.deck,
            &projection.package,
            &artifact.to_hex(),
            &ExportProfile::default(),
            &assets,
        )
        .map_err(live)
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
}

impl Entry {
    fn bytes(&self) -> usize {
        self.images.values().map(Vec::len).sum()
    }
}

impl Drawn {
    /// The export's slide count and those of `asked` it holds drawn, when it
    /// holds the export; entries idle past [`DRAWN_IDLE`] go first.
    fn held(
        &mut self,
        slot: &Slot,
        asked: &[u64],
        now: Instant,
    ) -> Option<(u64, BTreeMap<u64, Vec<u8>>)> {
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
        let images = asked
            .iter()
            .filter_map(|&slide| Some((slide, entry.images.get(&slide)?.clone())))
            .collect();
        Some((entry.slides, images))
    }

    /// Keep `drawn` for the export of `slides` slides; past [`DRAWN_BYTES`],
    /// the least recently read exports go.
    fn keep(&mut self, slot: Slot, slides: u64, drawn: &[(u64, Vec<u8>)], now: Instant) {
        let entry = self.entries.entry(slot).or_insert_with(|| Entry {
            slides,
            images: BTreeMap::new(),
            read_at: now,
        });
        entry.read_at = now;
        for (slide, image) in drawn {
            self.bytes = self.bytes.saturating_add(image.len());
            if let Some(old) = entry.images.insert(*slide, image.clone()) {
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

fn failed(reason: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INTERNAL,
        format!("{ROW}: {reason}"),
        &["Report this deck preview failure."],
    )
}
