//! The deterministic export projector and the eight-step gate
//! (ARCH-0077, "Export is a deterministic projection").
//!
//! The projector writes the live model's text and own-geometry values back
//! over the retained package through the checked edit verbs, in stable
//! model-identity order, with no clock and no randomness. Imported native
//! ids are preserved because every write addresses the retained shape by
//! its binding. A true no-op returns the original archive bytes.
//!
//! Structural divergence from the retained package (nodes born in the live
//! body, removals, moves) is refused here rather than guessed: those nodes
//! have no retained element to write over yet. Until [`Gate::is_open`],
//! blob versions remain authoritative and exports are proposal artifacts.

use super::LiveError;
use super::pptx::{LiveDeck, NodeId, NodeKind};
use crate::deck::DeckView;
use crate::edit::{Target, ValueEdit, Xfrm, edit};
use crate::retained_opc::Package;
use serde::{Deserialize, Serialize};

/// Bump on any projector change; part of every memo key.
pub const PROJECTOR_VERSION: &str = "live-deck-projector/1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportProfile {
    pub name: String,
}

impl Default for ExportProfile {
    fn default() -> Self {
        Self {
            name: "pptx-live-v1".to_owned(),
        }
    }
}

/// The bounded memo key: state, retained input, profile and implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportKey {
    pub document: String,
    pub state_hash: [u8; 32],
    /// Hash of the retained package's part names and part hashes.
    pub package_hash: [u8; 32],
    pub profile: String,
    pub projector: String,
}

impl ExportKey {
    pub fn hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOutcome {
    pub bytes: Vec<u8>,
    pub key: ExportKey,
    /// The document version the export was projected from.
    pub document_version: u64,
    pub changed_parts: Vec<String>,
    /// A true no-op: `bytes` is the original archive.
    pub noop: bool,
}

fn package_hash(package: &Package) -> Result<[u8; 32], LiveError> {
    let mut hasher = blake3::Hasher::new();
    for name in package.names() {
        hasher.update(name.as_bytes());
        if let Some(bytes) = package.part(name)? {
            hasher.update(blake3::hash(&bytes).as_bytes());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

/// The retained shape's current fingerprint, refreshed after each edit so a
/// second verb on the same shape is never stale.
fn fingerprint_of(view: &DeckView, slide_part: &str, native_id: u32) -> Option<[u8; 32]> {
    view.slides
        .iter()
        .find(|slide| slide.part == slide_part)?
        .shapes
        .iter()
        .find(|shape| shape.id == Some(native_id))
        .map(|shape| shape.content_fingerprint)
}

/// Project `deck` at its current version over its retained `package`.
pub fn project(
    deck: &LiveDeck,
    package: &Package,
    document: &str,
    profile: &ExportProfile,
) -> Result<ExportOutcome, LiveError> {
    let key = ExportKey {
        document: document.to_owned(),
        state_hash: deck.state_hash(),
        package_hash: package_hash(package)?,
        profile: profile.name.clone(),
        projector: PROJECTOR_VERSION.to_owned(),
    };
    // Nodes born in the live body have no retained element yet.
    let unbound: Vec<NodeId> = deck
        .nodes
        .iter()
        .filter(|(_, node)| node.kind != NodeKind::Root && node.binding.is_none())
        .map(|(id, _)| *id)
        .collect();
    if !unbound.is_empty() {
        return Err(LiveError::UnboundNodes(unbound));
    }
    let imported = LiveDeck::import(package)?;
    // Structure must still match the retained package. Import mints model
    // identities deterministically in document order, so a deck imported
    // from this package lines up node for node.
    if deck.nodes.len() != imported.nodes.len() {
        return Err(LiveError::Invalid(
            "structural divergence from the retained package",
        ));
    }
    for (id, node) in &deck.nodes {
        let Some(was) = imported.nodes.get(id) else {
            return Err(LiveError::Invalid(
                "structural divergence from the retained package",
            ));
        };
        if node.parent != was.parent || node.children != was.children || node.binding != was.binding
        {
            return Err(LiveError::Invalid(
                "structural divergence from the retained package",
            ));
        }
    }
    // Opaque replacements carry only their hash in the live model; the
    // replacement bytes must already be the retained part's bytes.
    for (part, expected) in &deck.opaque_parts {
        match package.part(part)? {
            Some(bytes) if blake3::hash(&bytes).as_bytes() == expected => {}
            _ => {
                return Err(LiveError::Invalid(
                    "opaque replacement bytes are not in the retained package",
                ));
            }
        }
    }
    let mut next = package.clone();
    let mut changed_parts: Vec<String> = Vec::new();
    for (id, node) in &deck.nodes {
        let Some(binding) = &node.binding else {
            continue;
        };
        let Some(native_id) = binding.native_id else {
            continue;
        };
        if node.kind == NodeKind::Slide {
            continue;
        }
        let geometry_changed = imported
            .nodes
            .get(id)
            .is_some_and(|was| was.geometry != node.geometry);
        let text_changed = imported.texts.get(id) != deck.texts.get(id);
        if !geometry_changed && !text_changed {
            continue;
        }
        if geometry_changed {
            let view = DeckView::read(&next)?;
            let expected = fingerprint_of(&view, &binding.slide_part, native_id)
                .ok_or(LiveError::UnknownNode)?;
            let report = edit(
                &mut next,
                &ValueEdit::SetXfrm {
                    target: Target {
                        slide: &binding.slide_part,
                        shape: native_id,
                        expected,
                    },
                    xfrm: Xfrm {
                        offset: node.geometry.offset,
                        extent: node.geometry.extent,
                        rotation: node.geometry.rotation,
                        flip_h: node.geometry.flip_h,
                        flip_v: node.geometry.flip_v,
                    },
                },
            )?;
            changed_parts.extend(report.changed_parts);
        }
        if text_changed {
            let plain = deck
                .texts
                .get(id)
                .map_or_else(String::new, |body| body.plain());
            let view = DeckView::read(&next)?;
            let expected = fingerprint_of(&view, &binding.slide_part, native_id)
                .ok_or(LiveError::UnknownNode)?;
            let report = edit(
                &mut next,
                &ValueEdit::SetText {
                    target: Target {
                        slide: &binding.slide_part,
                        shape: native_id,
                        expected,
                    },
                    text: &plain,
                },
            )?;
            changed_parts.extend(report.changed_parts);
        }
    }
    changed_parts.sort();
    changed_parts.dedup();
    let noop = changed_parts.is_empty();
    let bytes = next.export()?;
    Ok(ExportOutcome {
        bytes,
        key,
        document_version: deck.version,
        changed_parts,
        noop,
    })
}

/// One step of the eight-step import-then-export check. A timeout or an
/// unrun oracle is inconclusive, never a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    Passed,
    Failed(String),
    Inconclusive(String),
    NotRun,
}

/// The hashed oracle evidence one profile passed under. PowerPoint, macOS
/// and font versions are recorded on every receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleReceipt {
    pub profile: String,
    pub powerpoint_version: String,
    pub macos_version: String,
    pub font_versions: Vec<String>,
    /// The eight steps, in canon order.
    pub steps: Vec<StepOutcome>,
    /// Opened without repair.
    pub clean: bool,
}

/// The activation gate. Closed until a receipt for this exact profile
/// shows all eight steps passed on a clean oracle opening.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gate {
    pub profile: String,
    pub receipt: Option<OracleReceipt>,
}

impl Gate {
    pub fn closed(profile: &str) -> Self {
        Self {
            profile: profile.to_owned(),
            receipt: None,
        }
    }

    pub fn is_open(&self) -> bool {
        self.receipt.as_ref().is_some_and(|receipt| {
            receipt.profile == self.profile
                && receipt.clean
                && receipt.steps.len() == 8
                && receipt
                    .steps
                    .iter()
                    .all(|step| matches!(step, StepOutcome::Passed))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundtripReport {
    pub profile: String,
    /// The eight steps, in canon order.
    pub steps: Vec<StepOutcome>,
    pub baseline_preserved: bool,
    pub fixed_point: bool,
}

/// Run the steps of the eight-step check that hold in-process: baseline
/// preservation (1), the semantic fixed point (3) and package closure (5).
/// Edit preservation (2), concurrency (4), the MacBook oracle (6), non-PDF
/// checks (7) and the regression corpus (8) are reported inconclusive —
/// they need fixtures, a merge harness and the oracle seat, and an
/// unrun step is never a pass.
pub fn roundtrip_check(
    package: &Package,
    original_bytes: &[u8],
    profile: &ExportProfile,
) -> Result<RoundtripReport, LiveError> {
    let deck = LiveDeck::import(package)?;
    let outcome = project(&deck, package, "roundtrip", profile)?;
    let baseline_preserved = outcome.noop && outcome.bytes == original_bytes;
    let reopened = Package::open(&outcome.bytes, package.limits())?;
    let closure = DeckView::read(&reopened);
    let fixed_point = match &closure {
        Ok(_) => LiveDeck::import(&reopened)?.semantically_eq(&deck),
        Err(_) => false,
    };
    let step = |passed: bool, why: &str| {
        if passed {
            StepOutcome::Passed
        } else {
            StepOutcome::Failed(why.to_owned())
        }
    };
    Ok(RoundtripReport {
        profile: profile.name.clone(),
        steps: vec![
            step(baseline_preserved, "no-op export changed bytes"),
            StepOutcome::Inconclusive("edit-preservation fixtures not run".to_owned()),
            step(fixed_point, "re-import differs from the live model"),
            StepOutcome::Inconclusive("concurrency cases not run".to_owned()),
            step(closure.is_ok(), "exported package does not read back"),
            StepOutcome::Inconclusive("oracle not run".to_owned()),
            StepOutcome::Inconclusive("non-PDF checks not run".to_owned()),
            StepOutcome::Inconclusive("regression corpus not run".to_owned()),
        ],
        baseline_preserved,
        fixed_point,
    })
}
