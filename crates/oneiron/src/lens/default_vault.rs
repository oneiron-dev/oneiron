//! Renderer-neutral default vault composition over already-admitted projections.
//!
//! Selection stays with the existing scoped reads, including their as-of selectors.
//! This module only joins their ledger, dossier and read-only thread projections;
//! it does not choose screens, navigation, section titles or visual defaults.

use crate::claim::{ScopedRead, ScopedReadReceipt, ScopedReadResult};
use crate::thread_lens::{ThreadLensEntry, entry_node};
use crate::{Error, Result};

use super::{
    AsofScrubberAtom, CollectionAtom, GeneratedLens, LedgerRowAtom, LensAtom, LensAtomId,
    LensBackingRefToken, LensHandleRef, LensHandleRole, LensNode, LensRenderFrame, LensText,
    SectionAtom,
};

/// A caller's scoped projection and the existing frame refs that back it.
///
/// The caller projects the value from its admitted reads, preserving their receipt.
/// A dossier may cite several sources. Every source is rechecked at composition
/// time; no raw entity id or new backing reference is accepted or minted here.
#[derive(Debug, Clone)]
pub struct DefaultVaultItem<T> {
    pub projection: ScopedReadResult<T>,
    pub backing_refs: Vec<LensBackingRefToken>,
}

/// Inputs to one default vault projection, not a rendering contract.
///
/// `as_of` describes the selection already applied by the caller's existing
/// temporal reads. It is not a second query or a promise to filter live data.
/// Titles and dossier content come from the caller rather than an engine UI.
#[derive(Debug, Clone)]
pub struct DefaultVaultInput {
    pub title: LensText,
    pub as_of: Option<AsofScrubberAtom>,
    pub ledger: Vec<DefaultVaultItem<LedgerRowAtom>>,
    pub dossiers: Vec<DefaultVaultItem<SectionAtom>>,
    pub threads: Vec<DefaultVaultItem<ThreadLensEntry>>,
}

/// Compose existing atoms under one sheet, retaining source selection handles and
/// the narrowing receipts of both the input projections and their current reads.
///
/// A stale, foreign-frame or inaccessible backing ref refuses the composition,
/// just as it does for other frame-bound lens reads. Thread entries use the
/// existing thread-lens projection without introducing its send box or actions.
pub fn compose_default_vault(
    read: &ScopedRead<'_>,
    frame: &LensRenderFrame,
    input: DefaultVaultInput,
) -> Result<ScopedReadResult<GeneratedLens>> {
    frame.ensure_scoped_read_actor(read)?;
    let mut receipt = read.read_receipt(None, 0)?;
    let mut root = LensNode::new(
        LensAtomId::new("default-vault")?,
        LensAtom::Sheet(CollectionAtom {
            title: input.title,
            rows: Vec::new(),
        }),
    );
    if let Some(as_of) = input.as_of {
        root.children.push(LensNode::new(
            LensAtomId::new("default-vault-as-of")?,
            LensAtom::AsofScrubber(as_of),
        ));
    }
    for (index, item) in input.ledger.into_iter().enumerate() {
        let (row, bindings) = admit_item(read, frame, item, &mut receipt)?;
        let mut node = LensNode::new(
            LensAtomId::new(format!("default-vault-ledger-{index}"))?,
            LensAtom::LedgerRow(row),
        );
        node.bindings = bindings;
        root.children.push(node);
    }
    for (index, item) in input.dossiers.into_iter().enumerate() {
        let (section, bindings) = admit_item(read, frame, item, &mut receipt)?;
        let mut node = LensNode::new(
            LensAtomId::new(format!("default-vault-dossier-{index}"))?,
            LensAtom::DossierSection(section),
        );
        node.bindings = bindings;
        root.children.push(node);
    }
    for (index, item) in input.threads.into_iter().enumerate() {
        let (entry, bindings) = admit_item(read, frame, item, &mut receipt)?;
        let mut node = entry_node(index, &entry)?;
        node.bindings = bindings.clone();
        // The message-ref metadata is the same projection of the same sources.
        for child in &mut node.children {
            child.bindings = bindings.clone();
        }
        root.children.push(node);
    }
    Ok(ScopedReadResult {
        value: GeneratedLens::new(root)?,
        receipt,
    })
}

fn admit_item<T>(
    read: &ScopedRead<'_>,
    frame: &LensRenderFrame,
    item: DefaultVaultItem<T>,
    receipt: &mut ScopedReadReceipt,
) -> Result<(T, Vec<LensHandleRef>)> {
    if item.backing_refs.is_empty() {
        return Err(Error::InvalidConfig(
            "default vault items require existing backing refs".into(),
        ));
    }
    receipt.restrict_with(&item.projection.receipt);
    let mut bindings = Vec::new();
    for token in &item.backing_refs {
        let backing = frame.resolve_backing_ref_token(read, token)?;
        if backing.role() == LensHandleRole::ActionTarget {
            return Err(Error::InvalidConfig(
                "default vault items require selectable read backing refs".into(),
            ));
        }
        let admitted = frame.scoped_body(read, backing.target().entity_id())?;
        receipt.restrict_with(&admitted.receipt);
        if admitted.value.is_none() {
            return Err(Error::InvalidConfig(
                "default vault source is outside the caller's read scope".into(),
            ));
        }
        if !bindings
            .iter()
            .any(|binding: &LensHandleRef| &binding.name == backing.handle())
        {
            bindings.push(LensHandleRef {
                name: backing.handle().clone(),
                role: backing.role(),
            });
        }
    }
    Ok((item.projection.value, bindings))
}
