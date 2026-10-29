//! A proposed lens's vault rows (FIX 9896; dashboard-v2:D8, ARCH-0035 Rule
//! A): the lens is a CODE kind=lens row carrying its frozen tree, and its
//! authored prompt is an explicit-only `lens/intent` NOTE beside it. The
//! lens row's birth names the prompt as its prompt input, the proposer as
//! its writer and the caller's trigger, all in the proposal's transaction.
//! The prompt NOTE sits where the proposal places the lens (FIX 2136,
//! [`super::scope`]). The proposal, intent and slot side rows index these
//! rows by ref.

use crate::batch::{BatchBuilder, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::code_artifact::{
    CodeArtifactBody, CodeArtifactClass, decode_code_artifact_body, encode_code_artifact_body,
};
use crate::edge::EdgeKind;
use crate::federation::record_scope::BirthPosition;
use crate::note::{LENS_INTENT_NOTE_KIND, NoteActor, NoteBody, NoteKind, encode_note_body};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::{MadeByClass, MadeByTrigger};
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::temporal::TimeRange;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};

/// The process a lens row's birth names.
const LENS_PROPOSE_PROCESS: &str = "vault.lenses.propose";

/// The rows one proposal writes.
pub(super) struct LensArtifacts<'a> {
    /// The CODE kind=lens row, which is also the proposal's lens ref.
    pub(super) lens_ref: EntityId,
    /// The `lens/intent` NOTE holding the authored prompt.
    pub(super) prompt_ref: EntityId,
    /// The pack slot the tree was compiled for, as the lens row names it.
    pub(super) slot_ref: String,
    pub(super) prompt: &'a str,
    /// The frozen tree's canonical JSON.
    pub(super) compiled_json: &'a str,
    /// What caused the proposal, when the caller names it.
    pub(super) trigger: Option<MadeByTrigger>,
    /// Where the lens is read: the prompt NOTE's world and facet.
    pub(super) placement: BirthPosition,
    pub(super) at: u64,
}

impl LensArtifacts<'_> {
    /// Both rows, the prompt's authorship and subject edges, the edges that
    /// place it and the lens row's birth, staged for the caller's write
    /// transaction.
    pub(super) fn stage<'v>(
        self,
        vault: &'v Vault,
        writer: WriteActor,
    ) -> Result<BatchBuilder<'v>> {
        let author = writer.entity_ref();
        let occurred = TimeRange {
            start: self.at,
            end: self.at,
        };
        let note = encode_note_body(&NoteBody {
            kind: NoteKind::parse(LENS_INTENT_NOTE_KIND).ok_or(Error::InvariantViolation(
                "the lens intent NOTE kind is shipped",
            ))?,
            author_ref: NoteActor::Actor(author),
            markdown: self.prompt.to_owned(),
            source_revision_ref: *self.lens_ref.as_bytes(),
        })?;
        let code = encode_code_artifact_body(&CodeArtifactBody::lens(
            self.prompt,
            *blake3::hash(self.compiled_json.as_bytes()).as_bytes(),
            self.slot_ref,
            self.compiled_json,
        ))?;
        // The proposer wrote the tree from the prompt; nothing else was read.
        let trigger = self.trigger;
        let birth = RowBirth::prompted(
            writer,
            MadeByClass::of_writer(writer.actor_class()),
            LENS_PROPOSE_PROCESS,
            &[self.prompt_ref],
            &[self.prompt.as_bytes()],
            self.at,
        )
        .map(|mut birth| {
            birth.made_by.trigger = trigger;
            birth
        });
        let weight = |kind: EdgeKind| kind.default_weight().unwrap_or(1.0);
        let mut batch = vault
            .batch_in()
            .put(
                &self.lens_ref,
                ENTITY_TYPE_CODE_ARTIFACT,
                occurred,
                self.at,
                &code,
            )
            .put_authored_note(&self.prompt_ref, &author, occurred, self.at, &note)
            .edge(
                &self.prompt_ref,
                EdgeKind::AuthoredBy,
                &author,
                weight(EdgeKind::AuthoredBy),
            )
            .edge(
                &self.prompt_ref,
                EdgeKind::About,
                &self.lens_ref,
                weight(EdgeKind::About),
            )
            .made_by(&self.lens_ref, birth);
        // The NOTE's world and its facet, in the writer that births it.
        if let Some(world) = self.placement.world {
            let kind = EdgeKind::InWorld;
            batch = batch.edge(&self.prompt_ref, kind, &world, weight(kind));
        }
        if let Some(facet) = self.placement.facet {
            let kind = EdgeKind::FacetOf;
            batch = batch.edge(&self.prompt_ref, kind, &facet, weight(kind));
        }
        Ok(batch)
    }
}

/// The frozen tree `lens_ref`'s CODE kind=lens row carries, in `txn`, when
/// its hash is `compiled_hash`.
///
/// # Errors
///
/// [`Error::CorruptedIndex`] when the row is missing, is no lens, or carries
/// another tree; storage errors as they occur.
pub(super) fn lens_tree_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    lens_ref: &EntityId,
    compiled_hash: &str,
) -> Result<String> {
    let corrupt = || Error::CorruptedIndex("lens proposal record");
    let raw = vault.get_raw_in(txn, lens_ref)?.ok_or_else(corrupt)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or_else(corrupt)?;
    if header.entity_type != ENTITY_TYPE_CODE_ARTIFACT {
        return Err(corrupt());
    }
    let body = decode_code_artifact_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if body.class != CodeArtifactClass::Lens {
        return Err(corrupt());
    }
    let tree = body.lens_tree.ok_or_else(corrupt)?;
    if super::proposal::lens_hash(&tree) != compiled_hash {
        return Err(corrupt());
    }
    Ok(tree)
}

/// The authored prompt the `lens/intent` NOTE `prompt_ref` holds, in `txn`,
/// or `None` once that NOTE is gone. Read as `Vault::read_note` reads a
/// NOTE.
///
/// # Errors
///
/// Storage errors, or a row at `prompt_ref` that is no lens intent NOTE.
pub(super) fn lens_prompt_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    prompt_ref: &EntityId,
) -> Result<Option<String>> {
    let corrupt = || Error::CorruptedIndex("lens intent record");
    if vault.archive_tombstone_in_txn(txn, prompt_ref)?.is_some() {
        return Ok(None);
    }
    let Some(raw) = vault.get_raw_in(txn, prompt_ref)? else {
        return Ok(None);
    };
    if raw.first() != Some(&crate::registry::ENTITY_TYPE_NOTE) {
        return Err(corrupt());
    }
    let bytes = &raw[ENTITY_METADATA_HEADER_LEN..];
    #[cfg(feature = "sync")]
    let resolved = crate::entity_doc::resolve_record_body(&vault.store, txn, prompt_ref, bytes)?;
    #[cfg(feature = "sync")]
    let bytes = resolved.as_slice();
    let bytes = crate::note::live_body_in_txn(
        &vault.store,
        txn,
        prompt_ref,
        crate::registry::ENTITY_TYPE_NOTE,
        bytes,
    )?;
    let note = crate::note::decode_note_body_in_txn(&vault.store, txn, &bytes)?;
    if note.kind.as_str() != LENS_INTENT_NOTE_KIND {
        return Err(corrupt());
    }
    Ok(Some(note.markdown))
}
