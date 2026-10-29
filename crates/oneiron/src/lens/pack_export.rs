//! `vault.lenses.export_pack` (FIX 1192): one lens, as a portable pack file
//! a recipient compiles against their own vault, and the local receipt of
//! what left.
//!
//! The file carries the frozen tree exactly as the lens's CODE kind=lens
//! row holds it (its authored node ids and paths unchanged), the pack it
//! was compiled for by name and content hash, and the born-with text the
//! sharer's choice lets travel. A lens pack's default is its intent prompt,
//! the recipe (`TravelChoice::or_default(.., TravelKind::LensPack)`); an
//! explicit empty choice sends none. No vault ref is in the file: the lens
//! row, its prompt NOTE and the slot's SKILL are named only in the receipt
//! the door answers beside it, whose digest is of the file's own bytes, and
//! the vault's share receipt lists what travelled. The export reads the
//! lens under the caller's own read, as `vault.lenses.list` does: a reader
//! narrowed to some worlds or facets is given no frozen tree. It previews,
//! asks, imports and activates nothing.

use serde::{Deserialize, Serialize};

use super::LENS_LIST_NARROWED_CARRIES_COMPILED;
use super::artifact::lens_tree_in;
use super::proposal::{PROPOSALS, reads_narrowed};
use crate::claim::ClaimReadStatus;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::secret_custody::SecretSight;
use crate::share_travel::{BornWith, BornWithField, TravelChoice, TravelKind};
use crate::{EntityId, Error};

/// The schema a lens pack file names.
pub const LENS_PACK_SCHEMA: &str = "oneiron.lens_pack.v1";

/// The version a lens's share receipt names: a lens row is one frozen
/// revision, and a new tree is a new lens.
const LENS_PACK_RECEIPT_VERSION: u64 = 1;

/// `vault.lenses.export_pack`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LensPackExportRequest {
    /// The lens, as `vault.lenses.list` names it: 32 hex.
    pub lens_ref: String,
    /// The born-with text to send. Absent sends a lens pack's default, its
    /// intent prompt; `{"born_with": []}` sends none.
    #[serde(default)]
    pub travel: Option<TravelChoice>,
}

/// A portable lens pack file (`schema` [`LENS_PACK_SCHEMA`]). It names no
/// vault ref: what it carries is content, compared by hash.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LensPackFile {
    pub schema: String,
    /// The pack the tree was compiled for, by name.
    pub pack_name: String,
    /// The content hash of the pack the tree was compiled against.
    pub pack_content_hash: String,
    /// blake3 hex of the frozen tree's canonical JSON, as `vault.lenses.list`
    /// names it.
    pub compiled_hash: String,
    /// The frozen generated-lens envelope (`kit_version`,
    /// `apps_contract_version`, `root`), exactly as the lens row holds it.
    pub compiled: serde_json::Value,
    /// The born-with text that travels with the pack, by field.
    pub born_with: BornWith,
}

/// `vault.lenses.export_pack`'s answer: the file and its local receipt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LensPackExport {
    /// The pack file's bytes, a [`LensPackFile`] as JSON: the bytes the
    /// receipt's `content_hash` is of.
    pub pack_json: String,
    pub receipt: LensPackExportReceipt,
}

/// What left, for the sharer alone: the vault refs the file was made from
/// and its digest. It names; it grants nothing.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LensPackExportReceipt {
    /// The CODE kind=lens row the tree was read from, 32 hex.
    pub lens_ref: String,
    /// The `lens/intent` NOTE holding its authored prompt, 32 hex.
    pub prompt_ref: String,
    /// The slot's SKILL, 32 hex.
    pub skill_id: String,
    /// blake3 hex of `pack_json`'s bytes.
    pub content_hash: String,
    /// The born-with fields that left with the pack.
    pub travelled: Vec<BornWithField>,
}

impl Memory<'_> {
    /// `vault.lenses.export_pack`: the lens `lens_ref` as a portable pack
    /// file with the born-with text `travel` lets go, its local receipt,
    /// and the vault's share receipt listing what travelled. The owner's
    /// export reads the lens's born-with text as the owner does; any other
    /// caller's carries prompt text only from the rows its own read lane
    /// reads.
    ///
    /// # Errors
    ///
    /// A `lens_ref` that is not 32 hex; no lens by it; a reader narrowed to
    /// some worlds or facets ([`LENS_LIST_NARROWED_CARRIES_COMPILED`]); a
    /// share receipt that does not write while born-with text travels.
    pub fn lenses_export_pack(&self, input: &LensPackExportRequest) -> MemoryResult<LensPackExport> {
        let lens_ref = EntityId::from_hex(&input.lens_ref)
            .map_err(|_| MemoryError::bad_request("lens_ref is a 32-hex lens ref"))?;
        let read = self.read_lane(ClaimReadStatus::Recorded)?;
        if reads_narrowed(read.actor_key()) && !LENS_LIST_NARROWED_CARRIES_COMPILED {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "a reader narrowed to some worlds or facets is given no lens's frozen tree",
                &["Export the lens on a credential that reads the whole vault."],
            ));
        }
        let vault = self.vault();
        let (record, tree, prompt_ref, prompt_readable) = {
            let txn = vault.store.env.read_txn().map_err(Error::from)?;
            let record = PROPOSALS
                .get(&vault.store, &txn, &lens_ref)?
                .ok_or_else(|| MemoryError::not_found(format!("no lens {}", input.lens_ref)))?;
            let tree = lens_tree_in(vault, &txn, &lens_ref, &record.compiled_hash)?;
            let prompt_ref = EntityId::from_hex(&record.prompt_ref)
                .map_err(|_| Error::CorruptedIndex("lens proposal record"))?;
            let prompt_readable = read.is_entity_readable_in(&txn, &prompt_ref)?;
            (record, tree, prompt_ref, prompt_readable)
        };
        let travel = TravelChoice::or_default(input.travel.as_ref(), TravelKind::LensPack);
        let text = if self.secret_sight()? == SecretSight::Owner {
            vault.born_with_text(&lens_ref, None)?
        } else {
            let mut text = match vault.row_birth(&lens_ref)? {
                Some(birth) => self.born_with_text_for_reader(&lens_ref, &birth.made_by, &travel)?,
                None => vault.born_with_text_for_another(&lens_ref, None)?,
            };
            // The intent prompt is the prompt NOTE's text: it leaves only
            // with a reader who reads that NOTE.
            if !prompt_readable {
                text.remove(&BornWithField::IntentPrompt);
            }
            text
        };
        let born_with = travel.project(text);
        let file = LensPackFile {
            schema: LENS_PACK_SCHEMA.to_owned(),
            pack_name: record.pack_name,
            pack_content_hash: record.pack_content_hash,
            compiled_hash: record.compiled_hash,
            compiled: serde_json::from_str(&tree)
                .map_err(|_| Error::CorruptedIndex("lens proposal record"))?,
            born_with,
        };
        let pack_json = serde_json::to_string(&file)
            .map_err(|_| Error::InvalidConfig("lens pack did not encode".into()))?;
        let content_hash = blake3::hash(pack_json.as_bytes()).to_hex().to_string();
        vault.record_export_travel(
            lens_ref.to_hex(),
            LENS_PACK_RECEIPT_VERSION,
            content_hash.clone(),
            &self.actor(),
            &file.born_with,
        )?;
        Ok(LensPackExport {
            pack_json,
            receipt: LensPackExportReceipt {
                lens_ref: lens_ref.to_hex(),
                prompt_ref: prompt_ref.to_hex(),
                skill_id: record.skill_id,
                content_hash,
                travelled: file.born_with.keys().copied().collect(),
            },
        })
    }
}
