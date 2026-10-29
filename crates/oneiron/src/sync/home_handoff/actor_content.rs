//! FIX 8875 stage 2: each actor's content a handoff carries, sealed under an
//! erasable key of its own, never under the target's long-lived machine key.
//!
//! A table exports its content-free facts and each actor's content apart
//! ([`super::Partitioned`]). In the source's freezing writer each actor gets
//! one key for the export's incarnation (`home_handoff_custody::mint`), drawn
//! from the 16 wire bytes the signed header carries, and its content is
//! sealed under that key, bound to the vault, the incarnation, the key, the
//! section and the part's place in it. The manifest names the key by its ref
//! alone, never its actor. The frozen parts keep these seals as history: an
//! erase of the actor retires the key, so they read as erased wherever a copy
//! went, while the facts stay.
//!
//! The target opens each part under the key it received for it
//! (`super::key_transit`). A key retired here (its actor erased) or not here
//! gives nothing, and the section's facts land without that content: never a
//! Conflict, never a refusal.

use heed::RwTxn;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::envelope::TableSection;
use super::table::ExportedRows;
use super::{HomeMove, refused};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::home_handoff_custody::{
    Content, Incarnation, KeyRef, mint, open_content, seal_content,
};

const AAD_DOMAIN: &[u8] = b"oneiron/home-handoff/actor-content/v1\0";

/// One actor's content in a section, sealed under its erasable key: the
/// key's ref, as 64 lowercase hex digits, and the sealed bytes. Never the
/// actor, never the key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SealedActorPart {
    pub(super) key: String,
    #[serde(with = "super::bin")]
    pub(super) sealed: Vec<u8>,
}

/// One table's export, ready to seal: its wire id, its version and its rows.
pub(super) struct SectionExport {
    pub(super) table_id: &'static str,
    pub(super) schema_version: u16,
    pub(super) rows: ExportedRows,
}

/// The 16 random wire bytes of one export's incarnation, drawn before its
/// tables export and its actors' keys mint.
///
/// # Errors
///
/// The OS random source failed.
pub(super) fn draw_wire() -> Result<[u8; 16]> {
    let mut wire = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut wire)
        .map_err(|_| refused("os randomness unavailable"))?;
    Ok(wire)
}

/// The associated data one actor part is sealed with: the domain, then the
/// vault (32) | key incarnation (32) | key ref (32) | the section's id,
/// length-prefixed (u16be) | the part's index in it (u32be).
fn aad(
    vault_id: &[u8; 32],
    incarnation: &Incarnation,
    key: &KeyRef,
    section: &str,
    index: u32,
) -> Result<Vec<u8>> {
    let length = u16::try_from(section.len())
        .map_err(|_| refused("a section's id is longer than its prefix holds"))?;
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 96 + 2 + section.len() + 4);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(vault_id);
    aad.extend_from_slice(incarnation.as_bytes());
    aad.extend_from_slice(key.as_bytes());
    aad.extend_from_slice(&length.to_be_bytes());
    aad.extend_from_slice(section.as_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    Ok(aad)
}

/// Seals `exports` for `movement` in `txn`, the source's freezing writer:
/// each section's facts as they are, and each actor's content under that
/// actor's one key for the incarnation `wire` names, minted here. Returns the
/// sections and the ref of every key minted, which the source keeps to send
/// each key to its target.
///
/// # Errors
///
/// Minting or sealing faults (an archived vault's custody is its
/// replacement's), and a section id too long to bind.
pub(super) fn seal_sections(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    movement: &HomeMove,
    wire: &[u8; 16],
    exports: Vec<SectionExport>,
) -> Result<(Vec<TableSection>, Vec<String>)> {
    let incarnation = Incarnation::of_handoff(wire);
    let mut keys: Vec<(EntityId, KeyRef)> = Vec::new();
    let mut sections = Vec::with_capacity(exports.len());
    for export in exports {
        let mut actors = Vec::with_capacity(export.rows.actors.len());
        for (index, (actor, plain)) in (0u32..).zip(export.rows.actors) {
            let key = match keys.iter().find(|(held, _)| *held == actor) {
                Some((_, key)) => *key,
                None => {
                    let key = mint(&vault.store, txn, incarnation, actor)?;
                    keys.push((actor, key));
                    key
                }
            };
            let aad = aad(
                &movement.vault_id,
                &incarnation,
                &key,
                export.table_id,
                index,
            )?;
            actors.push(SealedActorPart {
                key: key.to_hex(),
                sealed: seal_content(&vault.store, key, &aad, &plain)?,
            });
        }
        sections.push(TableSection {
            table_id: export.table_id.to_owned(),
            schema_version: export.schema_version,
            rows: export.rows.facts,
            actors,
        });
    }
    let refs = keys.iter().map(|(_, key)| key.to_hex()).collect();
    Ok((sections, refs))
}

/// Refuses a section whose actor parts name a key other than in its one
/// canonical spelling, before any writer.
///
/// # Errors
///
/// A key ref that is not 64 lowercase hex digits.
pub(super) fn check_parts(section: &TableSection) -> Result<()> {
    for part in &section.actors {
        KeyRef::from_hex(&part.key)?;
    }
    Ok(())
}

/// The content of every actor part of `section` that opens here, in the
/// handoff `movement` whose signed header carries the wire incarnation
/// `wire`, in the order the parts stand. A part whose key was retired here
/// (its actor erased) or is not here gives nothing: the section's facts land
/// without it.
///
/// # Errors
///
/// A malformed key ref; bytes that do not open under a live key; custody
/// faults.
pub(super) fn open_section(
    vault: &Vault,
    movement: &HomeMove,
    wire: &[u8; 16],
    section: &TableSection,
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let incarnation = Incarnation::of_handoff(wire);
    let mut opened = Vec::with_capacity(section.actors.len());
    let mut erased = 0usize;
    let mut unavailable = 0usize;
    for (index, part) in (0u32..).zip(&section.actors) {
        let key = KeyRef::from_hex(&part.key)?;
        let aad = aad(
            &movement.vault_id,
            &incarnation,
            &key,
            &section.table_id,
            index,
        )?;
        match open_content(&vault.store, key, &aad, &part.sealed)? {
            Content::Open(plain) => opened.push(plain),
            Content::Erased => erased = erased.saturating_add(1),
            Content::Unavailable(_) => unavailable = unavailable.saturating_add(1),
        }
    }
    if erased > 0 || unavailable > 0 {
        tracing::info!(
            section = %section.table_id,
            erased,
            unavailable,
            "a home handoff section lands some actors' rows as their facts alone"
        );
    }
    Ok(opened)
}
