//! Crash-idempotent push-to-document lowering under the origin single-writer lock.
use super::document_candidate_types::{ReceivedRefIngress, ReceivedRefSource};
use super::smart_http::{ReceivePackAttribution, RefUpdate};
use crate::code_document::{CodeEditReceipt, CodeFileEdit, CodeFileIngress};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::git_wire::{GitWire, GitWireRepo};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::scan_check::{EngineScan, ScanCount};
use crate::side_table::{self, LegacyCompact, SideKey, SideTable};
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// One push operation, including non-text blobs and mode-only changes.
/// Git objects remain pinned by the hash-keyed origin change claim.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ReceivedFileOperation {
    pub operation_id: String,
    /// The pusher's hex id, or [`ERASED_CALL_IDENTITY`] once that actor was
    /// erased (FIX 4475).
    pub actor_id: String,
    pub session_id: String,
    pub ref_name: String,
    pub path: String,
    pub before_hash: [u8; 32],
    pub after_hash: [u8; 32],
    pub old_mode: Option<u32>,
    pub new_mode: Option<u32>,
    pub document_edit: bool,
}
/// Crash-idempotent receipt of one push's ref: its validated source, first receipt time, the
/// file operations it landed and the candidate matching attached (G4 PR2), keyed by
/// provenance then blake3(ref_name). Key: id16 ":" hash32 — the ':' is a literal byte, not a
/// NUL, exactly the shape this row has always spelled.
pub(super) const CODE_OPERATIONS: SideTable<ProvenanceRefKey, ReceivedRefIngress, LegacyCompact> =
    SideTable::new(&side_table::ORIGIN_CODE_OPERATIONS);

pub(super) struct ProvenanceRefKey {
    pub(super) provenance: EntityId,
    pub(super) ref_name_hash: [u8; 32],
}

impl ProvenanceRefKey {
    /// The row key of `ref_name` under the push `provenance`.
    pub(super) fn of(provenance: EntityId, ref_name: &str) -> Self {
        Self {
            provenance,
            ref_name_hash: *blake3::hash(ref_name.as_bytes()).as_bytes(),
        }
    }
}

impl SideKey for ProvenanceRefKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.provenance.as_bytes());
        out.push(b':');
        out.extend_from_slice(&self.ref_name_hash);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (id, rest) = bytes.split_at_checked(16)?;
        let (&separator, hash) = rest.split_first()?;
        if separator != b':' {
            return None;
        }
        Some(Self {
            provenance: EntityId::from_bytes(id.try_into().ok()?).ok()?,
            ref_name_hash: hash.try_into().ok()?,
        })
    }
}

impl Vault {
    /// The authenticated observer receipt, not a trailer, identifies the push.
    /// The outer landing holds the repo coordinator and already validated it.
    pub(in crate::origin) fn land_received_code_operations(
        &self,
        wire: &GitWire<'_>,
        repo: &GitWireRepo,
        update: &RefUpdate,
        attribution: &ReceivePackAttribution,
        now: u64,
    ) -> Result<()> {
        let session = entity_id_from_hash_material(
            b"oneiron:push-session:v1",
            &[
                repo.identity().as_hex().as_bytes(),
                attribution.provenance_claim_id.as_bytes(),
            ],
        )?;
        let session_body = attribution.provenance_claim_id.to_hex();
        match self.get_entity_type(&session)? {
            None => self.put_entity(
                &session,
                crate::registry::ENTITY_TYPE_SESSION,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                session_body.as_bytes(),
            )?,
            Some(crate::registry::ENTITY_TYPE_SESSION) => (),
            Some(_) => return Err(Error::CorruptedIndex("push session identity occupied")),
        }
        let mut operations = Vec::new();
        let mut ingress = Vec::new();
        {
            let old = update
                .old_oid
                .as_ref()
                .map(|oid| read_files(wire, repo, oid))
                .transpose()?
                .unwrap_or_default();
            let new = update
                .new_oid
                .as_ref()
                .map(|oid| read_files(wire, repo, oid))
                .transpose()?
                .unwrap_or_default();
            let paths: BTreeSet<_> = old.keys().chain(new.keys()).cloned().collect();
            // The repository's own scope, as every local writer spells it:
            // one document per path whatever ref a push moves (FIX 12199).
            let scope = crate::repo_mutation::canonical_mutation_scope(repo.repo_root())?;
            for path in paths {
                let before = bytes(&old, &path);
                let after = bytes(&new, &path);
                let old_mode = old.get(&path).map(|f| f.mode);
                let new_mode = new.get(&path).map(|f| f.mode);
                if before == after && old_mode == new_mode {
                    continue;
                }
                let before_hash = *blake3::hash(before).as_bytes();
                let after_hash = *blake3::hash(after).as_bytes();
                let operation = entity_id_from_hash_material(
                    b"oneiron:push-file-operation:v1",
                    &[
                        attribution.provenance_claim_id.as_bytes(),
                        update.name.as_bytes(),
                        path.as_bytes(),
                        &before_hash,
                        &after_hash,
                        &old_mode.unwrap_or(0).to_be_bytes(),
                        &new_mode.unwrap_or(0).to_be_bytes(),
                    ],
                )?;
                let document_edit = if before != after
                    && old_mode != Some(0o160000)
                    && new_mode != Some(0o160000)
                {
                    if let (Ok(before), Ok(after)) =
                        (std::str::from_utf8(before), std::str::from_utf8(after))
                    {
                        let document = self.open_code_document(&scope, &path, before, session)?;
                        // Another ref's push may have moved the document off
                        // this push's base: the pushed text lands as one
                        // version over its current text, never a refused
                        // push. A replay lowers the edit it landed.
                        let base = match self.code_file_edit_receipt(operation)? {
                            Some(landed) => self.code_document_at(&landed.before)?,
                            None => document.text(),
                        };
                        if base == after {
                            false
                        } else {
                            ingress.push(CodeFileIngress {
                                operation,
                                session: document,
                                edit: CodeFileEdit::between(&path, &base, after),
                                metadata_edit: None,
                                actor: WriteActor::new(
                                    attribution.actor_id,
                                    EdgeActorClass::System,
                                ),
                                expected_text: base,
                            });
                            true
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };
                operations.push(ReceivedFileOperation {
                    operation_id: operation.to_hex(),
                    actor_id: attribution.actor_id.to_hex(),
                    session_id: session.to_hex(),
                    ref_name: update.name.clone(),
                    path,
                    before_hash,
                    after_hash,
                    old_mode,
                    new_mode,
                    document_edit,
                });
            }
        }
        // The exact validated update, kept even when it changed no file.
        let source = ReceivedRefSource {
            object_store: repo.identity().as_hex(),
            ref_name: update.name.clone(),
            old_oid: update.old_oid.as_ref().map(|oid| oid.as_str().to_owned()),
            new_oid: update.new_oid.as_ref().map(|oid| oid.as_str().to_owned()),
        };
        let fresh = ReceivedRefIngress {
            source,
            received_at: now,
            operations,
            candidate: None,
        };
        CODE_OPERATIONS.encode_value(&fresh)?;
        let receipt_key = ProvenanceRefKey::of(attribution.provenance_claim_id, &update.name);
        self.with_write_txn_grouped(|txn| {
            let held = CODE_OPERATIONS.get(&self.store, txn, &receipt_key)?;
            if let Some(old) = &held {
                if old.source != fresh.source {
                    return Err(Error::ConcurrentWrite("push source receipt changed"));
                }
                if old.operations != fresh.operations {
                    // An erase since the landing left the same operations
                    // naming no one: they landed, and their documents'
                    // receipts refuse a second ingress, so nothing runs again.
                    if landed_erased(&old.operations, &fresh.operations) {
                        return Ok(());
                    }
                    return Err(Error::ConcurrentWrite("push operation receipt changed"));
                }
            }
            // A conflicting aggregate must refuse before any document effect.
            // Both receipt layers commit together or the entire ref aborts.
            self.apply_code_file_ingress_exact_in_txn(txn, &mut ingress)?;
            // A replay keeps the first receipt time and any attached candidate.
            CODE_OPERATIONS.put(
                &self.store,
                txn,
                &receipt_key,
                held.as_ref().unwrap_or(&fresh),
            )?;
            Ok(())
        })
    }
    pub fn received_file_operations(
        &self,
        provenance: EntityId,
    ) -> Result<Vec<ReceivedFileOperation>> {
        let txn = self.store.env.read_txn()?;
        let mut operations = Vec::new();
        for (_, row) in CODE_OPERATIONS.scan_from(&self.store, &txn, provenance.as_bytes())? {
            operations.extend(row.operations);
        }
        operations.sort_by(|a, b| (&a.ref_name, &a.path).cmp(&(&b.ref_name, &b.path)));
        Ok(operations)
    }
    pub fn received_code_operations(&self, provenance: EntityId) -> Result<Vec<CodeEditReceipt>> {
        self.received_file_operations(provenance)?
            .iter()
            .filter(|row| row.document_edit)
            .map(|row| {
                self.code_file_edit_receipt(EntityId::from_hex(&row.operation_id)?)?
                    .ok_or(Error::CorruptedIndex("push operation absent"))
            })
            .collect()
    }
}
/// Whether `held`, a landed aggregate, is `fresh` with some operations
/// naming no one (FIX 4475): every other field matches, and where the two
/// differ the held one is erased. Erased never turns back into a live actor.
fn landed_erased(held: &[ReceivedFileOperation], fresh: &[ReceivedFileOperation]) -> bool {
    held.len() == fresh.len()
        && held.iter().zip(fresh).all(|(held, fresh)| {
            (held.actor_id == fresh.actor_id || held.actor_id == ERASED_CALL_IDENTITY)
                && ReceivedFileOperation {
                    actor_id: fresh.actor_id.clone(),
                    ..held.clone()
                } == *fresh
        })
}

/// Erasing `actor` from the push operation receipts (FIX 4475): each
/// operation it pushed keeps its id, session, ref, path, hashes, modes and
/// document flag and names no one. One-way, in the erase's own transaction.
/// An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a receipt row that cannot be read.
pub(crate) fn erase_code_operations_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::typed_body::names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let hex = actor.to_hex();
    let mut rows = Vec::new();
    for (key, mut row) in CODE_OPERATIONS.scan(&vault.store, wtxn)? {
        let mut named = false;
        for operation in &mut row.operations {
            if operation.actor_id == hex {
                operation.actor_id = ERASED_CALL_IDENTITY.to_owned();
                named = true;
            }
        }
        // The source and its candidate links stay; only actors are forgotten.
        if named {
            rows.push((key, row));
        }
    }
    for (key, row) in rows {
        CODE_OPERATIONS.put(&vault.store, wtxn, &key, &row)?;
    }
    Ok(())
}

fn bytes<'a>(files: &'a BTreeMap<String, super::tree::OriginTreeFile>, path: &str) -> &'a [u8] {
    files.get(path).map_or(b"", |file| file.content.as_slice())
}

/// The files `oid` names, a valid annotated-tag chain peeled to its end
/// however long (rule 5, FIX 9999): past its scan row the peel raises a check
/// and reads on. A malformed or looping chain still fails.
fn read_files(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    oid: &crate::git_wire::GitOid,
) -> Result<BTreeMap<String, super::tree::OriginTreeFile>> {
    let mut count = {
        let vault = wire.vault();
        let rtxn = vault.store.env.read_txn()?;
        ScanCount::start(
            &vault.store,
            &rtxn,
            EngineScan::OriginTagPeelSteps,
            repo.identity().as_hex().as_bytes(),
        )?
    };
    let mut seen = BTreeSet::new();
    let mut tip = oid.clone();
    loop {
        count.row();
        if !seen.insert(tip.clone()) {
            return Err(Error::CorruptedIndex("tag object chain loops"));
        }
        let kinds = wire.object_info(repo, std::slice::from_ref(&tip))?;
        match kinds.get(&tip).map(String::as_str) {
            Some("blob") => {
                count.finish(wire.vault());
                return Ok(BTreeMap::new());
            }
            Some("commit" | "tree") => {
                count.finish(wire.vault());
                return super::tree::read_tree_files(wire, repo, &tip);
            }
            Some("tag") => {
                let raw = wire.read_object(repo, &tip)?;
                let first = raw
                    .split(|b| *b == b'\n')
                    .next()
                    .and_then(|b| b.strip_prefix(b"object "))
                    .ok_or(Error::CorruptedIndex("tag object header"))?;
                tip = crate::git_wire::GitOid::parse_hex(
                    std::str::from_utf8(first)
                        .map_err(|_| Error::CorruptedIndex("tag object id"))?,
                )?;
            }
            _ => return Err(Error::EntityNotFound),
        }
    }
}
