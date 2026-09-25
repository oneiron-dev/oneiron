//! Crash-idempotent push-to-document lowering under the origin single-writer lock.
use super::smart_http::{ReceivePackAttribution, RefUpdate};
use crate::code_document::{CodeEditReceipt, CodeFileEdit, CodeFileIngress};
use crate::codebase::entity_id_from_hash_material;
use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::git_wire::{GitWire, GitWireRepo};
use crate::write_envelope::WriteActor;
use crate::{EntityId, TimeRange, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// One push operation, including non-text blobs and mode-only changes.
/// Git objects remain pinned by the hash-keyed origin change claim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReceivedFileOperation {
    pub operation_id: String,
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
fn key(provenance: EntityId) -> Vec<u8> {
    [
        b"origin:code_operations:v1:".as_slice(),
        provenance.as_bytes(),
    ]
    .concat()
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
            let scope = format!("origin:{}:{}", repo.identity().as_hex(), update.name);
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
                        ingress.push(CodeFileIngress {
                            operation,
                            session: document,
                            edit: CodeFileEdit::between(&path, before, after),
                            actor: WriteActor::new(attribution.actor_id, EdgeActorClass::System),
                            expected_text: before.to_owned(),
                        });
                        true
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
        let encoded = rmp_serde::to_vec(&operations)
            .map_err(|_| Error::CorruptedIndex("push operations encode"))?;
        let receipt_key = [
            key(attribution.provenance_claim_id),
            b":".to_vec(),
            blake3::hash(update.name.as_bytes()).as_bytes().to_vec(),
        ]
        .concat();
        self.with_write_txn(|txn| {
            if let Some(old) = self.store.vault_meta.get(txn, &receipt_key)?
                && old.as_ref() != encoded
            {
                return Err(Error::ConcurrentWrite("push operation receipt changed"));
            }
            // A conflicting aggregate must refuse before any document effect.
            // Both receipt layers commit together or the entire ref aborts.
            self.apply_code_file_ingress_exact_in_txn(txn, &mut ingress)?;
            self.store.vault_meta.put(txn, &receipt_key, &encoded)?;
            Ok(())
        })
    }
    pub fn received_file_operations(
        &self,
        provenance: EntityId,
    ) -> Result<Vec<ReceivedFileOperation>> {
        let txn = self.store.env.read_txn()?;
        let mut operations = Vec::new();
        for row in self.store.vault_meta.prefix_iter(&txn, &key(provenance))? {
            let (_, raw) = row?;
            let rows: Vec<ReceivedFileOperation> = rmp_serde::from_slice(&raw)
                .map_err(|_| Error::CorruptedIndex("push operation receipt decode"))?;
            operations.extend(rows);
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
fn bytes<'a>(files: &'a BTreeMap<String, super::tree::OriginTreeFile>, path: &str) -> &'a [u8] {
    files.get(path).map_or(b"", |file| file.content.as_slice())
}

fn read_files(
    wire: &GitWire<'_>,
    repo: &GitWireRepo,
    oid: &crate::git_wire::GitOid,
) -> Result<BTreeMap<String, super::tree::OriginTreeFile>> {
    let mut tip = oid.clone();
    for _ in 0..64 {
        let kinds = wire.object_info(repo, std::slice::from_ref(&tip))?;
        match kinds.get(&tip).map(String::as_str) {
            Some("blob") => return Ok(BTreeMap::new()),
            Some("commit" | "tree") => return super::tree::read_tree_files(wire, repo, &tip),
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
    Err(Error::IndexOverflow("nested origin tags"))
}
