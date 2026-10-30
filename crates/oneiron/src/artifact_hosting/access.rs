//! Serve-time authority for live artifact pointers.

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::federation::{FederationGrantScope, decode_federation_grant_body};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use rand_core::{OsRng, RngCore};

/// Digest of a randomly minted URL capability. The secret itself is never persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ArtifactLinkCapability(pub(super) [u8; 32]);

/// Authority attached to one live pointer, never to an unpinned snapshot.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub enum ArtifactServeTier {
    #[default]
    Private,
    Public,
    LinkToken(ArtifactLinkCapability),
    WorldMembers(u64),
}

impl ArtifactServeTier {
    /// Mint 256 bits of OS entropy and return the URL token once. The pointer
    /// and publish admission retain only its domain-separated digest.
    #[must_use]
    pub fn mint_link_token() -> (Self, String) {
        let mut secret = [0_u8; 32];
        OsRng.fill_bytes(&mut secret);
        let token = artifact_hex(&secret);
        (
            Self::LinkToken(ArtifactLinkCapability(link_digest(&secret))),
            token,
        )
    }
}

fn link_digest(token: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("oneiron artifact link token v1", token)
}

fn matches_token(capability: ArtifactLinkCapability, token: Option<&str>) -> bool {
    let Some(token) = token.and_then(|value| parse_codebase_fork_hash_hex(value).ok()) else {
        return false;
    };
    // Compare every byte without an early mismatch branch.
    let candidate = link_digest(&token);
    let mut diff = 0_u8;
    for (a, b) in capability.0.iter().zip(candidate.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// One read-view-resolved export. Scope comes from the owner's digest-bound
/// stored record, not a kind-only guess or a caller-supplied world id.
struct ResolvedArtifactTarget {
    pointer: ArtifactPointer,
    owner: EntityId,
    scope: crate::federation::Scope,
    snapshot: Option<CodebaseSnapshot>,
}

/// Constructed only after pointer, credential tier, grant and target Scope
/// agree. The byte reader consumes this exact target, never a bare hash lookup.
struct AuthorizedArtifactRead {
    target: ResolvedArtifactTarget,
    selector: ArtifactSnapshotSelector,
}

impl Vault {
    pub fn resolve_authorized_artifact_file(
        &self,
        artifact: &str,
        selector: ArtifactSnapshotSelector,
        path: &str,
        token: Option<&str>,
        principal: Option<EntityId>,
    ) -> Result<Option<ArtifactServedFile>> {
        validate_artifact_id(artifact)?;
        validate_artifact_path(path)?;
        let txn = self.store.env.read_txn()?;
        let channels: &[ArtifactPointerChannel] = match selector {
            ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published) => {
                &[ArtifactPointerChannel::Published]
            }
            ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Preview) => {
                &[ArtifactPointerChannel::Preview]
            }
            ArtifactSnapshotSelector::ForkHash(_) | ArtifactSnapshotSelector::BlobVersion(_) => &[
                ArtifactPointerChannel::Published,
                ArtifactPointerChannel::Preview,
            ],
        };
        for channel in channels {
            let Some(target) = self.resolve_artifact_target_in_txn(&txn, artifact, *channel)?
            else {
                continue;
            };
            let pinned = match target.pointer.export {
                ArtifactExportRef::ForkHash(hash) => ArtifactSnapshotSelector::ForkHash(hash),
                ArtifactExportRef::BlobVersion { version, .. } => {
                    ArtifactSnapshotSelector::BlobVersion(version)
                }
            };
            if !matches!(selector, ArtifactSnapshotSelector::Channel(_)) && selector != pinned {
                continue;
            }
            let allowed = match target.pointer.serve_tier {
                ArtifactServeTier::Private => false,
                ArtifactServeTier::Public => true,
                ArtifactServeTier::LinkToken(capability) => matches_token(capability, token),
                ArtifactServeTier::WorldMembers(world_id) => principal.is_some_and(|member| {
                    self.artifact_world_member_in_txn(&txn, world_id, member, &target.scope)
                        .unwrap_or(false)
                }),
            };
            if !allowed {
                continue;
            }
            let read = AuthorizedArtifactRead { target, selector };
            return self.read_authorized_artifact_in_txn(&txn, artifact, path, read);
        }
        Ok(None)
    }

    fn resolve_artifact_target_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &str,
        channel: ArtifactPointerChannel,
    ) -> Result<Option<ResolvedArtifactTarget>> {
        validate_artifact_id(artifact)?;
        let key = ArtifactPointerRowKey {
            channel,
            artifact: artifact.to_owned(),
        };
        let Some(ArtifactPointerRow {
            export,
            stale_taint_override,
            serve_tier,
        }) = ARTIFACT_POINTERS.get(&self.store, txn, &key)?
        else {
            return Ok(None);
        };
        let (owner, snapshot) = match export {
            ArtifactExportRef::ForkHash(hash) => {
                let mut match_owner = None;
                for id in self.codebase_snapshots_by_fork_hash_in_txn(txn, &hash)? {
                    if crate::codebase::codebase_artifact_snapshot_matches_in_txn(
                        &self.store,
                        txn,
                        &id,
                        artifact,
                        &hash,
                    )? {
                        let snapshot = self
                            .get_codebase_snapshot_in_txn(txn, &id)?
                            .ok_or(Error::CorruptedIndex("artifact snapshot owner"))?;
                        match_owner = Some((id, Some(snapshot)));
                        break;
                    }
                }
                let Some(owner) = match_owner else {
                    return Ok(None);
                };
                owner
            }
            ArtifactExportRef::BlobVersion { .. } => {
                let Some(id) = self.resolve_export_owner_in_txn(txn, artifact, export)? else {
                    return Ok(None);
                };
                (id, None)
            }
        };
        let raw_owner = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &owner)?
            .ok_or(Error::CorruptedIndex("artifact owner record"))?;
        let Some(scope) =
            crate::federation::record_scope::scope_for_blob(&self.store, txn, owner, &raw_owner)?
        else {
            return Ok(None);
        };
        Ok(Some(ResolvedArtifactTarget {
            pointer: ArtifactPointer {
                artifact: artifact.to_owned(),
                channel,
                export,
                stale_taint_override,
                serve_tier,
            },
            owner,
            scope,
            snapshot,
        }))
    }

    fn artifact_world_member_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        world_id: u64,
        principal: EntityId,
        target_scope: &crate::federation::Scope,
    ) -> Result<bool> {
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        let now = self.store.clock.now_recorded_at();
        for row in crate::ports::EntityStoreRead::port_entity_ids_by_type(
            &self.store,
            txn,
            ENTITY_TYPE_FEDERATION_GRANT,
            None,
        )? {
            let id = row?;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)?
                .ok_or(Error::CorruptedIndex("artifact membership grant row"))?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("artifact membership grant header"))?;
            if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
                return Err(Error::CorruptedIndex("artifact membership grant type"));
            }
            // A deleted grant is no membership: its shell is skipped here, and a
            // stored body counts only while its row is live, checked last.
            if raw.len() == ENTITY_METADATA_HEADER_LEN
                && !crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.is_live()
            {
                continue;
            }
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if grant.scope == FederationGrantScope::vault(world_id)
                && grant.member_ref == principal
                && grant.confers_at(now)
                && matches!(
                    crate::authority::federation_grant_activation(&fold, &id),
                    crate::authority::FederationGrantActivation::Unpacted
                        | crate::authority::FederationGrantActivation::Active
                )
                && grant.authority_scope.admits(
                    "read",
                    target_scope,
                    &crate::federation::Scope::top(),
                )
                && crate::vault::live_entity_row_in_txn(&self.store, txn, &id)?.is_live()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read_authorized_artifact_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        artifact: &str,
        path: &str,
        read: AuthorizedArtifactRead,
    ) -> Result<Option<ArtifactServedFile>> {
        let target = read.target;
        // The export's taint is read again in this view before any byte is
        // read (FIX 9574): a stale one serves only under its pointer's stamp
        // while the stale-publish policy still permits it.
        let refs = exhaust_taint_refs_in_txn(&self.store, txn, &target.owner)?;
        let stale = matches!(
            taint_state_for_refs_in_txn(&self.store, txn, &refs)?,
            ArtifactTaintState::TaintedStale
        );
        if stale
            && !(target.pointer.stale_taint_override
                && allow_stale_publish_in_txn(&self.store, txn)?)
        {
            return Ok(None);
        }
        // A hosted reader is never the owner verified at a door (OF-560): the
        // bytes it reads are masked. A body kept in its ASSET's file is masked
        // as it is read, never held whole beside its copy (FIX 6507).
        let sight = crate::secret_custody::SecretSight::Masked;
        let (bytes, media_type, hash) = match target.pointer.export {
            ArtifactExportRef::ForkHash(hash) => {
                let Some(snapshot) = target.snapshot else {
                    return Ok(None);
                };
                let Some(entry) = snapshot_file_entry(&snapshot, path) else {
                    return Ok(None);
                };
                if snapshot.project_id != artifact || snapshot.fork_hash != hash {
                    return Ok(None);
                }
                // A file the snapshot's custody report quarantines is served
                // to no one (OF-067).
                if self
                    .codebase_withheld_paths_in_txn(txn, &hash)?
                    .contains(path)
                {
                    return Ok(None);
                }
                // A file a repo mark covers is served as its projection,
                // found before its bytes are read, under its own hash (FIX 7608).
                if let Some(copy) = self.repo_marked_asset_copy_in_txn(txn, &entry.content_hash)? {
                    let bytes = copy.into_bytes();
                    let hash = *blake3::hash(&bytes).as_bytes();
                    (bytes, None, hash)
                } else {
                    let asset = crate::codebase::snapshot_asset_entity_id(&entry.content_hash)?;
                    let bytes = match self.sighted_body_file_in_txn(
                        txn,
                        &asset,
                        &entry.content_hash,
                        sight,
                    )? {
                        Some(bytes) => bytes,
                        None => self.masked_whole_in_txn(
                            txn,
                            crate::codebase::read_asset_blob_in_txn(
                                self,
                                txn,
                                &entry.content_hash,
                            )?,
                            &entry.content_hash,
                        )?,
                    };
                    (bytes, None, entry.content_hash)
                }
            }
            ArtifactExportRef::BlobVersion {
                artifact_id,
                version,
            } => {
                if artifact_id != target.owner || artifact != artifact_id.to_hex() {
                    return Ok(None);
                }
                // A replica serves from its descriptor (FIX 1195).
                let Some(serving) = self.serving_blob_in_txn(txn, &artifact_id, version)? else {
                    return Ok(None);
                };
                if path != "export" && path != "index.html" && path != serving.export_name {
                    return Ok(None);
                }
                let Some(bytes) =
                    self.read_serving_blob_in_txn(txn, &artifact_id, &serving, sight)?
                else {
                    return Ok(None);
                };
                (bytes, Some(serving.export_media_type), serving.content_hash)
            }
        };
        // A DOCX copy shows its default author (FIX 4513).
        let bytes = self.resolve_docx_authors_in_txn(txn, bytes)?;
        let size_bytes = u64::try_from(bytes.len())
            .map_err(|_| Error::ArithmeticOverflow("artifact served length"))?;
        Ok(Some(ArtifactServedFile {
            artifact: artifact.to_owned(),
            selector: read.selector,
            serve_tier: target.pointer.serve_tier,
            export: target.pointer.export,
            path: path.to_owned(),
            media_type,
            content_hash: hash,
            size_bytes,
            bytes,
        }))
    }

    /// The stored `bytes` a hosted reader reads whole, checked against
    /// `hash` and masked (OF-560).
    fn masked_whole_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        bytes: Vec<u8>,
        hash: &[u8; 32],
    ) -> Result<Vec<u8>> {
        if blake3::hash(&bytes).as_bytes() != hash {
            return Err(Error::CorruptedIndex("artifact served content hash"));
        }
        crate::secret_custody::sighted_bytes_in_txn(
            &self.store,
            txn,
            bytes,
            Some(hash),
            crate::secret_custody::SecretSight::Masked,
        )
    }
}
