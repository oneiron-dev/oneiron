//! Serve-time authority for live artifact pointers.

use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::federation::{FederationGrantScope, decode_federation_grant_body};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use rand_core::{OsRng, RngCore};

/// Digest of a randomly minted URL capability. The secret itself is never persisted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactLinkCapability(pub(super) [u8; 32]);

/// Authority attached to one live pointer, never to an unpinned snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
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

impl Vault {
    /// Only an authorized, LIVE pointer may expose a file, including a hash URL.
    /// The granted pointer's hash is passed to the resolver, not a later pointer
    /// read; repointing cannot turn an earlier authorization into a new fork.
    pub fn resolve_authorized_artifact_file(
        &self,
        artifact: &str,
        selector: ArtifactSnapshotSelector,
        path: &str,
        token: Option<&str>,
        principal: Option<EntityId>,
    ) -> Result<Option<ArtifactServedFile>> {
        let channels: &[ArtifactPointerChannel] = match selector {
            ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Published) => {
                &[ArtifactPointerChannel::Published]
            }
            ArtifactSnapshotSelector::Channel(ArtifactPointerChannel::Preview) => {
                &[ArtifactPointerChannel::Preview]
            }
            ArtifactSnapshotSelector::ForkHash(_) => &[
                ArtifactPointerChannel::Published,
                ArtifactPointerChannel::Preview,
            ],
        };
        for channel in channels {
            let Some(pointer) = self.artifact_pointer(artifact, *channel)? else {
                continue;
            };
            if let ArtifactSnapshotSelector::ForkHash(hash) = selector
                && hash != pointer.fork_hash
            {
                continue;
            }
            let allowed = match pointer.serve_tier {
                ArtifactServeTier::Private => false,
                ArtifactServeTier::Public => true,
                ArtifactServeTier::LinkToken(capability) => matches_token(capability, token),
                ArtifactServeTier::WorldMembers(world_id) => principal.is_some_and(|principal| {
                    self.artifact_world_member(world_id, principal)
                        .unwrap_or(false)
                }),
            };
            if !allowed {
                continue;
            }
            let mut file = self.resolve_artifact_file(
                artifact,
                ArtifactSnapshotSelector::ForkHash(pointer.fork_hash),
                path,
            )?;
            if let Some(file) = &mut file {
                file.selector = selector;
                file.serve_tier = pointer.serve_tier;
            }
            return Ok(file);
        }
        Ok(None)
    }

    fn artifact_world_member(&self, world_id: u64, principal: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        let fold = self.authority_fold_readonly_in_txn(&txn)?;
        let now = self.store.clock.now_recorded_at();
        for row in self
            .store
            .type_index
            .prefix_iter(&txn, &[ENTITY_TYPE_FEDERATION_GRANT])?
        {
            let (key, _) = row?;
            let id = crate::vault::entity_id_from_type_index_key(&key)?;
            let raw = self
                .store
                .entities
                .get(&txn, id.as_bytes())?
                .ok_or(Error::CorruptedIndex("artifact membership grant row"))?;
            let header = EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("artifact membership grant header"))?;
            if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
                return Err(Error::CorruptedIndex("artifact membership grant type"));
            }
            let grant = decode_federation_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
            if grant.scope == FederationGrantScope::vault(world_id)
                && grant.member_ref == principal
                && grant.confers_at(now)
                && fold.pact_for_grant(&id).is_none_or(|pact| {
                    pact.status == crate::authority::FederationPactStatus::Active
                })
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
