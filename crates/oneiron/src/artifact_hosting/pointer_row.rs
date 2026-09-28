//! Pinned code/blob pointer frames, including their serving tier.

use super::{
    ARTIFACT_POINTER_BLOB_TAG, ARTIFACT_POINTER_KEY_PREFIX, ARTIFACT_POINTER_STALE_OVERRIDE_STAMP,
    ArtifactExportRef, ArtifactLinkCapability, ArtifactPointerChannel, ArtifactServeTier,
    validate_artifact_id,
};
use crate::{
    EntityId,
    error::{Error, Result},
};
use heed::RwTxn;

pub(super) fn put_artifact_pointer_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &str,
    channel: ArtifactPointerChannel,
    export: ArtifactExportRef,
    stale_taint_override: bool,
    serve_tier: ArtifactServeTier,
) -> Result<()> {
    let key = artifact_pointer_key(artifact, channel)?;
    let mut value = match export {
        ArtifactExportRef::ForkHash(hash) => hash.to_vec(),
        ArtifactExportRef::BlobVersion {
            artifact_id,
            version,
        } => {
            let mut value = Vec::with_capacity(26);
            value.push(ARTIFACT_POINTER_BLOB_TAG);
            value.extend_from_slice(artifact_id.as_bytes());
            value.extend_from_slice(&version.to_be_bytes());
            value
        }
    };
    if stale_taint_override || serve_tier != ArtifactServeTier::Private {
        value.push(u8::from(stale_taint_override));
        match serve_tier {
            ArtifactServeTier::Private => {}
            ArtifactServeTier::Public => value.push(1),
            ArtifactServeTier::LinkToken(capability) => {
                value.push(2);
                value.extend_from_slice(&capability.0);
            }
            ArtifactServeTier::WorldMembers(world_id) => {
                if world_id == 0 {
                    return Err(Error::InvalidConfig(
                        "artifact world id cannot be zero".into(),
                    ));
                }
                value.push(3);
                value.extend_from_slice(&world_id.to_be_bytes());
            }
        }
    }
    store.vault_meta.put(wtxn, &key, &value)?;
    Ok(())
}

/// A deleted blob must not leave a channel that can spring back to life if
/// the caller later creates another version chain under the same entity id.
pub(crate) fn remove_blob_pointers_in_txn(
    store: &crate::store::Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let artifact = id.to_hex();
    for channel in [
        ArtifactPointerChannel::Published,
        ArtifactPointerChannel::Preview,
    ] {
        let key = artifact_pointer_key(&artifact, channel)?;
        if let Some(raw) = store.vault_meta.get(wtxn, &key)?
            && matches!(decode_artifact_pointer_row(&raw)?.0,
                ArtifactExportRef::BlobVersion { artifact_id, .. } if artifact_id == *id)
        {
            store.vault_meta.delete(wtxn, &key)?;
        }
    }
    Ok(())
}

pub(super) fn artifact_pointer_key(
    artifact: &str,
    channel: ArtifactPointerChannel,
) -> Result<Vec<u8>> {
    validate_artifact_id(artifact)?;
    let len = u16::try_from(artifact.len())
        .map_err(|_| Error::ArithmeticOverflow("artifact id length overflow"))?;
    let mut key = Vec::with_capacity(ARTIFACT_POINTER_KEY_PREFIX.len() + 1 + 2 + artifact.len());
    key.extend_from_slice(ARTIFACT_POINTER_KEY_PREFIX);
    key.push(channel.key_byte());
    key.extend_from_slice(&len.to_be_bytes());
    key.extend_from_slice(artifact.as_bytes());
    Ok(key)
}

/// Legacy 32/33-byte fork rows remain byte-identical. A blob row has a
/// disjoint 25/26-byte tagged frame: tag, entity id, big-endian version,
/// and the optional stale-taint override stamp.
pub(super) fn decode_artifact_pointer_row(
    raw: &[u8],
) -> Result<(ArtifactExportRef, bool, ArtifactServeTier)> {
    // Fork and blob base frames are disjoint lengths even with the tier suffix.
    let base_len = match raw.len() {
        32 | 33 | 34 | 42 | 66 => 32,
        25 | 26 | 27 | 35 | 59 => 25,
        _ => return Err(Error::CorruptedIndex("artifact pointer frame")),
    };
    let export = if base_len == 32 {
        ArtifactExportRef::ForkHash(
            raw[..32]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("artifact pointer fork hash"))?,
        )
    } else {
        if raw[0] != ARTIFACT_POINTER_BLOB_TAG {
            return Err(Error::CorruptedIndex("artifact pointer blob tag"));
        }
        let id = raw[1..17]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("artifact pointer blob id"))?;
        let artifact_id = EntityId::from_bytes(id)
            .map_err(|_| Error::CorruptedIndex("artifact pointer blob id"))?;
        let version = u64::from_be_bytes(
            raw[17..25]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("artifact pointer blob version"))?,
        );
        if version == 0 {
            return Err(Error::CorruptedIndex("artifact pointer blob version"));
        }
        ArtifactExportRef::BlobVersion {
            artifact_id,
            version,
        }
    };
    let (stale, tier) = match &raw[base_len..] {
        [] => (false, ArtifactServeTier::Private),
        [ARTIFACT_POINTER_STALE_OVERRIDE_STAMP] => (true, ArtifactServeTier::Private),
        [stamp @ (0 | 1), 1] => (*stamp == 1, ArtifactServeTier::Public),
        [stamp @ (0 | 1), 2, digest @ ..] if digest.len() == 32 => (
            *stamp == 1,
            ArtifactServeTier::LinkToken(ArtifactLinkCapability(
                digest
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("artifact token digest"))?,
            )),
        ),
        [stamp @ (0 | 1), 3, world @ ..] if world.len() == 8 => {
            let world_id = u64::from_be_bytes(
                world
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("artifact world id"))?,
            );
            if world_id == 0 {
                return Err(Error::CorruptedIndex("artifact world id"));
            }
            (*stamp == 1, ArtifactServeTier::WorldMembers(world_id))
        }
        _ => return Err(Error::CorruptedIndex("artifact pointer tier")),
    };
    Ok((export, stale, tier))
}
