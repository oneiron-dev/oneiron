//! Snapshot and membership encode/decode with strict guards.

use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::types::{
    CommunityCacheMeta, CommunityError, CommunityId, CommunityMembership, META_KEY,
    PPR_COMMUNITY_CACHE_PREFIX, PPR_COMMUNITY_CPM_GAMMA, PPR_COMMUNITY_SCHEMA_VERSION, Result,
};

impl CommunityCacheMeta {
    /// The unpublished v0 row also stores a writer-derived graph node count.
    /// Full decoding checks it against every node; indexed queries trust that
    /// atomic publication and never substitute the size of their selected view.
    pub(crate) fn decode_row(value: &[u8], max_nodes: usize) -> Result<(Self, usize)> {
        if value.len() != 29 {
            return Err(CommunityError::Cache);
        }
        let meta = Self {
            schema: value[0],
            graph_version: u64::from_le_bytes(array(&value[1..9])?),
            gamma: f32::from_le_bytes(array(&value[9..13])?),
            generated_at: u64::from_le_bytes(array(&value[13..21])?),
        };
        let count = usize::try_from(u64::from_le_bytes(array(&value[21..29])?))
            .map_err(|_| CommunityError::Cache)?;
        if meta.schema != PPR_COMMUNITY_SCHEMA_VERSION
            || meta.gamma != PPR_COMMUNITY_CPM_GAMMA
            || count > max_nodes
        {
            return Err(CommunityError::Cache);
        }
        Ok((meta, count))
    }
}

impl CommunityMembership {
    pub(crate) fn decode_row(value: &[u8]) -> Result<Self> {
        if value.len() != 32 {
            return Err(CommunityError::Cache);
        }
        Ok(Self {
            fine: CommunityId(array(&value[..16])?),
            coarse: CommunityId(array(&value[16..])?),
        })
    }
}

pub(crate) fn decode_community_members(
    id: CommunityId,
    value: &[u8],
    max_nodes: usize,
) -> Result<Vec<EntityId>> {
    if value.is_empty() || !value.len().is_multiple_of(16) || value.len() / 16 > max_nodes {
        return Err(CommunityError::Cache);
    }
    let members = value
        .chunks_exact(16)
        .map(|v| EntityId::from_bytes(array(v)?).map_err(|_| CommunityError::Cache))
        .collect::<Result<Vec<_>>>()?;
    if members.windows(2).any(|w| w[0] >= w[1]) || CommunityId::from_members(&members)? != id {
        return Err(CommunityError::Cache);
    }
    Ok(members)
}

#[derive(Debug, Clone, PartialEq)]
pub struct CommunitySnapshot {
    pub meta: CommunityCacheMeta,
    pub nodes: BTreeMap<EntityId, CommunityMembership>,
    pub members: BTreeMap<CommunityId, Vec<EntityId>>,
}

impl CommunitySnapshot {
    pub fn from_partitions(
        meta: CommunityCacheMeta,
        fine: &[Vec<EntityId>],
        coarse: &[Vec<EntityId>],
    ) -> Result<Self> {
        let mut snapshot = Self {
            meta,
            nodes: BTreeMap::new(),
            members: BTreeMap::new(),
        };
        let mut fine_ids = BTreeMap::new();
        for group in fine {
            let id = CommunityId::from_members(group)?;
            for &entity in group {
                if fine_ids.insert(entity, id).is_some() {
                    return Err(CommunityError::Cache);
                }
            }
        }
        for group in coarse {
            let coarse = CommunityId::from_members(group)?;
            for &entity in group {
                let fine = fine_ids.remove(&entity).ok_or(CommunityError::Cache)?;
                snapshot
                    .nodes
                    .insert(entity, CommunityMembership { fine, coarse });
            }
        }
        if !fine_ids.is_empty() {
            return Err(CommunityError::Cache);
        }
        snapshot.members = snapshot.expected_members()?;
        snapshot.validate(meta.graph_version)?;
        Ok(snapshot)
    }

    fn expected_members(&self) -> Result<BTreeMap<CommunityId, Vec<EntityId>>> {
        let mut fine: BTreeMap<CommunityId, Vec<EntityId>> = BTreeMap::new();
        let mut coarse: BTreeMap<CommunityId, Vec<EntityId>> = BTreeMap::new();
        let mut parents = BTreeMap::new();
        for (&entity, m) in &self.nodes {
            if parents
                .insert(m.fine, m.coarse)
                .is_some_and(|old| old != m.coarse)
            {
                return Err(CommunityError::Cache);
            }
            fine.entry(m.fine).or_default().push(entity);
            coarse.entry(m.coarse).or_default().push(entity);
        }
        let mut result = BTreeMap::new();
        for (id, members) in fine.into_iter().chain(coarse) {
            if CommunityId::from_members(&members)? != id {
                return Err(CommunityError::Cache);
            }
            if result
                .insert(id, members.clone())
                .is_some_and(|old| old != members)
            {
                return Err(CommunityError::Cache);
            }
        }
        Ok(result)
    }

    pub fn validate(&self, graph_version: u64) -> Result<()> {
        if self.meta.graph_version != graph_version {
            return Err(CommunityError::Version);
        }
        if self.meta.schema != PPR_COMMUNITY_SCHEMA_VERSION
            || self.meta.gamma != PPR_COMMUNITY_CPM_GAMMA
            || self.members != self.expected_members()?
        {
            return Err(CommunityError::Cache);
        }
        Ok(())
    }

    /// Canonical lowercase hex keys; binary values use fixed-width little endian.
    pub fn encode_rows(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        self.validate(self.meta.graph_version)?;
        let mut rows = BTreeMap::new();
        let mut meta = vec![self.meta.schema];
        meta.extend(self.meta.graph_version.to_le_bytes());
        meta.extend(self.meta.gamma.to_le_bytes());
        meta.extend(self.meta.generated_at.to_le_bytes());
        meta.extend((self.nodes.len() as u64).to_le_bytes());
        rows.insert(META_KEY.as_bytes().to_vec(), meta);
        for (entity, m) in &self.nodes {
            let mut value = m.fine.0.to_vec();
            value.extend(m.coarse.0);
            rows.insert(
                format!("{PPR_COMMUNITY_CACHE_PREFIX}node:{}", entity.to_hex()).into_bytes(),
                value,
            );
        }
        for (id, members) in &self.members {
            let value = members
                .iter()
                .flat_map(|e| e.as_bytes().iter().copied())
                .collect();
            rows.insert(
                format!("{PPR_COMMUNITY_CACHE_PREFIX}members:{}", id.to_hex()).into_bytes(),
                value,
            );
        }
        Ok(rows)
    }

    /// Decode a complete logical family only. Bound rows and member bytes before
    /// allocation; reject unknown keys, duplicates, reserved IDs and torn indexes.
    pub fn decode_rows(
        rows: &[(Vec<u8>, Vec<u8>)],
        version: u64,
        max_nodes: usize,
    ) -> Result<Self> {
        if rows.len() > max_nodes.saturating_mul(3).saturating_add(1) {
            return Err(CommunityError::Cache);
        }
        let mut seen = BTreeSet::new();
        let mut meta = None;
        let mut nodes = BTreeMap::new();
        let mut members = BTreeMap::new();
        let mut member_count = 0usize;
        for (key, value) in rows {
            if !seen.insert(key) {
                return Err(CommunityError::Cache);
            }
            let key = std::str::from_utf8(key).map_err(|_| CommunityError::Cache)?;
            if key == META_KEY {
                meta = Some(CommunityCacheMeta::decode_row(value, max_nodes)?);
            } else if let Some(hex) = key.strip_prefix("ppr_community_cache:v0:node:") {
                let id = EntityId::from_bytes(hex_id(hex)?).map_err(|_| CommunityError::Cache)?;
                if value.len() != 32 || nodes.len() >= max_nodes {
                    return Err(CommunityError::Cache);
                }
                nodes.insert(
                    id,
                    CommunityMembership {
                        fine: CommunityId(array(&value[..16])?),
                        coarse: CommunityId(array(&value[16..])?),
                    },
                );
            } else if let Some(hex) = key.strip_prefix("ppr_community_cache:v0:members:") {
                if value.is_empty() || !value.len().is_multiple_of(16) {
                    return Err(CommunityError::Cache);
                }
                member_count = member_count
                    .checked_add(value.len() / 16)
                    .ok_or(CommunityError::Cache)?;
                if member_count > max_nodes.saturating_mul(2) {
                    return Err(CommunityError::Cache);
                }
                let ids = value
                    .chunks_exact(16)
                    .map(|v| EntityId::from_bytes(array(v)?).map_err(|_| CommunityError::Cache))
                    .collect::<Result<Vec<_>>>()?;
                members.insert(CommunityId(hex_id(hex)?), ids);
            } else {
                return Err(CommunityError::Cache);
            }
        }
        let (meta, count) = meta.ok_or(CommunityError::Cache)?;
        if count != nodes.len() {
            return Err(CommunityError::Cache);
        }
        let snapshot = Self {
            meta,
            nodes,
            members,
        };
        snapshot.validate(version)?;
        Ok(snapshot)
    }
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| CommunityError::Cache)
}

fn hex_id(hex: &str) -> Result<[u8; 16]> {
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CommunityError::Cache);
    }
    let mut bytes = [0; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| CommunityError::Cache)?;
    }
    Ok(bytes)
}
