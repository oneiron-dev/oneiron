//! Path parsing and the lane helpers of the Graph-FS directory read (moved from `readdir.rs`, FIX 19106).

use super::*;

/// Whether `lane` may walk into `world` (`None` is base reality) in `rtxn`,
/// judged as claim admission judges a claim's world: the lane must read
/// some row ([`lane_reads_some_row`]), its credential must be live, and the
/// worlds the read asked for and its Scope must admit `world`; the owner then
/// reads every world of their vault (ARCH-0057). Any other reader reads where
/// a read grant for it reads the world
/// ([`crate::gate::scoped_read_grant_reads_world`]), anywhere while the
/// manifest holds no read grant, and, with a credential no grant names,
/// wherever that credential reads.
pub(super) fn lane_walks_world(
    lane: &ScopedRead<'_>,
    rtxn: &heed::RoTxn<'_>,
    policy: &PolicyManifestResolution,
    world: Option<EntityId>,
) -> Result<bool> {
    let key = lane.actor_key();
    if !lane_reads_some_row(lane, policy) || !lane.world_readable_in(rtxn, world)? {
        return Ok(false);
    }
    if key.vault_owner_ref().is_some() {
        return Ok(true);
    }
    if !policy.has_scoped_read_grants() {
        return Ok(true);
    }
    let mut matched = false;
    for grant in policy.scoped_grants() {
        if !read_grant_matches_actor(grant, key) {
            continue;
        }
        matched = true;
        if lane.vault().store.gate_hooks.scoped_read_grant_reads_world(
            grant,
            world,
            key.authority_scope(),
        ) {
            return Ok(true);
        }
    }
    Ok(key.authority_scope().is_some() && !matched)
}

/// Whether `lane`'s ordinary reads could admit any row under `policy`: the
/// retrieval floor every read applies leaves some row
/// ([`crate::gate::RetrievalPolicyFloor::reads_some_row`]). A credential
/// without the read verb, or with its bands, audience, sensitivity or worlds
/// at bottom, a fail-closed manifest, grants that read nothing, and a
/// credential whose bands share no type with its grants' each leave it none,
/// so it walks no world either (Sol R7-003, R11-001).
pub(super) fn lane_reads_some_row(
    lane: &ScopedRead<'_>,
    policy: &PolicyManifestResolution,
) -> bool {
    policy
        .retrieval_floor_for_actor(Some(lane.actor_key()))
        .reads_some_row()
}

pub(in crate::graph_fs) fn empty_page(path: &str, mount: GraphFsMount) -> GraphFsPage {
    GraphFsPage {
        path: path.to_owned(),
        mount,
        entries: Vec::new(),
        next_cursor: None,
        byte_count: 0,
        read_receipt: None,
        entry_cursors: Vec::new(),
    }
}

pub(in crate::graph_fs) fn normalize_path(path: &str) -> Result<String> {
    if !path.starts_with('/') {
        return Err(Error::InvalidConfig(
            "graph-fs path must be absolute".to_owned(),
        ));
    }
    let normalized = path.trim_end_matches('/');
    if normalized.is_empty() {
        Ok("/".to_owned())
    } else {
        path_components(normalized)?;
        Ok(normalized.to_owned())
    }
}

pub(in crate::graph_fs) fn path_components(path: &str) -> Result<Vec<&str>> {
    if path == "/" {
        return Ok(Vec::new());
    }
    let mut components = Vec::new();
    for component in path.trim_start_matches('/').split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(Error::InvalidConfig(
                "graph-fs path component is invalid".to_owned(),
            ));
        }
        components.push(component);
    }
    Ok(components)
}

pub(in crate::graph_fs) fn parse_entity_id(value: &str) -> Result<EntityId> {
    EntityId::from_hex(value)
}

pub(super) fn parse_world_scope(value: &str) -> Result<Option<EntityId>> {
    if value == "base" {
        Ok(None)
    } else {
        parse_entity_id(value).map(Some)
    }
}

/// A walk passes over sealed secret custody as absent rather than failing:
/// it is never part of the tree, and a raw read of it still refuses.
pub(in crate::graph_fs) fn sealed_is_absent(readable: Result<bool>) -> Result<bool> {
    match readable {
        Err(error) if error.kind() == crate::error::ErrorKind::InvalidSecretCustodyBody => {
            Ok(false)
        }
        readable => readable,
    }
}
