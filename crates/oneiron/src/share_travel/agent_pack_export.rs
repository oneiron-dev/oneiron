//! `vault.agents.export_pack` (OF-491, FIX 2042): the sharing door for an
//! agent. It sends the reference-free AgentPack projection, never the native
//! facets an owner backup keeps. The sharer is the caller's own actor, and
//! everything the pack carries is read through the sharer's admission in one
//! snapshot: the definition, its skill packages, its knowledge, its world's
//! name and the born-with text the sharer chose (none by default; FIX 3307).
//! The share receipt is written before the folder leaves. The owner's own
//! share reads his private worlds too and names each one his recipient
//! choice would keep from where it goes (FIX 5493).

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use super::{BornWith, OmittedKnowledge, TravelChoice, TravelKind, WorldRecipientNotice};
use crate::agent_def::{AgentScope, decode_agent_definition};
use crate::batch::export::ExportEntity;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::memory::{Memory, MemoryResult};
use crate::ports::EntityStoreRead;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL, ENTITY_TYPE_WORLD,
};
use crate::serialize::ExportBody;

/// Which agent to share, and the born-with text to send with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackExportRequest {
    pub agent_ref: String,
    /// The born-with text to send with the pack; absent sends none (OF-491).
    #[serde(default)]
    pub travel: Option<TravelChoice>,
}

/// The travelling AgentPack folder, with what travelled and what stayed home.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPackExport {
    pub agent_ref: String,
    pub version: String,
    /// The canonical tree hash of `files`, lowercase hex.
    pub content_hash: String,
    pub born_with: BornWith,
    /// Knowledge claims kept home: a typed or ref-bearing value never travels.
    pub omitted: Vec<OmittedKnowledge>,
    pub files: Vec<AgentPackExportFile>,
    /// The owner's own export only: each world it carried that his recipient
    /// choice would keep from where it goes, and why (FIX 5493). His share
    /// receipt keeps the same notices.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notices: Vec<WorldRecipientNotice>,
}

/// One file of the folder, its bytes base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPackExportFile {
    pub path: String,
    pub content_base64: String,
}

/// What one read of the pack gathered in its one snapshot.
struct PackParts {
    version: String,
    files: Vec<crate::skill_hub::HubFile>,
    born_with: BornWith,
    omitted: Vec<crate::agent_def::OmittedClaim>,
    /// The owner's notices; `None` when a row he selected cannot be placed
    /// ([`super::pack_notice::owner_export_notices_in`]).
    notices: Option<Vec<WorldRecipientNotice>>,
}

impl Memory<'_> {
    /// `vault.agents.export_pack`: the agent's travelling AgentPack, read
    /// through the caller's admission, with a share receipt listing the
    /// born-with text that travelled and the knowledge that stayed home.
    /// The owner's own share is his will wherever it goes (FIX 5493): it
    /// carries his private worlds too, and names each one his recipient
    /// choice would have kept from there. Every other sharer's carries
    /// nothing of a world that choice keeps from where it goes (mesh PR2b).
    pub fn export_agent_pack(
        &self,
        input: &AgentPackExportRequest,
    ) -> MemoryResult<AgentPackExport> {
        let vault = self.vault();
        let agent = crate::memory::resolve_entity_ref(vault, &input.agent_ref)?;
        let choice = TravelChoice::or_default(input.travel.as_ref(), TravelKind::AgentPack);
        // Where the pack goes on from here: the machine this surface's
        // connection proved, judged for it; from this device, a recipient
        // nobody proved, since the pack travels on (CALLS `FIX 5493 local
        // export destination`).
        let onward = if self.destination().is_off_device() {
            self.destination().clone()
        } else {
            crate::claim::CallerLocality::OffDevice.into()
        };
        let on_device = crate::settings::ReadDestination::on_device();
        // Each lane opens its own snapshots before the read's one snapshot
        // (LMDB allows one per thread).
        let parts = match self.owner_export_lane(ClaimReadStatus::Recorded)? {
            // The owner reads as his own read and keeps no born-with text
            // back; each world his choice would keep from `onward` is named.
            // A row of his that cannot be placed overrides nothing: his share
            // then reads as it did before the ruling.
            Some(lane) => {
                let parts = pack_in(
                    vault,
                    &lane,
                    &agent,
                    &choice,
                    &on_device,
                    Some((self.destination(), &onward)),
                )?;
                if parts.notices.is_some() {
                    parts
                } else {
                    let lane = self.read_lane(ClaimReadStatus::Recorded)?;
                    pack_in(vault, &lane, &agent, &choice, &on_device, None)?
                }
            }
            None => {
                let lane = self.read_lane(ClaimReadStatus::Recorded)?;
                pack_in(vault, &lane, &agent, &choice, &onward, None)?
            }
        };
        let PackParts {
            version,
            files,
            born_with,
            omitted,
            notices,
        } = parts;
        let notices = notices.unwrap_or_default();
        let content_hash = crate::skill::canonical_skill_tree_hash(
            files
                .iter()
                .map(|file| (file.path.as_str(), file.content.as_slice())),
        )?
        .to_hex();
        let omitted: Vec<OmittedKnowledge> = omitted
            .iter()
            .map(|row| OmittedKnowledge::new(row.claim, row.reason))
            .collect();
        vault.record_agent_pack_travel(
            &agent,
            version.clone(),
            content_hash.clone(),
            &self.actor(),
            &born_with,
            omitted.clone(),
            notices.clone(),
        )?;
        Ok(AgentPackExport {
            agent_ref: agent.to_hex(),
            version,
            content_hash,
            born_with,
            omitted,
            files: files
                .into_iter()
                .map(|file| AgentPackExportFile {
                    content_base64: base64::engine::general_purpose::STANDARD.encode(&file.content),
                    path: file.path,
                })
                .collect(),
            notices,
        })
    }
}

/// The pack `lane` reads of `agent` in one snapshot: the definition, its
/// skill packages, its knowledge, its world's name and the born-with text
/// `choice` names, none a world kept from `recipient` holds. With `warn`
/// (the owner's own share: the machine this surface proved, and where the
/// pack goes on to), the notices for the worlds behind the bytes it selected,
/// judged in the same snapshot.
fn pack_in(
    vault: &crate::Vault,
    lane: &ScopedRead<'_>,
    agent: &EntityId,
    choice: &TravelChoice,
    recipient: &crate::settings::ReadDestination,
    warn: Option<(
        &crate::settings::ReadDestination,
        &crate::settings::ReadDestination,
    )>,
) -> MemoryResult<PackParts> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let Some((ENTITY_TYPE_AGENT_DEF, _, body)) = admitted(lane, &txn, agent)? else {
        return Err(Error::EntityNotFound.into());
    };
    let kept = crate::settings::device_local_worlds_for(vault, &txn, recipient)?;
    let text = super::born_with_text_in_txn(vault, &txn, lane, agent, None, choice, &kept)?;
    let def = decode_agent_definition(&body)?;
    let mut skills = Vec::new();
    for id in EntityStoreRead::port_entity_ids_by_type(&vault.store, &txn, ENTITY_TYPE_SKILL, None)?
    {
        let id = id?;
        if let Some((ENTITY_TYPE_SKILL, _, body)) = admitted(lane, &txn, &id)?
            && let Ok(record) = crate::skill::decode_skill_record(&body)
        {
            skills.push((id, record));
        }
    }
    let refs = crate::agent_def::resolve_agent_skill_refs(&def, &skills).ok_or_else(|| {
        Error::InvalidConfig(
            "agent pack: a skill dependency is missing, ambiguous or unpinned".into(),
        )
    })?;
    let mut packages = BTreeMap::new();
    for reference in &refs {
        let id = EntityId::from_hex(reference.entity_id())?;
        if let Some(package) = vault.export_hub_package_in_txn(&txn, &id)? {
            packages.insert(id, package);
        }
    }
    let mut claims = Vec::new();
    for id in vault.claims_for_subject_in_txn(&txn, agent)? {
        if let Some((ENTITY_TYPE_CLAIM, header, body)) = admitted(lane, &txn, &id)? {
            claims.push(ExportEntity {
                short_ref: None,
                id: id.to_hex(),
                entity_type: ENTITY_TYPE_CLAIM,
                occurred_start: header.occurred_start,
                occurred_end: header.occurred_end,
                learned_at: header.learned_at,
                body: ExportBody::from_bytes(&body, ENTITY_TYPE_CLAIM),
            });
        }
    }
    let scope_world = match def.scope {
        AgentScope::World(world) => Some(world),
        AgentScope::All | AgentScope::Base => None,
    };
    let world_name = match scope_world {
        Some(world) => match admitted(lane, &txn, &world)? {
            Some((ENTITY_TYPE_WORLD, _, body)) => world_name(&body),
            _ => None,
        },
        None => None,
    };
    let (files, born_with, omitted) = crate::agent_def::agent_pack_files_travelling(
        agent,
        &def,
        &refs,
        &packages,
        &claims,
        world_name.as_deref(),
        text,
        choice,
    )?;
    let notices = match warn {
        None => Some(Vec::new()),
        Some((actual, onward)) => {
            // The rows whose bytes the pack carries: the definition, each
            // skill package, the knowledge that travelled as text, the
            // world its scope named and the born-with text's rows.
            let home: BTreeSet<EntityId> = omitted.iter().map(|row| row.claim).collect();
            let mut rows = vec![*agent];
            rows.extend(packages.keys().copied());
            rows.extend(
                crate::agent_def::select_agent_knowledge(agent, &claims)
                    .iter()
                    .filter_map(|row| EntityId::from_hex(&row.id).ok())
                    .filter(|id| !home.contains(id)),
            );
            rows.extend(scope_world.filter(|_| world_name.is_some()));
            rows.extend(super::pack_notice::born_with_rows_in(
                vault, &txn, lane, agent, &born_with,
            )?);
            super::pack_notice::owner_export_notices_in(vault, &txn, &rows, actual, onward)?
        }
    };
    drop(txn);
    Ok(PackParts {
        version: def.version,
        files,
        born_with,
        omitted,
        notices,
    })
}

/// `id` as the sharer's lane admits it in `txn`: its type, header and live
/// body. `None` when the lane withholds it.
fn admitted(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> crate::Result<Option<(u8, EntityMetadataHeader, Vec<u8>)>> {
    let Some(raw) = lane.entity_raw_live_in(txn, id)? else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("agent pack header"))?;
    Ok(Some((
        header.entity_type,
        header,
        raw[ENTITY_METADATA_HEADER_LEN..].to_vec(),
    )))
}

/// A WORLD body's travelling name: its `label` leaf, else its `name` leaf.
/// A body that reads whole as a secret has none, and a world with no name
/// cannot scope a travelling pack.
pub(super) fn world_name(body: &[u8]) -> Option<String> {
    let value = rmpv::decode::read_value(&mut &body[..]).ok()?;
    if crate::batch::secret_scan::release_body_reads_whole_as_stored(&value, body) {
        return None;
    }
    let rmpv::Value::Map(entries) = value else {
        return None;
    };
    ["label", "name"].into_iter().find_map(|key| {
        entries
            .iter()
            .find(|(entry, _)| entry.as_str() == Some(key))
            .and_then(|(_, value)| value.as_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    })
}
