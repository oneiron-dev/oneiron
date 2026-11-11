//! Frozen source tree identity at genuine local birth. Not an execution grant.
use super::portable::{agent_pack_files, resolve_agent_skill_refs, select_agent_knowledge};
use super::{AgentDefinition, decode_agent_definition};
use crate::batch::export::ExportEntity;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_SKILL};
use crate::scan_check::{EngineScan, ScanCount};
use crate::serialize::ExportBody;
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::skill::{SkillContentHash, decode_skill_record};
use crate::store::Store;

// Rows a source composition read takes past which it asks whether everything
// is okay: the count it once refused past. The read never truncates a hashed
// tree and never refuses for its count (rule 5).
const SOURCE_SCAN_CHECK: u64 = 100_000;

/// Frozen source-tree identity recorded at an agent's genuine local birth:
/// which source it was captured from, and the skill content hash that source
/// resolved to at capture time.
struct PortableBirthBinding {
    source: EntityId,
    hash: SkillContentHash,
}

impl RawValue for PortableBirthBinding {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut bytes = self.source.as_bytes().to_vec();
        bytes.extend_from_slice(self.hash.as_bytes());
        Ok(bytes)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        if bytes.len() != 48 {
            return Err(Error::CorruptedIndex("agent portable birth binding").into());
        }
        let source = crate::entity_id::parse_entity_id(&bytes[..16], "agent portable source")?;
        let hash: [u8; 32] = bytes[16..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("agent portable hash"))?;
        Ok(Self {
            source,
            hash: SkillContentHash::from_bytes(hash),
        })
    }
}

const PORTABLE_BIRTH: SideTable<EntityId, PortableBirthBinding, Raw> =
    SideTable::new(&side_table::AGENT_DEF_PORTABLE_BIRTH);

pub(crate) fn agent_fork_hash_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<SkillContentHash>> {
    if let Some(binding) = PORTABLE_BIRTH.get(store, txn, id)? {
        return Ok(Some(binding.hash));
    }
    super::read_birth_source(store, txn, id)?
        .map(|source| {
            crate::skill::SkillContentHash::parse_hex(
                source
                    .tree
                    .content_hash
                    .as_deref()
                    .ok_or_else(|| Error::CorruptedIndex("birth source hash"))?,
            )
        })
        .transpose()
}

fn put_binding(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    source: &EntityId,
    hash: SkillContentHash,
) -> Result<()> {
    PORTABLE_BIRTH.put(
        store,
        txn,
        id,
        &PortableBirthBinding {
            source: *source,
            hash,
        },
    )
}

/// Called only in apply_put's genuine local AGENT_DEF create arm. If a native
/// composition is not hash-resolvable, leave the binding absent. Never backfill
/// a historic fork from whatever its parent happens to contain at export time.
pub(crate) fn bind_agent_birth_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    created: &AgentDefinition,
) -> Result<Option<(EntityId, Vec<u8>)>> {
    let Some(snapshot) = agent_birth_snapshot_in_txn(store, txn, id, created)? else {
        return Ok(None);
    };
    put_binding(store, txn, id, &snapshot.source, snapshot.hash)?;
    snapshot.encode(id, created).map(Some)
}

struct AgentBirthSnapshot {
    source: EntityId,
    definition: AgentDefinition,
    tree: crate::batch::export::ExportFileTree,
    hash: SkillContentHash,
}

impl AgentBirthSnapshot {
    fn encode(self, id: &EntityId, created: &AgentDefinition) -> Result<(EntityId, Vec<u8>)> {
        super::portable_source::encode_birth_source(
            id,
            created,
            &self.source,
            &self.definition,
            self.tree,
        )
    }
}

pub(crate) struct PreparedAgentBirth {
    source: EntityId,
    hash: SkillContentHash,
    asset: (EntityId, Vec<u8>),
}

impl PreparedAgentBirth {
    pub(crate) fn entity(&self) -> EntityId {
        self.asset.0
    }

    pub(super) fn entity_put(&self) -> (EntityId, &[u8]) {
        (self.asset.0, &self.asset.1)
    }

    pub(crate) fn apply_binding(
        self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(EntityId, Vec<u8>)> {
        put_binding(store, txn, id, &self.source, self.hash)?;
        Ok(self.asset)
    }

    fn apply_binding_for_put(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<(EntityId, Vec<u8>)> {
        put_binding(store, txn, id, &self.source, self.hash)?;
        Ok((self.asset.0, self.asset.1.clone()))
    }
}

/// Composes the same native birth bytes without writing their binding. Setup
/// commits this exact plan only after its Gate allows the candidate.
pub(crate) fn prepare_agent_birth_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    created: &AgentDefinition,
) -> Result<Option<PreparedAgentBirth>> {
    let Some(snapshot) = agent_birth_snapshot_in_txn(store, txn, id, created)? else {
        return Ok(None);
    };
    let source = snapshot.source;
    let hash = snapshot.hash;
    let asset = snapshot.encode(id, created)?;
    Ok(Some(PreparedAgentBirth {
        source,
        hash,
        asset,
    }))
}

/// The genuine create arm consumes this one native setup's birth decision.
/// The outer value distinguishes a prepared native skip from no setup plan.
pub(crate) struct PreparedAgentDefinitionBirth {
    id: EntityId,
    birth: Option<PreparedAgentBirth>,
}

impl std::fmt::Debug for PreparedAgentDefinitionBirth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedAgentDefinitionBirth")
            .field("id", &self.id)
            .field("has_birth", &self.birth.is_some())
            .finish()
    }
}

impl PreparedAgentDefinitionBirth {
    pub(crate) fn id(&self) -> EntityId {
        self.id
    }

    pub(super) fn entity_put(&self) -> Option<(EntityId, &[u8])> {
        self.birth.as_ref().map(PreparedAgentBirth::entity_put)
    }

    pub(crate) fn bind_in_txn(
        &self,
        store: &Store,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<Option<(EntityId, Vec<u8>)>> {
        self.birth
            .as_ref()
            .map(|birth| birth.apply_binding_for_put(store, txn, &self.id))
            .transpose()
    }
}

pub(crate) fn prepare_agent_definition_birth_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    created: &AgentDefinition,
) -> Result<PreparedAgentDefinitionBirth> {
    Ok(PreparedAgentDefinitionBirth {
        id: *id,
        birth: prepare_agent_birth_in_txn(store, txn, id, created)?,
    })
}

fn agent_birth_snapshot_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    created: &AgentDefinition,
) -> Result<Option<AgentBirthSnapshot>> {
    if created.source == crate::claim::ClaimSource::Imported {
        return Ok(None);
    }
    if let Some(binding) = PORTABLE_BIRTH.get(store, txn, id)? {
        if binding.source != created.forked_from.unwrap_or(*id) {
            return Err(Error::InvalidConfig(
                "agent fork origin cannot change after deletion".into(),
            ));
        }
        return Ok(None);
    }
    let (source_id, definition) = if let Some(parent) = created.forked_from {
        if store.off_record_sessions.contains_entity(&parent)?
            || !crate::vault::live_entity_row_in_txn(store, txn, &parent)?.is_live()
            || !crate::secret_rotation::exhaust_taint_refs_in_txn(store, txn, &parent)?.is_empty()
        {
            return Ok(None);
        }
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &parent)?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("agent parent"))?;
        if header.entity_type != ENTITY_TYPE_AGENT_DEF {
            return Err(Error::EntityNotFound);
        }
        (
            parent,
            decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])?,
        )
    } else {
        (*id, created.clone())
    };
    let skills = read_portable_skills(store, txn, &definition)?;
    let claims = read_portable_knowledge(store, txn, &source_id)?;
    let Some(refs) = resolve_agent_skill_refs(&definition, &skills) else {
        return Ok(None);
    };
    let files = agent_pack_files(
        &source_id,
        &definition,
        &refs,
        &select_agent_knowledge(&source_id, &claims),
    )?;
    let tree = crate::serialize::export_source_tree(&files)?;
    let Some(hash) = tree.content_hash.as_deref() else {
        return Ok(None);
    };
    let hash = SkillContentHash::parse_hex(hash)?;
    Ok(Some(AgentBirthSnapshot {
        source: source_id,
        definition,
        tree,
        hash,
    }))
}

fn read_portable_skills(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    def: &AgentDefinition,
) -> Result<Vec<(EntityId, crate::skill::SkillRecord)>> {
    let mut skills = Vec::new();
    if def.skills.is_empty() {
        return Ok(skills);
    }
    // Every SKILL row is read, however many (rule 5): past its row the scan
    // asks whether everything is okay, counted on every way out.
    let mut count = source_count(store, txn, EngineScan::AgentBirthSkillRows, &[]);
    let read = skill_rows_into(store, txn, &mut count, &mut skills);
    count.defer(store);
    read?;
    Ok(skills)
}

fn skill_rows_into(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    count: &mut ScanCount,
    skills: &mut Vec<(EntityId, crate::skill::SkillRecord)>,
) -> Result<()> {
    for entry in
        crate::ports::EntityStoreRead::port_entity_ids_by_type(store, txn, ENTITY_TYPE_SKILL, None)?
    {
        count.row();
        let row_id = entry?;
        if excluded(store, txn, &row_id)? {
            continue;
        }
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &row_id)?
            .ok_or(Error::CorruptedIndex("agent skill index"))?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("agent skill header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::CorruptedIndex("agent skill type"));
        }
        if let Ok(record) = decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..]) {
            skills.push((row_id, record));
        }
    }
    Ok(())
}

fn read_portable_knowledge(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source_id: &EntityId,
) -> Result<Vec<ExportEntity>> {
    let mut claims = Vec::new();
    // Every ClaimOf edge is read, however many (rule 5), counted on every
    // way out.
    let mut count = source_count(
        store,
        txn,
        EngineScan::AgentBirthClaimOfRows,
        source_id.as_bytes(),
    );
    let read = knowledge_rows_into(store, txn, source_id, &mut count, &mut claims);
    count.defer(store);
    read?;
    Ok(claims)
}

fn knowledge_rows_into(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    source_id: &EntityId,
    count: &mut ScanCount,
    claims: &mut Vec<ExportEntity>,
) -> Result<()> {
    for entry in store.port_edges(
        txn,
        source_id,
        EdgeDirection::In,
        Some(crate::edge::EdgeKind::ClaimOf),
        None,
    )? {
        count.row();
        let row_id = entry?.target;
        if excluded(store, txn, &row_id)? {
            continue;
        }
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &row_id)? else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("agent knowledge header"))?;
        if header.entity_type != ENTITY_TYPE_CLAIM {
            continue;
        }
        claims.push(ExportEntity {
            short_ref: None,
            id: row_id.to_hex(),
            entity_type: header.entity_type,
            occurred_start: header.occurred_start,
            occurred_end: header.occurred_end,
            learned_at: header.learned_at,
            body: ExportBody::from_bytes(&raw[ENTITY_METADATA_HEADER_LEN..], header.entity_type),
        });
    }
    Ok(())
}

/// A source scan's count: its threshold row, or the count it once refused
/// past when the row does not read, so the count never fails the birth.
fn source_count(store: &Store, txn: &heed::RoTxn<'_>, scan: EngineScan, scope: &[u8]) -> ScanCount {
    ScanCount::start(store, txn, scan, scope)
        .unwrap_or_else(|_| ScanCount::start_at(scan, scope, SOURCE_SCAN_CHECK))
}

fn excluded(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(store.off_record_sessions.contains_entity(id)?
        || !crate::vault::live_entity_row_in_txn(store, txn, id)?.is_live()
        || !crate::secret_rotation::exhaust_taint_refs_in_txn(store, txn, id)?.is_empty())
}

/// Foreign lineage is archival provenance only. The caller has already admitted
/// a disabled/proposed AGENT_DEF through the ordinary local gate in this txn.
/// Do not call for preexisting rows: they keep their own birth binding.
pub(crate) fn import_agent_fork_hash_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    hash: Option<&str>,
) -> Result<()> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
        .ok_or(Error::EntityNotFound)?;
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("imported agent header"))?;
    if header.entity_type != ENTITY_TYPE_AGENT_DEF {
        return Err(Error::EntityNotFound);
    }
    let def = decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if def.enabled
        || def.ceiling != super::AgentCeiling::Proposed
        || def.approval_status != crate::claim::ClaimApprovalStatus::Proposed
        || def.source != crate::claim::ClaimSource::Imported
    {
        return Err(Error::InvalidConfig(
            "archive agent binding requires inert imported definition".into(),
        ));
    }
    match hash {
        Some(hash) => {
            put_binding(
                store,
                txn,
                id,
                &def.forked_from.unwrap_or(*id),
                SkillContentHash::parse_hex(hash)?,
            )?;
        }
        None => {
            PORTABLE_BIRTH.delete(store, txn, id)?;
        }
    }
    Ok(())
}
