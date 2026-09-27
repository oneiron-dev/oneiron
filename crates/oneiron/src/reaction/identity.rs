//! Canonical, replicated connector-generation receipts for reaction adds.
//! A receipt binds provider generation to an original immutable add. It is
//! metadata, not another visible REACTION and not another author signal.
use super::{ReactionBody, ReactionChange, ReactionExternalId, ReactionState};
use crate::conversation::{AudienceCache, room_for_record_in};
use crate::conversation_dag::actor_in_txn;
use crate::error::{Error, RecordError, Result};
use crate::registry::{ENTITY_TYPE_REACTION, ENTITY_TYPE_REACTION_BINDING};
use crate::store::{ManifestDbs, Store};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, TimeRange, Vault, WriteActor};
use serde::{Deserialize, Serialize};

const INDEX: &[u8] = b"reaction:generation:v1:";
const BY_REACTION: &[u8] = b"reaction:generation_for:v1:";
const DOMAIN_BINDING: &[u8] = b"oneiron:reaction-binding:v1:";

/// One connector-scoped provider generation. A remove then a later re-add
/// MUST carry distinct generation IDs; delivery IDs are not generations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionGeneration {
    pub connector: String,
    pub id: String,
}
impl From<ReactionExternalId> for ReactionGeneration {
    fn from(ext: ReactionExternalId) -> Self {
        Self {
            connector: ext.connector,
            id: ext.id,
        }
    }
}
impl From<ReactionGeneration> for ReactionExternalId {
    fn from(generation: ReactionGeneration) -> Self {
        Self {
            connector: generation.connector,
            id: generation.id,
        }
    }
}
impl ReactionGeneration {
    fn validate(&self) -> Result<()> {
        ReactionBody {
            v: 1,
            msg: EntityId::from_bytes([1; 16])?,
            by: EntityId::from_bytes([2; 16])?,
            glyph: "x".into(),
            at: 0,
            ext: Some(self.clone().into()),
        }
        .validate()
    }
    fn digest(&self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(&(self.connector.len() as u64).to_be_bytes());
        hash.update(self.connector.as_bytes());
        hash.update(&(self.id.len() as u64).to_be_bytes());
        hash.update(self.id.as_bytes());
        *hash.finalize().as_bytes()
    }
}
fn derived_id(
    domain: &[u8],
    generation: &ReactionGeneration,
    source: Option<EntityId>,
) -> Result<EntityId> {
    for nonce in 0..=u8::MAX {
        let mut hash = blake3::Hasher::new();
        hash.update(domain);
        hash.update(&generation.digest());
        if let Some(source) = source {
            hash.update(source.as_bytes());
        }
        hash.update(&[nonce]);
        if let Ok(id) = EntityId::from_bytes(
            hash.finalize().as_bytes()[..16]
                .try_into()
                .map_err(|_| Error::InvalidKey)?,
        ) {
            return Ok(id);
        }
    }
    Err(Error::InvalidKey)
}
pub(crate) fn binding_id(body: &ReactionBindingBody) -> Result<EntityId> {
    derived_id(DOMAIN_BINDING, &body.generation, Some(body.reaction))
}
fn prefix(generation: &ReactionGeneration) -> Vec<u8> {
    [INDEX, generation.digest().as_slice()].concat()
}
fn suppression_key_digest(digest: [u8; 32]) -> String {
    format!(
        "reaction:erased_generation:v1:{}",
        blake3::Hash::from_bytes(digest).to_hex()
    )
}
fn suppression_key(generation: &ReactionGeneration) -> String {
    suppression_key_digest(generation.digest())
}
pub(super) fn suppress_generation(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    generation: &ReactionGeneration,
) -> Result<()> {
    store
        .sync_state()
        .put(txn, &suppression_key(generation), &[1])?;
    Ok(())
}
pub(super) fn suppressed(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    generation: &ReactionGeneration,
) -> Result<bool> {
    Ok(store
        .sync_state()
        .get(txn, &suppression_key(generation))?
        .is_some())
}

/// A provider removal is a generation tombstone. When one bound physical add
/// has a soft shell, any later alias of the same generation is not live,
/// even if that alias's own body and edges replay after the removal.
pub(crate) fn generation_revoked_for(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    body: &ReactionBody,
) -> Result<bool> {
    let mut digests = std::collections::BTreeSet::<[u8; 32]>::new();
    if let Some(ext) = body.ext.clone() {
        digests.insert(ReactionGeneration::from(ext).digest());
    }
    let reverse_prefix = [BY_REACTION, id.as_bytes()].concat();
    for (n, entry) in store
        .vault_meta()
        .prefix_iter(txn, &reverse_prefix)?
        .enumerate()
    {
        if n >= 100_000 {
            return Err(Error::IndexOverflow("reaction source generations"));
        }
        let (key, _) = entry?;
        if key.len() != reverse_prefix.len() + 32 {
            return Err(Error::CorruptedIndex("reaction source generation key"));
        }
        digests.insert(
            key[reverse_prefix.len()..]
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction source digest"))?,
        );
    }
    for digest in digests {
        if store
            .sync_state()
            .get(txn, &suppression_key_digest(digest))?
            .is_some()
        {
            return Ok(true);
        }
        let prefix = [INDEX, digest.as_slice()].concat();
        for (n, entry) in store.vault_meta().prefix_iter(txn, &prefix)?.enumerate() {
            if n >= 100_000 {
                return Err(Error::IndexOverflow("reaction generation aliases"));
            }
            let (key, _) = entry?;
            if key.len() != prefix.len() + 16 {
                return Err(Error::CorruptedIndex("reaction generation alias key"));
            }
            let source = EntityId::from_bytes(
                key[prefix.len()..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("reaction generation source"))?,
            )?;
            if store
                .sync_state()
                .get(txn, &crate::deletion::local_hard_delete_key(&source))?
                .is_some()
            {
                return Ok(true);
            }
            let Some(raw) = store.entities().get(txn, source.as_bytes())? else {
                continue;
            };
            let header = crate::batch::EntityMetadataHeader::parse(&raw)
                .ok_or(Error::CorruptedIndex("reaction generation source header"))?;
            if header.entity_type == ENTITY_TYPE_REACTION
                && raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn index_key(body: &ReactionBindingBody) -> Vec<u8> {
    [
        prefix(&body.generation).as_slice(),
        body.reaction.as_bytes(),
    ]
    .concat()
}

fn reverse_key(body: &ReactionBindingBody) -> Vec<u8> {
    [
        BY_REACTION,
        body.reaction.as_bytes(),
        body.generation.digest().as_slice(),
    ]
    .concat()
}

/// Durable receipt. A provider generation may have several alias add IDs on
/// disconnected peers; all matching receipts belong to ONE logical element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReactionBindingBody {
    pub v: u8,
    pub generation: ReactionGeneration,
    pub reaction: EntityId,
    pub msg: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub at: u64,
}
impl ReactionBindingBody {
    fn validate(&self) -> Result<()> {
        if self.v != 1 {
            return Err(invalid("unsupported generation binding"));
        }
        ReactionBody {
            v: 1,
            msg: self.msg,
            by: self.by,
            glyph: self.glyph.clone(),
            at: self.at,
            ext: Some(self.generation.clone().into()),
        }
        .validate()
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        rmp_serde::to_vec_named(self).map_err(|_| invalid("binding encode failed"))
    }
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let body: Self =
            rmp_serde::from_slice(data).map_err(|_| invalid("binding decode failed"))?;
        body.validate()?;
        if body.to_bytes()? != data {
            return Err(invalid("noncanonical binding body"));
        }
        Ok(body)
    }
}
fn invalid(why: &'static str) -> Error {
    RecordError::InvalidReactionBody(why).into()
}

/// Explicit acknowledgment from the connector lane; original is the outbound
/// attempt's reaction ID. No tuple-matching guess is made from delivery time.
#[derive(Debug, Clone)]
pub struct ReactionAcknowledgment {
    pub original: EntityId,
    pub generation: ReactionGeneration,
    pub actor: WriteActor,
}

/// The generic put door refuses local untyped receipt writes and hostile
/// same-ID replacements; replay can arrive before the referenced add.
pub(crate) fn guard_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    kind: u8,
    occurred: TimeRange,
    data: &[u8],
    replicated: bool,
) -> Result<()> {
    if kind != ENTITY_TYPE_REACTION_BINDING {
        return Ok(());
    }
    let body = ReactionBindingBody::from_bytes(data)?;
    if occurred.start != body.at || occurred.end != body.at || binding_id(&body)? != *id {
        return Err(invalid("binding identity or occurrence mismatch"));
    }
    if !replicated && !super::admission::has_permit(store, txn, id)? {
        return Err(invalid("binding requires connector acknowledgment"));
    }
    if suppressed(store, txn, &body.generation)?
        || store
            .sync_state
            .get(txn, &crate::deletion::local_hard_delete_key(&body.reaction))?
            .is_some()
    {
        // The remote opaque receipt is consumed only as a suppression fact;
        // its content is scrubbed in the same materialization transaction.
        return if replicated {
            Ok(())
        } else {
            Err(invalid("hard-erased generation cannot regain a binding"))
        };
    }
    match live_entity_row_in_txn(store, txn, &body.reaction)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_REACTION,
            body: source,
        } => {
            let original = ReactionBody::from_bytes(&source)?;
            if original.msg != body.msg
                || original.by != body.by
                || original.glyph != body.glyph
                || original.at != body.at
                || original.ext.as_ref().is_some_and(|ext| {
                    ext.connector != body.generation.connector || ext.id != body.generation.id
                })
            {
                return Err(invalid("generation binding differs from add"));
            }
        }
        LiveEntityRow::DeletedShell | LiveEntityRow::Absent if replicated => {}
        _ => return Err(invalid("generation binding lacks original add")),
    }
    Ok(())
}

/// Rebuildable index of canonical receipts. Neither the key nor its value is
/// the authority; every lookup verifies the backing immutable entity row.
pub(crate) fn index_binding(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kind: u8,
    data: &[u8],
) -> Result<()> {
    if kind != ENTITY_TYPE_REACTION_BINDING {
        return Ok(());
    }
    let body = ReactionBindingBody::from_bytes(data)?;
    if binding_id(&body)? != id {
        return Err(invalid("binding ID mismatch"));
    }
    if suppressed(store, txn, &body.generation)?
        || store
            .sync_state()
            .get(txn, &crate::deletion::local_hard_delete_key(&body.reaction))?
            .is_some()
    {
        store
            .sync_state()
            .put(txn, &suppression_key(&body.generation), &[1])?;
        let raw = store
            .entities()
            .get(txn, id.as_bytes())?
            .ok_or(Error::CorruptedIndex("suppressed binding header"))?;
        let header = raw[..crate::batch::ENTITY_METADATA_HEADER_LEN].to_vec();
        store.entities().put(txn, id.as_bytes(), &header)?;
        return Ok(());
    }
    for entry in store
        .vault_meta()
        .prefix_iter(txn, &prefix(&body.generation))?
    {
        let (_, prior_id) = entry?;
        if prior_id.len() != 16 {
            return Err(Error::CorruptedIndex("generation alias ID"));
        }
        let prior_id = EntityId::from_bytes(
            prior_id
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("generation alias ID"))?,
        )?;
        let Some(raw) = store.entities().get(txn, prior_id.as_bytes())? else {
            continue;
        };
        let h = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("generation alias header"))?;
        if h.entity_type != ENTITY_TYPE_REACTION_BINDING
            || raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let prior =
            ReactionBindingBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        if prior.msg != body.msg || prior.by != body.by || prior.glyph != body.glyph {
            return Err(invalid("provider generation conflicts with another tuple"));
        }
    }
    store
        .vault_meta()
        .put(txn, &index_key(&body), id.as_bytes())?;
    store
        .vault_meta()
        .put(txn, &reverse_key(&body), id.as_bytes())?;
    Ok(())
}

pub(crate) fn bindings_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    generation: &ReactionGeneration,
) -> Result<Vec<(EntityId, ReactionBindingBody)>> {
    let prefix = prefix(generation);
    let mut rows = Vec::new();
    for (n, item) in store.vault_meta.prefix_iter(txn, &prefix)?.enumerate() {
        if n >= 100_000 {
            return Err(Error::IndexOverflow("reaction_generation"));
        }
        let (key, value) = item?;
        if key.len() != prefix.len() + 16 || value.len() != 16 {
            return Err(Error::CorruptedIndex("reaction binding index"));
        }
        let id = EntityId::from_bytes(
            value
                .as_ref()
                .try_into()
                .map_err(|_| Error::CorruptedIndex("reaction binding ID"))?,
        )?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("reaction binding header"))?;
        if header.entity_type != ENTITY_TYPE_REACTION_BINDING
            || raw.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body =
            ReactionBindingBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        if body.generation != *generation
            || index_key(&body).as_slice() != key.as_ref()
            || binding_id(&body)? != id
        {
            return Err(Error::CorruptedIndex("reaction binding index mismatch"));
        }
        rows.push((id, body));
    }
    Ok(rows)
}

/// A pending replicated receipt is not an idempotency verdict. The bound
/// original must exist as a typed add with complete topology, or as its
/// deliberate soft-revocation shell; a wrong-kind/missing source is unresolved.
pub(super) fn binding_ready(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &ReactionBindingBody,
) -> Result<bool> {
    if store
        .sync_state
        .get(txn, &crate::deletion::local_hard_delete_key(&row.reaction))?
        .is_some()
    {
        return Ok(false);
    }
    let source = crate::vault::live_entity_row_in_txn(store, txn, &row.reaction)?;
    match source {
        LiveEntityRow::DeletedShell => Ok(true),
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_REACTION,
            body,
        } if body.is_empty() => Ok(true),
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_REACTION,
            body,
        } => {
            let original = ReactionBody::from_bytes(&body)?;
            if original.msg != row.msg
                || original.by != row.by
                || original.glyph != row.glyph
                || original.at != row.at
            {
                return Ok(false);
            }
            Ok(matches!(
                super::state::resolve(store, txn, row.reaction, &original)?,
                super::state::ReactionResolution::Active { .. }
                    | super::state::ReactionResolution::Revoked { .. }
                    | super::state::ReactionResolution::SuppressedAlias
            ))
        }
        _ => Ok(false),
    }
}

/// Record a provider generation in the same write transaction as its add.
pub(super) fn put_binding_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    body: ReactionBindingBody,
) -> Result<EntityId> {
    let id = binding_id(&body)?;
    if let Some((_, old)) = bindings_in(&vault.store, txn, &body.generation)?
        .into_iter()
        .find(|(_, old)| old.reaction == body.reaction)
    {
        if old != body {
            return Err(invalid("generation binding changed"));
        }
        return Ok(id);
    }
    super::admission::permit(&vault.store, txn, &id)?;
    vault
        .batch_in()
        .put(
            &id,
            ENTITY_TYPE_REACTION_BINDING,
            TimeRange {
                start: body.at,
                end: body.at,
            },
            vault.store.clock.now_recorded_at(),
            &body.to_bytes()?,
        )
        .apply(txn)?;
    super::admission::finish(&vault.store, txn, &id)?;
    Ok(id)
}

impl Vault {
    /// Persist the connector's causal acknowledgment without a second
    /// REACTION or a second author put signal.
    pub fn acknowledge_reaction(&self, input: ReactionAcknowledgment) -> Result<ReactionChange> {
        self.acknowledge_reaction_asserted(input, None)
    }

    pub(super) fn acknowledge_reaction_asserted(
        &self,
        input: ReactionAcknowledgment,
        claimed: Option<(EntityId, EntityId, &str)>,
    ) -> Result<ReactionChange> {
        input.generation.validate()?;
        self.with_write_txn(|txn| {
            actor_in_txn(&self.store, txn, input.actor)?;
            let bindings = bindings_in(&self.store, txn, &input.generation)?;
            if let Some((id, prior)) = bindings
                .iter()
                .find(|(_, row)| row.reaction == input.original)
            {
                if !binding_ready(&self.store, txn, prior)? {
                    return Err(RecordError::ReactionNeedsReconciliation(
                        "binding original add is not yet valid",
                    )
                    .into());
                }
                if input.actor.entity_ref() != prior.by
                    || claimed.is_some_and(|(msg, by, glyph)| {
                        prior.msg != msg || prior.by != by || prior.glyph != glyph
                    })
                {
                    return Err(invalid("ack assertion differs from original"));
                }
                return Ok(ReactionChange {
                    id: *id,
                    state: ReactionState::Replayed,
                });
            }
            let LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_REACTION,
                body,
            } = live_entity_row_in_txn(&self.store, txn, &input.original)?
            else {
                return Err(RecordError::ReactionNeedsReconciliation(
                    "original add is absent or revoked without an existing binding",
                )
                .into());
            };
            let original = ReactionBody::from_bytes(&body)?;
            if original.by != input.actor.entity_ref()
                || claimed.is_some_and(|(msg, by, glyph)| {
                    original.msg != msg || original.by != by || original.glyph != glyph
                })
            {
                return Err(invalid("ack assertion differs from original"));
            }
            let room = room_for_record_in(self, txn, original.msg)?
                .ok_or(invalid("unresolved acknowledgment: target room missing"))?;
            let room_body = crate::conversation::body_in(self, txn, room)?;
            if room_body.kind != crate::conversation::ConversationKind::Mirror
                || room_body
                    .external_id
                    .as_deref()
                    .and_then(|v| v.split_once(':'))
                    .is_none_or(|(connector, _)| connector != input.generation.connector)
                || !AudienceCache::default().readable(self, txn, original.msg, &[original.by])?
                || !crate::conversation::member_at_in(self, txn, room, original.by, original.at)?
            {
                return Err(invalid("ack is outside the original mirrored audience"));
            }
            if bindings.iter().any(|(_, prior)| {
                prior.msg != original.msg
                    || prior.by != original.by
                    || prior.glyph != original.glyph
            }) {
                return Err(invalid("provider generation conflicts with another tuple"));
            }
            let receipt = ReactionBindingBody {
                v: 1,
                generation: input.generation,
                reaction: input.original,
                msg: original.msg,
                by: original.by,
                glyph: original.glyph,
                at: original.at,
            };
            let id = put_binding_in_txn(self, txn, receipt)?;
            Ok(ReactionChange {
                id,
                state: ReactionState::Replayed,
            })
        })
    }
}

/// Hard erase of an original add destroys every content-bearing generation
/// receipt, including receipts learned before the original body arrives.
/// Only the original's permanent hard marker remains as opaque suppression.
pub(crate) fn purge_for_reaction(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    reaction: EntityId,
) -> Result<()> {
    let mut generations = std::collections::BTreeSet::new();
    for (n, entry) in store.vault_meta.prefix_iter(txn, INDEX)?.enumerate() {
        if n >= 100_000 {
            return Err(Error::IndexOverflow("reaction binding purge"));
        }
        let (key, value) = entry?;
        if key.len() != INDEX.len() + 32 + 16 || value.len() != 16 {
            return Err(Error::CorruptedIndex("reaction binding purge index"));
        }
        if &key[key.len() - 16..] == reaction.as_bytes() {
            generations.insert(key[INDEX.len()..INDEX.len() + 32].to_vec());
        }
    }
    let mut receipts = std::collections::BTreeSet::new();
    let mut aliases = std::collections::BTreeSet::new();
    for digest in generations {
        let digest_bytes: [u8; 32] = digest
            .as_slice()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("reaction generation digest"))?;
        store
            .sync_state
            .put(txn, &suppression_key_digest(digest_bytes), &[1])?;
        let prefix = [INDEX, digest.as_slice()].concat();
        for (n, entry) in store.vault_meta.prefix_iter(txn, &prefix)?.enumerate() {
            if n >= 100_000 {
                return Err(Error::IndexOverflow("reaction generation purge"));
            }
            let (key, value) = entry?;
            if key.len() != prefix.len() + 16 || value.len() != 16 {
                return Err(Error::CorruptedIndex("reaction generation purge index"));
            }
            aliases.insert(EntityId::from_bytes(
                key[prefix.len()..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("reaction alias ID"))?,
            )?);
            receipts.insert(EntityId::from_bytes(
                value
                    .as_ref()
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("reaction binding ID"))?,
            )?);
        }
    }
    // Remove ALL content-bearing receipts before purging aliases: the alias
    // purge recursively checks receipts, and this ordering makes that finite.
    for id in receipts {
        crate::batch::deindex_entity(store, txn, &id)?;
        store
            .sync_state
            .put(txn, &crate::deletion::local_hard_delete_key(&id), &[1])?;
    }
    for alias in aliases {
        if alias == reaction {
            continue;
        }
        store
            .sync_state
            .put(txn, &crate::deletion::local_hard_delete_key(&alias), &[1])?;
        crate::batch::deindex_entity(store, txn, &alias)?;
    }
    Ok(())
}

/// A hard-erased binding itself drops its disposable lookup row.
pub(crate) fn purge_binding(store: &Store, txn: &mut heed::RwTxn<'_>, raw: &[u8]) -> Result<()> {
    let body = ReactionBindingBody::from_bytes(raw)?;
    store.vault_meta.delete(txn, &index_key(&body))?;
    store.vault_meta.delete(txn, &reverse_key(&body))?;
    Ok(())
}

/// A late canonical receipt for an already-hard-erased original is consumed
/// only as an opaque generation suppression fact. Purge any earlier alias
/// that replayed before this receipt supplied the missing correlation.
pub(crate) fn purge_suppressed_aliases(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    kind: u8,
    data: &[u8],
) -> Result<()> {
    if kind != ENTITY_TYPE_REACTION_BINDING {
        return Ok(());
    }
    let body = ReactionBindingBody::from_bytes(data)?;
    if !suppressed(store, txn, &body.generation)? {
        return Ok(());
    }
    let mut aliases = Vec::new();
    for (n, entry) in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_REACTION])?
        .enumerate()
    {
        if n >= 100_000 {
            return Err(Error::IndexOverflow("reaction suppressed alias scan"));
        }
        let (key, _) = entry?;
        let id = crate::vault::entity_id_from_type_index_key(&key)?;
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            continue;
        };
        if raw.len() <= crate::batch::ENTITY_METADATA_HEADER_LEN {
            continue;
        }
        let source = ReactionBody::from_bytes(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        if source.ext.as_ref().is_some_and(|ext| {
            ext.connector == body.generation.connector && ext.id == body.generation.id
        }) {
            aliases.push(id);
        }
    }
    for id in aliases {
        store
            .sync_state
            .put(txn, &crate::deletion::local_hard_delete_key(&id), &[1])?;
        crate::batch::deindex_entity(store, txn, &id)?;
    }
    Ok(())
}
