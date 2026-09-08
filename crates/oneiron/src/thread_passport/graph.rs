//! Thread components are derived from observed Message-ID relationships.
//! Aliases are checked receipts of convergence, never independent routing authority.
use super::*;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::edge::EdgeKind;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::store::Store;
use crate::vault::{edge_kind_prefix, entity_id_from_type_index_key, parse_edge_record};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PassportRow {
    pub(super) claim_id: EntityId,
    pub(super) passport: ThreadPassport,
    pub(super) references: Vec<CanonicalMessageId>,
    pub(super) in_reply_to: Option<CanonicalMessageId>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct PassportPinKey {
    observed_at: u64,
    message_id: String,
    claim_id: EntityId,
}

impl PassportRow {
    pub(super) fn pin_key(&self) -> PassportPinKey {
        PassportPinKey {
            observed_at: self.passport.observed_at,
            message_id: self.passport.message_id.0.clone(),
            claim_id: self.claim_id,
        }
    }
}

/// Reuse the existing type and inbound ClaimOf indexes. No complete CLAIM
/// table scan, and no unsynchronized local predicate cache. apply_put maintains
/// ClaimOf for this family, including raw batch writes and sync materialization.
fn thread_claims(store: &Store, rtxn: &heed::RoTxn<'_>) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut rows = BTreeMap::new();
    for entry in store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_CHANNEL_IDENTITY])?
    {
        let (key, _) = entry?;
        let owner = entity_id_from_type_index_key(&key)?;
        let prefix = edge_kind_prefix(&owner, EdgeKind::ClaimOf);
        for entry in store.edges_in.prefix_iter(rtxn, &prefix)? {
            let (key, value) = entry?;
            let id = parse_edge_record(&key, &value)?.target;
            let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
                continue;
            };
            let header =
                EntityMetadataHeader::parse(&raw).ok_or_else(|| corrupt("thread claim header"))?;
            if header.entity_type != ENTITY_TYPE_CLAIM {
                continue;
            }
            let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
            if !is_thread_claim_predicate(&body.predicate)
                || body.subject != ClaimSubject::Entity(owner)
            {
                continue;
            }
            validate_thread_claim_owner_in_txn(store, rtxn, &body, false)?;
            if body.lifecycle == ClaimLifecycleStatus::Active {
                rows.insert(id, body);
            }
        }
    }
    Ok(rows.into_iter().collect())
}

/// Union by size with path compression. Component names are not roots: the
/// canonical thread is the minimum *stored, evidenced* root in the component.
/// Unseen reference tokens participate in connectivity but do not mint threads.
#[derive(Default)]
struct MessageComponents {
    ids: BTreeMap<CanonicalMessageId, usize>,
    parents: Vec<usize>,
    sizes: Vec<usize>,
}

impl MessageComponents {
    fn id(&mut self, message: &CanonicalMessageId) -> usize {
        if let Some(id) = self.ids.get(message) {
            return *id;
        }
        let id = self.parents.len();
        self.parents.push(id);
        self.sizes.push(1);
        self.ids.insert(message.clone(), id);
        id
    }

    fn root(&mut self, mut id: usize) -> usize {
        while self.parents[id] != id {
            self.parents[id] = self.parents[self.parents[id]];
            id = self.parents[id];
        }
        id
    }

    fn join(&mut self, left: usize, right: usize) {
        let mut left = self.root(left);
        let mut right = self.root(right);
        if left == right {
            return;
        }
        if self.sizes[left] < self.sizes[right] {
            std::mem::swap(&mut left, &mut right);
        }
        self.parents[right] = left;
        self.sizes[left] += self.sizes[right];
    }
}

pub(super) struct ThreadState {
    pub(super) rows: Vec<PassportRow>,
    pub(super) edges: BTreeMap<String, String>,
    /// Includes unknown references, so parent arrival is a reverse lookup.
    pub(super) message_threads: BTreeMap<CanonicalMessageId, String>,
}

impl ThreadState {
    pub(super) fn load(vault: &Vault, rtxn: &heed::RoTxn<'_>) -> Result<Self> {
        Self::from_claims(thread_claims(&vault.store, rtxn)?)
    }

    fn from_claims(claims: Vec<(EntityId, ClaimBody)>) -> Result<Self> {
        let mut rows = Vec::new();
        let mut aliases = Vec::new();
        for (claim_id, body) in claims {
            let ClaimSubject::Entity(subject) = body.subject else {
                unreachable!("validated owner")
            };
            if body.predicate == PREDICATE_THREAD_PASSPORT {
                let (references, in_reply_to) = decode_relationships(&body.value)?;
                rows.push(PassportRow {
                    claim_id,
                    passport: decode_passport_value(subject, &body.value)?,
                    references,
                    in_reply_to,
                });
            } else {
                aliases.push((subject, decode_alias_value(subject, &body.value)?));
            }
        }
        let mut state = Self::from_rows(rows);
        // An alias has authority only when independent passport evidence joins
        // its endpoints AND its subject owns a passport on that component.
        // Missing evidence after partial sync leaves the alias pending. A
        // forged alias alone cannot join components or poison unrelated reads.
        let owners: BTreeSet<_> = state
            .rows
            .iter()
            .filter_map(|row| {
                state
                    .message_threads
                    .get(&row.passport.message_id)
                    .map(|thread| (row.passport.identity_ref, thread.clone()))
            })
            .collect();
        for (subject, (from, to)) in aliases {
            let canonical = resolve_thread_alias(&state.edges, &from)?;
            if canonical != resolve_thread_alias(&state.edges, &to)?
                || !owners.contains(&(subject, canonical.clone()))
            {
                continue;
            }
            state.edges.insert(from, canonical);
        }
        Ok(state)
    }

    pub(super) fn from_rows(mut rows: Vec<PassportRow>) -> Self {
        // Remove unsupported rows before their relationships can route other
        // passports. Repeat to a fixed point because one pending ancestor may
        // have been the only proof for another row. Each retry removes rows.
        loop {
            let mut components = MessageComponents::default();
            for row in &rows {
                let message = components.id(&row.passport.message_id);
                for reference in row.references.iter().chain(row.in_reply_to.iter()) {
                    let other = components.id(reference);
                    components.join(message, other);
                }
            }
            let message_components: BTreeMap<_, _> = components
                .ids
                .clone()
                .into_iter()
                .map(|(message, id)| (message, components.root(id)))
                .collect();
            let minted_components: BTreeMap<_, _> = message_components
                .iter()
                .map(|(message, component)| (message.minted_thread_ref(), *component))
                .collect();
            // A stored root must be the hash of a message in its evidenced
            // component. A peer cannot redirect a passport merely by naming an
            // unrelated root. Partial sync may leave a passport pending until its
            // ancestor chain arrives; every read reconsiders it without a rewrite.
            let previous_len = rows.len();
            rows.retain(|row| {
                minted_components.get(&row.passport.thread_ref)
                    == message_components.get(&row.passport.message_id)
            });
            if rows.len() != previous_len {
                continue;
            }
            let mut roots: BTreeMap<usize, BTreeSet<String>> = BTreeMap::new();
            for row in &rows {
                roots
                    .entry(message_components[&row.passport.message_id])
                    .or_default()
                    .insert(row.passport.thread_ref.clone());
            }
            let mut edges = BTreeMap::new();
            for refs in roots.values() {
                let canonical = refs.first().expect("nonempty root set");
                for thread in refs.iter().skip(1) {
                    edges.insert(thread.clone(), canonical.clone());
                }
            }
            let message_threads = message_components
                .into_iter()
                .filter_map(|(message, component)| {
                    roots
                        .get(&component)
                        .and_then(|refs| refs.first())
                        .map(|canonical| (message, canonical.clone()))
                })
                .collect();
            return Self {
                rows,
                edges,
                message_threads,
            };
        }
    }

    /// One logical passport everywhere. Earliest observation, then claim id,
    /// decides both singular lookup and the thread mask. Losing rows remain
    /// durable evidence and still contribute their reference relationships.
    pub(super) fn logical_rows(&self) -> Vec<PassportRow> {
        let mut logical: BTreeMap<(EntityId, CanonicalMessageId), PassportRow> = BTreeMap::new();
        for row in &self.rows {
            let key = (row.passport.identity_ref, row.passport.message_id.clone());
            if logical
                .get(&key)
                .is_none_or(|prior| row.pin_key() < prior.pin_key())
            {
                logical.insert(key, row.clone());
            }
        }
        logical.into_values().collect()
    }
}

#[cfg(test)]
pub(super) fn active_passport_rows(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<Vec<PassportRow>> {
    Ok(ThreadState::load(vault, rtxn)?.logical_rows())
}

/// Callers validate their own key namespace. The public passport door uses
/// email-thread validation; comm also admits opaque non-email keys with spaces.
pub(crate) fn canonical_thread_ref_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    thread: &str,
) -> Result<String> {
    resolve_thread_alias(&ThreadState::load(vault, rtxn)?.edges, thread)
}

pub(super) fn resolve_thread_alias(
    edges: &BTreeMap<String, String>,
    start: &str,
) -> Result<String> {
    let mut seen = BTreeSet::new();
    let mut current = start;
    while let Some(next) = edges.get(current) {
        if !seen.insert(current) {
            return Err(corrupt("thread alias chain contains a cycle"));
        }
        current = next;
    }
    Ok(current.to_owned())
}

pub(super) fn passports_on_thread(
    rows: Vec<PassportRow>,
    edges: &BTreeMap<String, String>,
    canonical: &str,
) -> Result<BTreeMap<PassportPinKey, ThreadPassport>> {
    let mut ordered = BTreeMap::new();
    for row in rows {
        if resolve_thread_alias(edges, &row.passport.thread_ref)? == canonical {
            ordered.insert(row.pin_key(), row.passport);
        }
    }
    Ok(ordered)
}

pub(crate) fn thread_aliases_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<String, String>> {
    Ok(ThreadState::load(vault, rtxn)?.edges)
}

/// Local generic writes cannot assert routing without reference evidence.
/// Replicas may receive that evidence later; their readers use the same proof
/// before activating a row, so ordering is not mistaken for corruption.
pub(super) fn validate_thread_claim_provenance_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let ClaimSubject::Entity(subject) = body.subject else {
        unreachable!("validated subject")
    };
    let mut claims = thread_claims(store, rtxn)?;
    claims.retain(|(resident, _)| resident != id);
    if body.predicate == PREDICATE_THREAD_PASSPORT {
        claims.push((*id, body.clone()));
        if ThreadState::from_claims(claims)?
            .rows
            .iter()
            .any(|row| row.claim_id == *id)
        {
            return Ok(());
        }
    } else {
        let (from, to) = decode_alias_value(subject, &body.value)?;
        let state = ThreadState::from_claims(claims)?;
        let canonical = resolve_thread_alias(&state.edges, &from)?;
        if canonical == resolve_thread_alias(&state.edges, &to)?
            && state.rows.iter().any(|row| {
                row.passport.identity_ref == subject
                    && state.message_threads.get(&row.passport.message_id) == Some(&canonical)
            })
        {
            return Ok(());
        }
    }
    Err(Error::InvalidClaimBody(
        "thread routing lacks passport reference evidence",
    ))
}
