//! Who a read admits: the relationship reads a principal's memberships and
//! grants decide, the policy grants a reader's key matches on a claim, the
//! claims a minted credential's holder reads, the private notes a reader
//! reaches through a diary link, the diary links graph reads show, and the
//! position at which each record is read, selected and connected.
use super::{Decision, field, held_by_both};
use crate::access_grant::{AccessContext, decode_access_grant_body};
use crate::authority::AuthorityFold;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimBody, RelationshipRead, ScopedRead, ScopedReadActorKey, decode_claim_body,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::federation::Scope;
use crate::federation::record_scope::{disclosure_scope_for_stored_row, scope_for_blob};
use crate::note::NoteKind;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_NOTE,
    ENTITY_TYPE_SUMMARY,
};
use crate::secret_lease::VaultInstant;
use crate::{EntityId, Result, Vault};
use std::collections::{BTreeMap, BTreeSet};

/// Whether a relationship read lets a principal, or a caller bound to none,
/// read a CLAIM, MESSAGE or SUMMARY (`ScopedRead::relationship_raw_allowed_in`):
/// the relationship, privacy and record position the row is read at
/// (`claim::relationship_read`), against the memberships and grants of the
/// principal's context (`AccessContext::load`).
pub(super) struct RelationshipReads;

impl Decision for RelationshipReads {
    type Subject = (EntityId, Option<EntityId>);
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let records = kept(
            vaults,
            &[ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SUMMARY],
        )?;
        // A principal no grant or membership names reads as one bound to none.
        let mut principals = BTreeSet::from([None]);
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for id in vault
                .store
                .port_entity_ids_by_type(&txn, ENTITY_TYPE_ACCESS_GRANT, None)?
            {
                if let Some(record) = vault.store.port_entity_record(&txn, &id?)?
                    && let Ok(grant) = decode_access_grant_body(&record.body)
                {
                    principals.insert(Some(grant.principal_ref));
                }
            }
            for (_, membership) in vault.claims_with_predicate_in_txn(
                &txn,
                crate::federation::PREDICATE_RELATIONSHIP_PERSON_REF,
            )? {
                principals.extend(
                    membership
                        .value
                        .as_str()
                        .and_then(|person| EntityId::from_hex(person).ok())
                        .map(Some),
                );
            }
        }
        Ok(records
            .iter()
            .flat_map(|record| {
                principals
                    .iter()
                    .map(move |principal| (*record, *principal))
            })
            .collect())
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        let mut contexts = BTreeMap::new();
        let mut row: Option<(EntityId, Option<RelationshipRead>)> = None;
        let mut answers = Vec::with_capacity(subjects.len());
        for (record, principal) in subjects {
            if row.as_ref().is_none_or(|(id, _)| id != record) {
                let read = vault
                    .store
                    .port_entity_raw(&txn, record)
                    .ok()
                    .flatten()
                    .and_then(|raw| {
                        crate::claim::relationship_read(&vault.store, &txn, record, &raw).ok()
                    });
                row = Some((*record, read));
            }
            answers.push(match row.as_ref().and_then(|(_, read)| read.as_ref()) {
                None => None,
                Some(RelationshipRead::Decided(allowed)) => Some(*allowed),
                Some(read) => contexts
                    .entry(*principal)
                    .or_insert_with(|| AccessContext::load(vault, &txn, *principal).ok())
                    .as_ref()
                    .map(|context| read.allowed_by(context)),
            });
        }
        Ok(answers)
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Whether a reader's key may read a claim, as far as who reads it goes: the
/// principal audience the claim names (`ScopedRead::principal_admits`), and
/// the policy grants the key matches with the selectors the claim meets
/// (`gate::scoped_read_claim_allowed`): its world and scope, the reader a
/// typed question binds it to, and the facets its `FacetOf` edges name
/// (`ScopedRead::claim_facet_refs_in`). A grant's floor on confidence,
/// salience or staleness sorts content rather than deciding who reads it, so
/// each claim is asked at its most permissive on those.
pub(super) struct ClaimGrants;

impl Decision for ClaimGrants {
    type Subject = (EntityId, Reader);
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let claims = kept(vaults, &[ENTITY_TYPE_CLAIM])?;
        let mut actors = BTreeSet::new();
        let mut classes = BTreeSet::from([None]);
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
            for grant in policy.scoped_grants() {
                actors.extend(grant.actor_ref.clone());
                classes.insert(grant.actor_class.clone());
            }
            for id in &claims {
                let Some(body) = stored_claim(vault, &txn, id) else {
                    continue;
                };
                actors.extend(
                    body.scope
                        .as_ref()
                        .and_then(|scope| field(scope, "typed_question_principal"))
                        .map(str::to_owned),
                );
                actors.extend(
                    crate::claim::claim_principal_id(&body)
                        .ok()
                        .flatten()
                        .map(|principal| principal.to_hex()),
                );
            }
        }
        actors.insert(stranger(&actors));
        let readers: Vec<Reader> = actors
            .iter()
            .flat_map(|actor| {
                classes
                    .iter()
                    .map(move |class| Reader::Asserted(actor.clone(), class.clone()))
            })
            .chain(owners(vaults)?.into_iter().map(Reader::Owner))
            .collect();
        Ok(claims
            .iter()
            .flat_map(|claim| readers.iter().map(move |reader| (*claim, reader.clone())))
            .collect())
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        let Ok(policy) = crate::gate::resolve_policy_manifest(&vault.store, &txn) else {
            return Ok(vec![None; subjects.len()]);
        };
        let mut claim: Option<(EntityId, Option<GrantInputs>)> = None;
        let mut answers = Vec::with_capacity(subjects.len());
        for (id, reader) in subjects {
            let Some(key) = reader.key() else {
                answers.push(None);
                continue;
            };
            let read = vault.scoped_read(key.clone());
            if claim.as_ref().is_none_or(|(held, _)| held != id) {
                claim = Some((*id, permissive_claim(vault, &txn, &read, id)));
            }
            answers.push(
                claim
                    .as_ref()
                    .and_then(|(_, claim)| claim.as_ref())
                    .and_then(|(body, facets)| {
                        let principal = crate::claim::claim_principal_id(body).ok()?;
                        Some(
                            read.principal_admits(principal)
                                && crate::gate::scoped_read_claim_allowed(
                                    &policy, &key, body, facets,
                                ),
                        )
                    }),
            );
        }
        Ok(answers)
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Whether a credential the authority log minted lets its holder read a
/// claim, as the key a verified proof of it reads under does
/// (`ScopedReadActorKey::from_verified_slip`), where no policy grant need
/// name the holder. A proof only meets or narrows its mint, so the mint's
/// own bounds stand for every proof of it: live at one instant both vaults
/// share (`AuthorityFold::slip_is_live_at`, `ScopedRead::proof_live_in`), a
/// read verb, no channel, and the claim among its records when it names any
/// (`ScopedRead::credential_allows_id`). The claim is one generic reads
/// serve (`claim::claim_generic_readable`), its principal audience admits
/// the holder, and the policy grants match with the mint's Scope standing
/// for the proof's (`gate::scoped_read_claim_allowed_with_scope`), each claim
/// asked at its most permissive on the floors that sort content.
pub(super) struct SlipClaimGrants;

impl Decision for SlipClaimGrants {
    type Subject = (EntityId, [u8; 32], VaultInstant);
    type Answer = bool;

    /// Every claim both vaults keep, with every credential either vault's
    /// authority log minted, at the later of the two vaults' instants.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let claims = kept(vaults, &[ENTITY_TYPE_CLAIM])?;
        let [live, restored] = vaults.map(minted);
        let ((mut slips, live_at), (restored_slips, restored_at)) = (live?, restored?);
        slips.extend(restored_slips);
        let at = live_at.max(restored_at);
        Ok(claims
            .iter()
            .flat_map(|claim| slips.iter().map(move |slip| (*claim, *slip, at)))
            .collect())
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        let Ok(policy) = crate::gate::resolve_policy_manifest(&vault.store, &txn) else {
            return Ok(vec![None; subjects.len()]);
        };
        let fold = vault.authority_fold_readonly_in_txn(&txn)?;
        let mut claim: Option<(EntityId, Option<GrantInputs>)> = None;
        let mut answers = Vec::with_capacity(subjects.len());
        for (id, slip, at) in subjects {
            let Some((scope, key)) = credential_reader(&fold, slip, *at, id) else {
                answers.push(Some(false));
                continue;
            };
            let read = vault.scoped_read(key);
            if claim.as_ref().is_none_or(|(held, _)| held != id) {
                claim = Some((*id, permissive_claim(vault, &txn, &read, id)));
            }
            answers.push(
                claim
                    .as_ref()
                    .and_then(|(_, claim)| claim.as_ref())
                    .and_then(|(body, facets)| {
                        let principal = crate::claim::claim_principal_id(body).ok()?;
                        Some(
                            crate::claim::claim_generic_readable(body)
                                && read.principal_admits(principal)
                                && crate::gate::scoped_read_claim_allowed_with_scope(
                                    &policy,
                                    read.actor_key(),
                                    body,
                                    facets,
                                    Some(scope),
                                ),
                        )
                    }),
            );
        }
        Ok(answers)
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Every credential `vault`'s authority log minted, and the instant `vault`
/// reads credentials at.
fn minted(vault: &Vault) -> Result<(BTreeSet<[u8; 32]>, VaultInstant)> {
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_fold_readonly_in_txn(&txn)?;
    Ok((
        fold.slips.mints.keys().copied().collect(),
        vault.instant_in_txn(&txn)?,
    ))
}

/// The Scope of the credential minted as `slip`, and the key a verified
/// proof of it reads under, where at `at` it may read claim `id`; `None`
/// where no proof of it reads that claim.
fn credential_reader<'f>(
    fold: &'f AuthorityFold,
    slip: &[u8; 32],
    at: VaultInstant,
    id: &EntityId,
) -> Option<(&'f Scope, ScopedReadActorKey)> {
    let credential = &fold.slips.mints.get(slip)?.action.claims;
    let reads = ["read", "core:read"]
        .into_iter()
        .any(|verb| credential.scope.verbs.contains(&verb.to_owned()));
    if !(reads
        && fold.slip_is_live_at(slip, at)
        && fold.vault_id == Some(credential.vault_id)
        && credential.channels.is_empty()
        && (credential.records.is_empty() || credential.records.contains(&id.to_hex())))
    {
        return None;
    }
    let holder = credential.holder_ref.clone();
    let key = match credential.actor_class.clone() {
        None => ScopedReadActorKey::new(holder),
        Some(class) => ScopedReadActorKey::with_actor_class(holder, class),
    }?;
    Some((&credential.scope, key))
}

/// A claim as the grant check reads it, and the facets its `FacetOf` edges
/// name.
type GrantInputs = (ClaimBody, Vec<EntityId>);

/// A claim as the grant check reads it, at its most permissive on the floors
/// that sort content, with the facets its `FacetOf` edges name.
fn permissive_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    id: &EntityId,
) -> Option<GrantInputs> {
    let mut body = stored_claim(vault, txn, id)?;
    body.confidence = 1.0;
    body.salience = Some(1.0);
    body.stale = false;
    let facets = read.claim_facet_refs_in(txn, id).ok()?;
    Some((body, facets))
}

/// The stored body of claim `id`, as the claim lanes decode it.
fn stored_claim(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Option<ClaimBody> {
    let raw = vault.store.port_entity_raw(txn, id).ok()??;
    decode_claim_body(raw.get(ENTITY_METADATA_HEADER_LEN..)?, true).ok()
}

/// Whether a reader's key may read a NOTE (`ScopedRead::note_readable_in`):
/// a kind every reader may read, its author's own, or a diary the reader
/// reaches through a `SameAs` link to its own diary that both authors
/// granted, at a position the reader's grants admit.
pub(super) struct NoteReads;

impl Decision for NoteReads {
    type Subject = (EntityId, Reader);
    type Answer = bool;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let notes = kept(vaults, &[ENTITY_TYPE_NOTE])?;
        // Only a diary's author reads it through a link, so the authors are
        // every reader a link can admit. One only one vault holds returns or
        // leaves with the restore.
        let mut authors = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for id in vault
                .store
                .port_entity_ids_by_type(&txn, ENTITY_TYPE_NOTE, None)?
            {
                if let Some(raw) = vault.store.port_entity_raw(&txn, &id?)?
                    && let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..)
                    && let Ok(note) = crate::note::decode_note_body_using(body, NoteKind::wire)
                {
                    authors.insert(note.author_ref);
                }
            }
        }
        let classes = [
            EdgeActorClass::Human,
            EdgeActorClass::Agent,
            EdgeActorClass::System,
        ]
        .map(|class| class.gate_actor_class().to_owned());
        let actors: BTreeSet<String> = undeleted(vaults, authors)?
            .iter()
            .map(EntityId::to_hex)
            .collect();
        // No author: what a note's kind lets every reader read.
        let mut readers = vec![Reader::Asserted(stranger(&actors), None)];
        for actor in &actors {
            readers.extend(
                classes
                    .iter()
                    .map(|class| Reader::Asserted(actor.clone(), Some(class.clone()))),
            );
        }
        readers.extend(owners(vaults)?.into_iter().map(Reader::Owner));
        Ok(notes
            .iter()
            .flat_map(|note| readers.iter().map(move |reader| (*note, reader.clone())))
            .collect())
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        let Ok(policy) = crate::gate::resolve_policy_manifest(&vault.store, &txn) else {
            return Ok(vec![None; subjects.len()]);
        };
        let mut note: Option<(EntityId, Option<Vec<u8>>)> = None;
        let mut answers = Vec::with_capacity(subjects.len());
        for (id, reader) in subjects {
            if note.as_ref().is_none_or(|(held, _)| held != id) {
                note = Some((*id, vault.store.port_entity_raw(&txn, id).ok().flatten()));
            }
            answers.push(
                note.as_ref()
                    .and_then(|(_, raw)| raw.as_deref()?.get(ENTITY_METADATA_HEADER_LEN..))
                    .and_then(|body| {
                        vault
                            .scoped_read(reader.key()?)
                            .note_readable_in(&txn, id, body, &policy)
                            .ok()
                    }),
            );
        }
        Ok(answers)
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Whether a graph read shows a `SameAs` link between two diary notes
/// (`note::diary_edge_access_in`, which the scoped graph door asks of each
/// link it returns): the link stored, and both authors' grants on that very
/// pair. A note readable through another shared link does not show this
/// one.
pub(super) struct DiaryLinks;

impl Decision for DiaryLinks {
    type Subject = (EntityId, EntityId);
    type Answer = bool;

    /// Every pair of notes both vaults keep that a `SameAs` link joins in
    /// either; a pair joined in neither shows in neither.
    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        let notes = kept(vaults, &[ENTITY_TYPE_NOTE])?;
        let mut pairs = BTreeSet::new();
        for vault in vaults {
            let txn = vault.store.env.read_txn()?;
            for note in &notes {
                for direction in [EdgeDirection::Out, EdgeDirection::In] {
                    for edge in vault.store.port_edges(
                        &txn,
                        note,
                        direction,
                        Some(EdgeKind::SameAs),
                        None,
                    )? {
                        let other = edge?.target;
                        if notes.contains(&other) {
                            pairs.insert((*note.min(&other), *note.max(&other)));
                        }
                    }
                }
            }
        }
        Ok(pairs)
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|(left, right)| {
                crate::note::diary_edge_access_in(vault, &txn, *left, EdgeKind::SameAs, *right).ok()
            })
            .collect())
    }

    fn loosens(live: &bool, restored: &bool) -> bool {
        !live && *restored
    }

    fn refusal() -> Option<bool> {
        Some(false)
    }
}

/// Where a record is selected, read and connected: the position the scoped
/// read and export doors select it at, once it is causally admitted
/// (`record_scope::disclosure_scope_for_stored_row`,
/// `authority::row_causal_admitted`); the position read-plane grants place it
/// at (`record_scope::scope_for_blob`, which for a NOTE or ASSET follows its
/// `FacetOf` edge); and what a world- or facet-scoped connector covers it by,
/// the facets its `FacetOf` edges name and a claim's own world, read as
/// `Vault::edges_out` and `Vault::get_claim` read them.
pub(super) struct RecordPositions;

/// Where one record is selected, read and connected.
pub(super) struct Position {
    /// `None` where no scoped read or export selects it.
    selected: Option<Scope>,
    /// `None` where no read-plane grant admits it.
    read: Option<Scope>,
    facets: BTreeSet<EntityId>,
    world: Option<EntityId>,
}

impl Decision for RecordPositions {
    type Subject = EntityId;
    type Answer = Position;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<Self::Subject>> {
        kept(vaults, &(0..=u8::MAX).collect::<Vec<_>>())
    }

    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<Self::Subject>,
    ) -> Result<Vec<Option<Self::Answer>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|id| position(vault, &txn, id))
            .collect())
    }

    fn loosens(live: &Position, restored: &Position) -> bool {
        widens(live.selected.as_ref(), restored.selected.as_ref())
            || widens(live.read.as_ref(), restored.read.as_ref())
            || !restored.facets.is_subset(&live.facets)
            || (restored.world.is_some() && restored.world != live.world)
    }
}

fn position(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Option<Position> {
    let raw = vault.store.port_entity_raw(txn, id).ok()??;
    let kind = EntityMetadataHeader::parse(&raw)?.entity_type;
    let disclosed = disclosure_scope_for_stored_row(
        &vault.store,
        txn,
        *id,
        kind,
        raw.get(ENTITY_METADATA_HEADER_LEN..)?,
    )
    .ok()?;
    let selected = match disclosed {
        Some(scope) if crate::authority::row_causal_admitted(vault, txn, id, &raw).ok()? => {
            Some(scope)
        }
        _ => None,
    };
    let facets = crate::ports::EdgeStore::port_edge_neighbors(
        vault,
        txn,
        id,
        EdgeDirection::Out,
        None,
        crate::vault::MAX_EDGE_QUERY_RESULTS,
    )
    .ok()?
    .into_iter()
    .filter(|edge| edge.kind == EdgeKind::FacetOf)
    .map(|edge| edge.target)
    .collect();
    let world = if kind == ENTITY_TYPE_CLAIM {
        vault
            .get_claim_in_txn(txn, id)
            .ok()?
            .and_then(|claim| claim.world)
    } else {
        None
    };
    Some(Position {
        selected,
        read: scope_for_blob(&vault.store, txn, *id, &raw).ok()?,
        facets,
        world,
    })
}

/// Whether a record at `restored` is admitted where one at `live` is not.
/// A door admits a position only within the scope it holds
/// (`Scope::admits`, `Scope::is_narrowing_of`), and never one with an empty
/// axis; `None` is a record no door admits.
fn widens(live: Option<&Scope>, restored: Option<&Scope>) -> bool {
    let admitted = |scope: &Scope| Scope::top().admits("read", scope, &Scope::top());
    match (live, restored) {
        (_, None) => false,
        (_, Some(restored)) if !admitted(restored) => false,
        (None, Some(_)) => true,
        (Some(live), Some(restored)) => !admitted(live) || !live.is_narrowing_of(restored),
    }
}

/// A key a read is asked under.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Reader {
    /// A vault owner's own key.
    Owner(EntityId),
    /// A key a host asserts for an actor ref, of a class or of none.
    Asserted(String, Option<String>),
}

impl Reader {
    fn key(&self) -> Option<ScopedReadActorKey> {
        match self {
            Self::Owner(owner) => Some(ScopedReadActorKey::vault_owner(*owner)),
            Self::Asserted(actor, None) => ScopedReadActorKey::new(actor.clone()),
            Self::Asserted(actor, Some(class)) => {
                ScopedReadActorKey::with_actor_class(actor.clone(), class.clone())
            }
        }
    }
}

/// An actor ref no key in `named` asserts: longer than every one of them,
/// and, being no 32-digit id, the ref of no entity.
fn stranger(named: &BTreeSet<String>) -> String {
    "0".repeat(named.iter().map(String::len).max().unwrap_or(0).max(32) + 1)
}

/// Everyone both vaults hold as an owner or member.
fn owners(vaults: [&Vault; 2]) -> Result<BTreeSet<EntityId>> {
    let [live, restored] = vaults.map(Vault::live_member_ids);
    Ok(live?.intersection(&restored?).copied().collect())
}

/// Every entity of `kinds` both vaults hold and neither has deleted. A
/// decision about one record is asked only of these.
pub(super) fn kept(vaults: [&Vault; 2], kinds: &[u8]) -> Result<BTreeSet<EntityId>> {
    let mut ids = BTreeSet::new();
    for kind in kinds {
        ids.extend(held_by_both(vaults, *kind)?);
    }
    undeleted(vaults, ids)
}

/// The entities of `ids` both vaults hold and neither has deleted: one only
/// one vault holds, or one deleted since, is content leaving or returning
/// with the restore, and the shell a deletion keeps decides nothing.
pub(super) fn undeleted(
    vaults: [&Vault; 2],
    mut ids: BTreeSet<EntityId>,
) -> Result<BTreeSet<EntityId>> {
    for vault in vaults {
        let txn = vault.store.env.read_txn()?;
        let mut held = BTreeSet::new();
        for id in ids {
            if vault.store.entities.get(&txn, id.as_bytes())?.is_some()
                && !vault.store.port_deletion_state(&txn, &id)?.deleted
            {
                held.insert(id);
            }
        }
        ids = held;
    }
    Ok(ids)
}
