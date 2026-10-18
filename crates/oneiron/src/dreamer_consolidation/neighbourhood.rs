//! The known entities an extraction pass sees beside its transcript (map
//! gap 7, the slice a correction needs to bind). Shown only
//! `[turn speaker] text`, a model mints a new subject each pass and can never
//! name the claim a later turn corrects. So each entity the passage names
//! that already exists is listed with its id, its label and its newest
//! claims: a TURN's PERSON byline, or a whole word span equal to a stored
//! identity hint. Nothing is guessed; a span is a stored hint or it is not.
//!
//! Every row is read through the Dreamer's scoped read in the wake's one
//! snapshot. On an unscoped branch each listed claim is granted to the
//! branch as an exact prior head; a supplied scope is authority, so there
//! only the heads it already grants are listed. A candidate that names a
//! listed claim binds to it through the conflict and grant doors.
//!
//! Extraction children group the queued turns by the known entities they name.
//! JointIE and typed supersede or merge questions are separate jobs.
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use super::PriorHead;
use super::resources::{document_version, standing};
use super::value_projection::rmpv_to_json;
use crate::attempt_queue::AttemptId;
use crate::claim::{
    PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED, ScopedRead, claim_sensitivity_band,
    decode_claim_body, is_reserved_predicate,
};
use crate::llm::{Scope, ScopeResource};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_ORG, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE};
use crate::side_table::{self, LegacyJson, SideTable};
use crate::{EntityId, Result, Vault};

/// At most this many entities per branch: a few turns rarely name more known
/// people or places, and each one costs the transcript room.
const MAX_ENTITIES: usize = 8;
/// k: at most this many claims per entity, newest first. A correction
/// touches a current fact, and the newest few hold them.
const CLAIMS_PER_ENTITY: usize = 6;
/// The listing's byte budget, about a thousand tokens: context for the
/// transcript, never larger than a typical Micro transcript itself.
const MAX_BYTES: usize = 4 * 1024;
/// A listed value is cut here: enough to recognise the fact, not to replay a
/// long body into every later pass.
const VALUE_BYTES: usize = 96;
/// A label is cut here.
const LABEL_BYTES: usize = 64;
/// Names of up to four words ("Mary Ann van Dyke").
const SPAN_WORDS: usize = 4;
/// Identity-index probes per branch: a Meso round's words at four spans each,
/// over three kinds, stay under it.
const MAX_PROBES: usize = 8 * 1024;
/// Claims read through the scoped read per entity while looking for k it
/// admits, newest first.
const CLAIM_WALK: usize = 64;
/// Kinds a passage names by an identity hint.
const NAMED_KINDS: [u8; 3] = [ENTITY_TYPE_PERSON, ENTITY_TYPE_ORG, ENTITY_TYPE_PLACE];
/// The persona compile's owner floor: a restricted (or ambiguous) band is
/// never shown, here to a model.
const RESTRICTED_BAND: u8 = 3;

type Row = (u8, u64, Vec<u8>);
/// The claim rows a listing names, for the wake to pin as sources.
pub(super) type ListedRows = Vec<(EntityId, Row)>;
/// The ids one attempt listed: each entity with its listed claims, in order.
type Pins = Vec<(EntityId, Vec<EntityId>)>;

/// Per attempt, the entity and claim ids its extraction listed. A replay
/// after a kill lists the same ones, so its request matches the one an
/// earlier run memoized: the people it named and the claims it wrote since
/// never enter what it shows its model or the scope it asks under, and it
/// never pays for the call twice. A listed claim it closed itself drops out
/// of the listing, so that replay calls once more; its content-addressed
/// candidate ids then meet its own landed correction, which applies nothing
/// twice. Ids only; the text is read again at each wake.
const PINS: SideTable<[u8; 16], Pins, LegacyJson> =
    SideTable::new(&side_table::DREAMER_NEIGHBOURHOOD);

/// The bounded listing one branch shows its extraction model, and the heads
/// it may hold as priors.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Neighbourhood {
    entities: Vec<KnownEntity>,
    /// Heads the branch may hold that a pinned listing does not show: what
    /// the passage names now, beyond what the attempt listed first.
    unlisted: Vec<KnownClaim>,
    /// Pinned ids the Dreamer can no longer read, erased or withheld since
    /// the attempt listed them. The pin drops them for good.
    gone: BTreeSet<EntityId>,
    /// Exact named-entity matches for each frozen TURN body and text pair.
    mentions: BTreeMap<([u8; 32], [u8; 32]), Vec<EntityId>>,
}

#[derive(Debug, Clone, PartialEq)]
struct KnownEntity {
    id: EntityId,
    label: Option<String>,
    claims: Vec<KnownClaim>,
}

#[derive(Debug, Clone, PartialEq)]
struct KnownClaim {
    id: EntityId,
    version: ScopeResource,
    predicate: String,
    value: String,
}

impl Neighbourhood {
    /// The exact head versions the branch may hold as priors.
    pub(super) fn claim_versions(&self) -> impl Iterator<Item = (EntityId, &ScopeResource)> {
        self.entities
            .iter()
            .flat_map(|entity| &entity.claims)
            .chain(&self.unlisted)
            .map(|claim| (claim.id, &claim.version))
    }

    /// The listing as transcript lines, each claim only while `admitted`
    /// holds it as a prior head.
    pub(super) fn render(&self, admitted: impl Fn(&EntityId) -> bool) -> String {
        let mut out = String::new();
        for entity in &self.entities {
            out.push_str(&entity_line(entity.id, entity.label.as_deref()));
            for claim in entity.claims.iter().filter(|claim| admitted(&claim.id)) {
                out.push_str(&claim_line(claim));
            }
        }
        out
    }

    /// The exact versions of the heads the branch holds but the listing does
    /// not show: what the passage names now, beyond what a pinned listing
    /// lists.
    pub(super) fn unlisted_versions(&self) -> impl Iterator<Item = &ScopeResource> {
        self.unlisted.iter().map(|claim| &claim.version)
    }

    /// Whether the branch may hold `claim`, listed or not.
    pub(super) fn lists(&self, claim: EntityId) -> bool {
        self.claim_versions().any(|(id, _)| id == claim)
    }

    /// Whether the listing shows `claim`. A head the branch holds only for a
    /// replay's scope (`unlisted`) is not shown.
    pub(super) fn shows(&self, claim: EntityId) -> bool {
        self.entities
            .iter()
            .flat_map(|entity| &entity.claims)
            .any(|known| known.id == claim)
    }

    /// Exact identity-hint matches from the wake's frozen read. Labels are
    /// presentation only: an alias must group just like the stored name.
    pub(super) fn mentioned(&self, body: &[u8], text: Option<&str>) -> Vec<EntityId> {
        let mut ids: Vec<_> = self
            .mentions
            .get(&mention_key(body, text))
            .into_iter()
            .flatten()
            .copied()
            .filter(|id| self.entities.iter().any(|entity| entity.id == *id))
            .collect();
        ids.sort_unstable();
        ids
    }

    /// A child's listing and exact heads. Unlisted replay heads never enter
    /// its prompt or its request scope.
    pub(super) fn slice(&self, ids: &[EntityId]) -> Self {
        Self {
            entities: self
                .entities
                .iter()
                .filter(|entity| ids.contains(&entity.id))
                .cloned()
                .collect(),
            ..Self::default()
        }
    }

    /// The claims the listing shows about `entity`: each id, predicate and
    /// value as the listing writes it.
    pub(super) fn shown_about(
        &self,
        entity: EntityId,
    ) -> impl Iterator<Item = (EntityId, &str, &str)> {
        self.entities
            .iter()
            .filter(move |known| known.id == entity)
            .flat_map(|known| &known.claims)
            .map(|claim| (claim.id, claim.predicate.as_str(), claim.value.as_str()))
    }

    fn pins(&self) -> Pins {
        self.entities
            .iter()
            .map(|entity| {
                let claims = entity.claims.iter().map(|claim| claim.id).collect();
                (entity.id, claims)
            })
            .collect()
    }
}

/// Pins what `attempt` lists, unless an earlier run of it already did.
/// Called before its extraction call goes out. A pinned id the rebuild found
/// gone leaves the pin for good, so no later replay reads it again; a request
/// without it may miss its memo, at the cost of one call.
pub(super) fn pin(vault: &Vault, attempt: AttemptId, listed: &Neighbourhood) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        match PINS.get(&vault.store, txn, attempt.as_bytes())? {
            None => PINS.put(&vault.store, txn, attempt.as_bytes(), &listed.pins())?,
            Some(pins) if !listed.gone.is_empty() => {
                let kept: Pins = pins
                    .into_iter()
                    .filter(|(id, _)| !listed.gone.contains(id))
                    .map(|(id, claims)| {
                        let claims = claims
                            .into_iter()
                            .filter(|claim| !listed.gone.contains(claim))
                            .collect();
                        (id, claims)
                    })
                    .collect();
                PINS.put(&vault.store, txn, attempt.as_bytes(), &kept)?;
            }
            Some(_) => {}
        }
        Ok(())
    })
}

/// Drops what `attempt` listed. Called in the transaction that settles or
/// abandons it, once it can no longer replay.
pub(crate) fn unpin_neighbourhood_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
) -> Result<()> {
    PINS.delete(&vault.store, txn, attempt.as_bytes())?;
    Ok(())
}

/// What one branch reads around its passage. `turns` holds each TURN's stored body and frozen
/// text; `axes` the branch's world, facet, relationship and project, or `None` to list no
/// claims; `bound` a supplied scope.
pub(super) struct Passage<'p> {
    pub(super) turns: &'p [(&'p [u8], Option<&'p str>)],
    pub(super) axes: Option<&'p Scope>,
    pub(super) bound: Option<&'p Scope>,
}

/// One branch's neighbourhood at the wake's snapshot, with the claim rows it
/// names for the wake to pin as sources. An attempt an earlier run pinned
/// lists what it listed then, as those rows read now; the heads the passage
/// names now are held beside it, unlisted.
pub(super) fn discover_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    attempt: AttemptId,
    passage: &Passage<'_>,
) -> Result<(Neighbourhood, ListedRows)> {
    let mut mentions = BTreeMap::new();
    for turn in passage.turns {
        mentions.insert(
            mention_key(turn.0, turn.1),
            named_entities(vault, txn, std::slice::from_ref(turn))?,
        );
    }
    let (fresh, mut rows) = fresh_in(vault, txn, read, passage)?;
    let Some(pins) = PINS.get(&vault.store, txn, attempt.as_bytes())? else {
        return Ok((
            Neighbourhood {
                entities: fresh,
                mentions,
                ..Neighbourhood::default()
            },
            rows,
        ));
    };
    #[cfg(feature = "sync")]
    let device_only = crate::settings::device_local_worlds_at(
        vault,
        txn,
        crate::claim::CallerLocality::OffDevice,
    )?;
    #[cfg(not(feature = "sync"))]
    let device_only = BTreeSet::new();
    let ids: Vec<_> = pins.iter().map(|(id, _)| *id).collect();
    let mut entities = Vec::new();
    let mut gone = BTreeSet::new();
    for ((id, claims), row) in pins
        .into_iter()
        .zip(read.get_entities_parts_in_txn(txn, &ids)?)
    {
        let Some((kind, _, body)) = row else {
            gone.insert(id);
            continue;
        };
        if !NAMED_KINDS.contains(&kind) || !named_within(passage.bound, id, &body) {
            continue;
        }
        let mut entity = KnownEntity {
            id,
            label: label(&body),
            claims: Vec::new(),
        };
        if let Some(axes) = passage.axes {
            for (claim, row) in claims
                .iter()
                .zip(read.get_entities_parts_in_txn(txn, &claims)?)
            {
                let Some(row) = row else {
                    gone.insert(*claim);
                    continue;
                };
                if let Some(known) = listable(id, *claim, &row, axes, passage.bound, &device_only) {
                    entity.claims.push(known);
                    rows.push((*claim, row));
                }
            }
        }
        entities.push(entity);
    }
    let listed: BTreeSet<_> = entities
        .iter()
        .flat_map(|entity| entity.claims.iter().map(|claim| claim.id))
        .collect();
    let unlisted = fresh
        .into_iter()
        .flat_map(|entity| entity.claims)
        .filter(|claim| !listed.contains(&claim.id))
        .collect();
    Ok((
        Neighbourhood {
            entities,
            unlisted,
            gone,
            mentions,
        },
        rows,
    ))
}

fn mention_key(body: &[u8], text: Option<&str>) -> ([u8; 32], [u8; 32]) {
    (
        *blake3::hash(body).as_bytes(),
        *blake3::hash(text.unwrap_or_default().as_bytes()).as_bytes(),
    )
}

/// The bounded listing the passage names at this snapshot.
fn fresh_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    passage: &Passage<'_>,
) -> Result<(Vec<KnownEntity>, ListedRows)> {
    let named = named_entities(vault, txn, passage.turns)?;
    let rows = read.get_entities_parts_in_txn(txn, &named)?;
    let mut entities = Vec::new();
    let mut pinned = Vec::new();
    let mut bytes = 0;
    'entities: for (id, row) in named.into_iter().zip(rows) {
        let Some((kind, _, body)) = row else {
            continue;
        };
        if !NAMED_KINDS.contains(&kind) || !named_within(passage.bound, id, &body) {
            continue;
        }
        if entities.len() == MAX_ENTITIES {
            break;
        }
        let label = label(&body);
        bytes += entity_line(id, label.as_deref()).len();
        if bytes > MAX_BYTES {
            break;
        }
        let mut entity = KnownEntity {
            id,
            label,
            claims: Vec::new(),
        };
        let claims = match passage.axes {
            Some(axes) => newest_claims(vault, txn, read, id, axes, passage.bound)?,
            None => Vec::new(),
        };
        for (claim, row) in claims {
            bytes += claim_line(&claim).len();
            if bytes > MAX_BYTES {
                entities.push(entity);
                break 'entities;
            }
            entity.claims.push(claim);
            pinned.push(row);
        }
        entities.push(entity);
    }
    Ok((entities, pinned))
}

/// Entities the passage names, in the order it names them: each TURN's
/// PERSON byline, then every whole span of up to [`SPAN_WORDS`] words that
/// is a stored identity hint of a PERSON, ORG or PLACE.
fn named_entities(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turns: &[(&[u8], Option<&str>)],
) -> Result<Vec<EntityId>> {
    let mut seen = BTreeSet::new();
    let mut named = Vec::new();
    for (body, _) in turns {
        if let Ok(Some(author)) = crate::conversation::record_author(body)
            && seen.insert(author)
        {
            named.push(author);
        }
    }
    let mut probed = BTreeSet::new();
    let mut probes = 0;
    for (_, text) in turns {
        let words = words(text.unwrap_or_default());
        for start in 0..words.len() {
            for end in start + 1..=words.len().min(start + SPAN_WORDS) {
                let span = words[start..end].join(" ");
                if !probed.insert(span.clone()) {
                    continue;
                }
                for kind in NAMED_KINDS {
                    if probes == MAX_PROBES {
                        return Ok(named);
                    }
                    probes += 1;
                    for id in vault.lookup_identity_key_in_txn(txn, kind, &span)? {
                        if seen.insert(id) {
                            named.push(id);
                        }
                    }
                }
            }
        }
    }
    Ok(named)
}

/// Whether a supplied scope lets the branch read the entity whose stored
/// `body` names it. A supplied scope is authority: an entity it grants no
/// read of is not shown, nor any claim about it. Without one, the Dreamer's
/// own scoped read admitted the row.
fn named_within(bound: Option<&Scope>, id: EntityId, body: &[u8]) -> bool {
    bound.is_none_or(|bound| bound.allows_read(&document_version(id, body)))
}

/// Lowercased words split at whitespace and sentence punctuation. A hyphen or
/// an apostrophe stays inside a word, so "Ann" never names "Ann-Marie".
fn words(text: &str) -> Vec<String> {
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '.' | ',' | '!' | '?' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '"'
            )
    })
    .filter(|word| !word.is_empty())
    .map(str::to_lowercase)
    .collect()
}

/// Up to k heads about `subject` the Dreamer may read and the branch may
/// hold as priors, newest first but an observed head below a stated one on
/// its question, with their rows.
fn newest_claims(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    read: &ScopedRead<'_>,
    subject: EntityId,
    axes: &Scope,
    bound: Option<&Scope>,
) -> Result<Vec<(KnownClaim, (EntityId, Row))>> {
    // A subject of any fan-in lists its newest claims (Rule 5): the subject
    // read raises its own scan check past its row and reads on.
    let ids = vault.claims_for_subject_in_txn(txn, &subject)?;
    // Order by the stored learned_at alone; only rows the scoped read admits
    // below are shown.
    let mut ordered = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
            && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
            && header.entity_type == ENTITY_TYPE_CLAIM
        {
            ordered.push((Reverse(header.learned_at), id));
        }
    }
    ordered.sort_unstable();
    ordered.truncate(CLAIM_WALK);
    let ids: Vec<_> = ordered.into_iter().map(|(_, id)| id).collect();
    // The worlds this device keeps to itself; none without sync.
    #[cfg(feature = "sync")]
    let device_only = crate::settings::device_local_worlds_at(
        vault,
        txn,
        crate::claim::CallerLocality::OffDevice,
    )?;
    #[cfg(not(feature = "sync"))]
    let device_only = BTreeSet::new();
    let rows = read.get_entities_parts_in_txn(txn, &ids)?;
    let mut claims = Vec::new();
    for (id, row) in ids.into_iter().zip(rows) {
        // A head awaiting its owner's confirmation is no prior for anyone.
        if let Some(row) = row
            && crate::gate::claim_consolidation_eligible_in_txn(
                &vault.store,
                txn,
                &id,
                crate::gate::ConsolidationReader::NewestClaims,
            )?
            && let Some(known) = listable(subject, id, &row, axes, bound, &device_only)
        {
            let body = decode_claim_body(&row.2, true).ok();
            claims.push(((known, (id, row)), body));
        }
    }
    // Held both (OF-023): an observed head never lists above a stated one
    // on its question, so the stated one keeps its place in the k.
    crate::context_pack::source_ranking::clamp_order(
        &mut claims,
        &Default::default(),
        |(_, body)| body.as_ref(),
    )?;
    claims.truncate(CLAIMS_PER_ENTITY);
    Ok(claims.into_iter().map(|(claim, _)| claim).collect())
}

/// A head about `subject` the branch may list and hold as a prior: a
/// consolidatable fact on the branch's axes (no engine bookkeeping, nothing
/// restricted, nothing a device keeps to itself), and one a supplied scope
/// grants.
fn listable(
    subject: EntityId,
    id: EntityId,
    row: &Row,
    axes: &Scope,
    bound: Option<&Scope>,
    device_only: &BTreeSet<EntityId>,
) -> Option<KnownClaim> {
    if row.0 != ENTITY_TYPE_CLAIM {
        return None;
    }
    let version = document_version(id, &row.2);
    // A head that does not decode or key is skipped, never a wake error.
    let body = decode_claim_body(&row.2, true).ok()?;
    let prior = PriorHead { claim_id: id, body };
    let body = &prior.body;
    if body.subject != crate::ClaimSubject::Entity(subject)
        || is_reserved_predicate(&body.predicate)
        || [PREDICATE_CONFLICT_OPEN, PREDICATE_CONFLICT_RESOLVED].contains(&&*body.predicate)
        || claim_sensitivity_band(body).is_none_or(|band| band >= RESTRICTED_BAND)
        || bound.is_some_and(|bound| !bound.allows_read(&version) || !bound.allows_write(&version))
        || body.world.is_some_and(|world| device_only.contains(&world))
        || standing(&prior, axes).ok().flatten().is_none()
    {
        return None;
    }
    Some(KnownClaim {
        id,
        version,
        predicate: prior.body.predicate.clone(),
        value: cut(&rmpv_to_json(&prior.body.value).to_string(), VALUE_BYTES),
    })
}

/// An entity's `name`, when its body carries one.
fn label(body: &[u8]) -> Option<String> {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    let name = rmpv_to_json(&value)
        .get("name")?
        .as_str()?
        .trim()
        .to_owned();
    (!name.is_empty()).then(|| cut(&name, LABEL_BYTES))
}

fn entity_line(id: EntityId, label: Option<&str>) -> String {
    match label {
        Some(label) => format!("entity {} {}\n", id.to_hex(), serde_json::json!(label)),
        None => format!("entity {}\n", id.to_hex()),
    }
}

fn claim_line(claim: &KnownClaim) -> String {
    format!(
        "  claim {} {} = {}\n",
        claim.id.to_hex(),
        claim.predicate,
        claim.value
    )
}

/// `text` cut to at most `limit` bytes on a character boundary, marked.
fn cut(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

impl Vault {
    #[cfg(test)]
    pub(crate) fn newest_claim_ids_for_test(
        &self,
        principal: EntityId,
        subject: EntityId,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let actor = crate::claim::ScopedReadActorKey::new(principal.to_hex())
            .ok_or(crate::Error::InvariantViolation("reader fixture actor"))?;
        let read = self.scoped_read(actor);
        Ok(
            newest_claims(self, &txn, &read, subject, &Scope::default(), None)?
                .into_iter()
                .map(|(known, _)| known.id)
                .collect(),
        )
    }
}
