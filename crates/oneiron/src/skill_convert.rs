//! Message-to-skill conversion — the user-initiated middle road into the skill
//! library (ARCH-0017, registry OF-206).
//!
//! Three roads reach the SKILL namespace: Dreamer distill, this manual convert,
//! and hub import. ARCH-0053 §6/§7 gives all three ONE lifecycle machine and
//! ONE identity, so this module adds a DOOR, not a second namespace: the user
//! selects turns or messages, a host-supplied LLM tier refines them into a
//! SKILL.md-shaped tree, and the result lands through the ordinary
//! [`Vault::put_skill_record`] path as a `candidate` revision whose canonical
//! content hash enters the SAME content-hash index hub import dedups against.
//!
//! Layering, stated once:
//! - the MECHANICAL dedup tier is exact content hash and nothing else. It runs
//!   before the refiner's verdict is honoured and outranks it;
//! - the LLM tier judges NEAR-duplication, having been shown the nearest
//!   existing skills, and its decision is receipted onto the landed record's
//!   provenance rather than discarded;
//! - the engine never trusts the refiner for identity: the content hash is
//!   recomputed here from the returned tree, exactly as the hub import door
//!   recomputes it from a package.
//!
//! **Registry status flag (OF-206):** the ARCH-0017 page is still stamped
//! `proposed` in the registry. The SOW's acceptance list is what this module
//! implements; the flag is recorded here rather than blocked on, so a later
//! ratification pass can see precisely which door was built ahead of the stamp.
//!
//! **Not a routine (ONE-248).** A skill is procedural MEMORY; a routine is a
//! scheduled ACT. Nothing here imports or mints routine machinery.

use std::cmp::Reverse;
use std::collections::BTreeSet;

use rmpv::Value;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::CallPurpose;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN};
use crate::skill::{
    SkillContentHash, SkillDependency, SkillLifecycle, SkillRecord, canonical_skill_tree_hash,
    encode_skill_record, validate_skill_update,
};
use crate::skill_hub::HubFile;
use crate::skill_reliability::{ProvenanceTrustClass, SkillReliabilityPosterior};
use crate::store::Store;
use crate::temporal::TimeRange;

/// Provenance key carrying the source message/turn ids a converted skill was
/// derived from, as an array of 32-char entity-id hex strings.
///
/// STRUCTURED on purpose, and this ticket mints the convention: ONE-1447 marks
/// a skill `stale` when its sources are deleted, which needs the linkage to be
/// READABLE rather than narrated in prose. [`source_message_refs`] is the
/// matching reader.
pub const PROVENANCE_SOURCE_MESSAGES_KEY: &str = "source_messages";

/// Provenance key naming the birth path, so a record says which of the three
/// roads it came in on without inference from flag combinations.
pub const PROVENANCE_BIRTH_KEY: &str = "birth";

/// [`PROVENANCE_BIRTH_KEY`] value for this door (the string the `skill.rs`
/// lifecycle comment already calls "conversation convert").
pub const CONVERT_BIRTH_PATH: &str = "conversation_convert";

/// Provenance key carrying the refiner's dedup rationale: why these bytes are a
/// NEW skill, or why they are an edit of an existing one.
///
/// One key for both verdicts because it answers one question. Which verdict was
/// reached is said by the presence of [`PROVENANCE_MERGE_OF_KEY`], never by a
/// second rationale key that could disagree with the first.
pub const PROVENANCE_DEDUP_RATIONALE_KEY: &str = "dedup_rationale";

/// Provenance key on a merge PROPOSAL: the hex id of the existing skill entity
/// this revision proposes to supersede.
pub const PROVENANCE_MERGE_OF_KEY: &str = "merge_of";

/// [`CallPurpose::Other`] name for the refinement tier, so conversion is
/// budgeted and audited as its own class instead of hiding inside extraction's
/// totals (the `actor_session_distill` precedent).
pub const SKILL_CONVERT_CALL_PURPOSE_NAME: &str = "skill_convert_refine";

/// Upper bound on the turns/messages one conversion may select. A selection is
/// a user's gesture at a passage, not a transcript export; the same bound the
/// `actor.*` citation lists carry.
pub const CONVERT_MAX_SOURCE_MESSAGES: usize = 64;

/// Upper bound on the existing skills a refine brief is shown for its near-dup
/// diff. A shortlist the tier can actually read beats a catalogue it skims.
pub const CONVERT_MAX_NEIGHBORS: usize = 8;

/// Upper bound on a refiner's dedup rationale. It is a reason, not a report.
pub const CONVERT_RATIONALE_MAX_BYTES: usize = 1024;

/// Upper bound on the user's optional refinement hint.
pub const CONVERT_HINT_MAX_BYTES: usize = 4096;

/// How many SKILL rows the neighbour retrieval reads before it stops.
const CONVERT_NEIGHBOR_SCAN_LIMIT: usize = 1024;

/// Shortest token that participates in neighbour matching. One- and two-letter
/// tokens match everything and therefore rank nothing.
const CONVERT_TOKEN_MIN_CHARS: usize = 3;

/// Version prefix for a conversion-minted revision.
const CONVERT_VERSION_PREFIX: &str = "convert-";

/// Hex characters of the content hash carried in the version string.
const CONVERT_VERSION_HASH_HEX: usize = 16;

/// What the user selected, plus how they want it read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertRequest {
    /// TURN or MESSAGE entities, in selection order.
    pub message_refs: Vec<EntityId>,
    /// The user's guidance to the refiner (ARCH-0017's `userInstruction`).
    pub hint: Option<String>,
}

impl ConvertRequest {
    /// Selects messages with no hint.
    #[must_use]
    pub fn new(message_refs: Vec<EntityId>) -> Self {
        Self {
            message_refs,
            hint: None,
        }
    }

    /// Adds the user's refinement hint.
    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// Where a conversion landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertOutcome {
    /// A new `candidate` SkillRecord.
    Created(EntityId),
    /// These exact bytes are already in the library: the existing holder, not a
    /// second entity.
    DupPointer(EntityId),
    /// Near-duplicate: a `candidate`/`proposed` revision of `existing` awaiting
    /// the admission gate, never an in-place edit of canon.
    MergeProposed {
        existing: EntityId,
        proposal: EntityId,
    },
}

/// One selected utterance, as the refiner sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertUtterance {
    /// The TURN or MESSAGE these words came from — the id that lands in
    /// [`PROVENANCE_SOURCE_MESSAGES_KEY`].
    pub source: EntityId,
    pub speaker: Option<String>,
    pub text: Option<String>,
}

/// An existing skill the refiner must diff against before minting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillNeighbor {
    pub entity: EntityId,
    pub skill_id: String,
    pub desc: String,
}

/// What a refinement gets to reason over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillRefineBrief {
    /// The selected words, in selection order.
    pub said: Vec<ConvertUtterance>,
    pub hint: Option<String>,
    /// The nearest existing skills by name/description, nearest first. Possibly
    /// empty — an empty shortlist is the honest answer for a library with
    /// nothing alike in it, and the refiner must not read it as permission to
    /// skip the diff it did not need.
    pub neighbors: Vec<SkillNeighbor>,
}

/// The refiner's near-duplication call. Either answer is receipted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefineVerdict {
    /// Genuinely new, and here is why.
    Mint { justification: String },
    /// A near-duplicate of a skill from [`SkillRefineBrief::neighbors`]: land as
    /// a gated edit proposal against it instead of minting a rival.
    MergeInto {
        existing: EntityId,
        rationale: String,
    },
}

/// A refined SKILL.md-shaped tree plus the record fields it implies.
///
/// The tree is `HubFile`s because the engine has exactly one representation of
/// a skill file tree, and the identity function ([`canonical_skill_tree_hash`])
/// is defined over it. The bytes stay the host's to write to disk — the engine
/// persists the record and the tree's HASH, the same boundary the hub import
/// door draws.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefinedSkill {
    /// Frontmatter `name` (ARCH-0017): lowercase, hyphenated.
    pub skill_id: String,
    /// Frontmatter `description`: what it does AND when to use it.
    pub desc: String,
    /// The SKILL.md-shaped tree.
    pub files: Vec<HubFile>,
    pub verdict: RefineVerdict,
}

/// Refines selected conversation into a skill, or refuses.
///
/// The host implements this against the engine's existing LLM surface under
/// [`skill_convert_call_purpose`]; this module constructs no client (the
/// `dreamer_consolidation` / `SessionActorDistiller` posture). ARCH-0017 pins
/// the system prompt's contract — structure loosely-stated steps, keep the
/// user's voice, and INVENT NOTHING that is not in the source.
pub trait SkillRefiner {
    /// The skill `brief` supports.
    fn refine(&self, brief: &SkillRefineBrief) -> Result<RefinedSkill>;
}

/// The [`CallPurpose`] a refiner's LLM tier must stamp.
#[must_use]
pub fn skill_convert_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: SKILL_CONVERT_CALL_PURPOSE_NAME.to_owned(),
    }
}

/// The source message/turn ids a converted skill cites, or empty when the
/// record came in on another road.
///
/// Strict on the shape it wrote: a present-but-malformed linkage is corruption,
/// not an absent linkage, and ONE-1447's deletion sweep must not read it as
/// "this skill cites nothing".
pub fn source_message_refs(record: &SkillRecord) -> Result<Vec<EntityId>> {
    const CONTEXT: &str = "source_messages must be an array of 32-char entity id hex strings";
    let Value::Map(entries) = &record.provenance else {
        return Ok(Vec::new());
    };
    let Some((_, value)) = entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(PROVENANCE_SOURCE_MESSAGES_KEY))
    else {
        return Ok(Vec::new());
    };
    let Value::Array(refs) = value else {
        return Err(Error::InvalidSkillBody(CONTEXT));
    };
    refs.iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::InvalidSkillBody(CONTEXT))
        })
        .collect()
}

/// Converts selected turns/messages into a SKILL record (ARCH-0017 road 02).
///
/// The order of the steps IS the contract:
/// 1. resolve and FENCE-CHECK every selected ref. An off-record turn can never
///    reach the refiner, because a durable skill minted from fenced words would
///    outlive the session that was promised to evaporate — pipeline-inertness
///    is broken at the read, so the refusal has to precede the read;
/// 2. retrieve the nearest existing skills, so the refiner diffs against the
///    library instead of guessing at it;
/// 3. refine;
/// 4. recompute canonical identity from the returned tree — never trust the
///    refiner for it;
/// 5. exact-hash dedup and the landing run in ONE write transaction, so two
///    concurrent conversions of the same passage cannot both see "no holder"
///    and both create.
///
/// Approval is `approved` and lifecycle is `candidate`: ARCH-0017 rules that
/// user initiation IS consent for the CONVERSION, while ARCH-0053 §6 keeps
/// admission to canon the gate's act. A merge proposal is stamped `proposed`
/// instead — the user consented to converting their words, not to rewriting a
/// skill they did not name.
pub fn convert_messages_to_skill(
    vault: &Vault,
    request: &ConvertRequest,
    refiner: &dyn SkillRefiner,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<ConvertOutcome> {
    let said = resolve_selection(vault, request)?;
    let brief = SkillRefineBrief {
        neighbors: nearest_skills(vault, &said, request.hint.as_deref())?,
        said,
        hint: request.hint.clone(),
    };
    let refined = refiner.refine(&brief)?;
    let content_hash = canonical_skill_tree_hash(
        refined
            .files
            .iter()
            .map(|file| (file.path.as_str(), file.content.as_slice())),
    )?;
    let (rationale, merge_target) = match &refined.verdict {
        RefineVerdict::Mint { justification } => (justification.as_str(), None),
        RefineVerdict::MergeInto {
            existing,
            rationale,
        } => {
            // Grounding, not etiquette: a merge target the brief never showed
            // is a target the refiner did not diff against, so it cannot have
            // judged it near-duplicate.
            if !brief
                .neighbors
                .iter()
                .any(|neighbor| neighbor.entity == *existing)
            {
                return Err(Error::InvalidSkillBody(
                    "merge target must be one of the skills the refine brief offered",
                ));
            }
            (rationale.as_str(), Some(*existing))
        }
    };
    validate_text(
        rationale,
        CONVERT_RATIONALE_MAX_BYTES,
        "refiner rationale must be a non-empty string at most 1024 bytes",
    )?;

    vault.with_write_txn(|wtxn| {
        // The MECHANICAL tier, first and unconditionally: identical bytes are
        // ONE skill whichever road they arrive on, and no refiner verdict — not
        // even an insistent `Mint` — buys a second holder for them.
        if let Some(existing) = vault.skill_entity_for_content_hash_in_txn(&*wtxn, content_hash)? {
            return Ok(ConvertOutcome::DupPointer(existing));
        }
        let record = match merge_target {
            Some(existing) => {
                // Resolved at the WRITE door, not carried from the shortlist:
                // the proposal's parent has to still be there — and still be
                // proposable against — when it lands.
                let target = vault.read_skill_record_in_txn(wtxn, &existing)?;
                // `nearest_skills` keeps frozen revisions out of the brief, but
                // it read them BEFORE the refinement ran, and refinement runs
                // outside this transaction. A target superseded in that window
                // is dead on arrival: `supersede_skill_record` rejects a
                // non-active old revision, so the gate could never admit the
                // proposal. Refuse rather than land a record with no future.
                if target.lifecycle_status == SkillLifecycle::Superseded {
                    return Err(Error::InvalidSkillBody(
                        "merge target was superseded while the refinement ran",
                    ));
                }
                converted_record(
                    // The proposal continues the TARGET's skill id — that is
                    // what makes it a revision the admission gate can supersede
                    // with, rather than a rival skill under a new name.
                    &target.skill_id,
                    &refined.desc,
                    content_hash,
                    ClaimApprovalStatus::Proposed,
                    // And it continues the target's DEPENDENCY contract for the
                    // same reason: admitting a revision that declares none would
                    // amputate the requirements its predecessor shipped with.
                    // The refiner has no say — `RefinedSkill` carries no
                    // dependency channel, exactly so it cannot invent one.
                    target.dependencies,
                    provenance(&brief.said, rationale, Some(&existing)),
                )
            }
            None => converted_record(
                &refined.skill_id,
                &refined.desc,
                content_hash,
                ClaimApprovalStatus::Approved,
                // A minted skill declares nothing: dependencies are a curated
                // contract, and there is no prior revision to inherit one from.
                Vec::new(),
                provenance(&brief.said, rationale, None),
            ),
        };
        let id = EntityId::now();
        vault.put_skill_record_in_txn(wtxn, &id, &record, occurred, learned_at)?;
        Ok(match merge_target {
            Some(existing) => ConvertOutcome::MergeProposed {
                existing,
                proposal: id,
            },
            None => ConvertOutcome::Created(id),
        })
    })
}

/// Builds the record both verdicts land.
///
/// `generated` / `ClaimSource::Generated` is the honest stamp for either: an LLM
/// wrote these bytes, whoever chose the passage. ARCH-0053 §5 already names
/// "conversation convert" under [`ProvenanceTrustClass::Generated`], so the
/// confidence CACHE is seeded from that class's prior rather than from an
/// optimistic constant — a converted skill starts WEAK and earns its place.
fn converted_record(
    skill_id: &str,
    desc: &str,
    content_hash: SkillContentHash,
    approval: ClaimApprovalStatus,
    dependencies: Vec<SkillDependency>,
    provenance: Value,
) -> SkillRecord {
    SkillRecord::new(
        skill_id,
        desc,
        convert_version(content_hash),
        approval,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        SkillReliabilityPosterior::seeded_from_provenance(ProvenanceTrustClass::Generated).mean(),
        true,
        false,
        dependencies,
        provenance,
    )
    .with_content_hash(content_hash)
}

/// The revision's version string.
///
/// A revision's identity IS its content in this engine (ARCH-0053 §7), so the
/// version NAMES the content instead of counting behind it. That also settles
/// the merge-proposal case for free: the proposal's version differs from the
/// target's because their bytes differ — no counter to read, no collision to
/// resolve.
fn convert_version(content_hash: SkillContentHash) -> String {
    let hex = content_hash.to_hex();
    format!(
        "{CONVERT_VERSION_PREFIX}{}",
        &hex[..CONVERT_VERSION_HASH_HEX]
    )
}

/// The provenance map: birth path, structured source linkage, and the receipted
/// dedup rationale.
fn provenance(said: &[ConvertUtterance], rationale: &str, merge_of: Option<&EntityId>) -> Value {
    let mut sources: Vec<Value> = Vec::with_capacity(said.len());
    let mut seen = BTreeSet::new();
    for utterance in said {
        // A turn contributes once even when several of its messages were read:
        // the linkage is a citation SET, and ONE-1447 asks it "was this source
        // deleted", a question a repeat cannot answer twice.
        if seen.insert(utterance.source) {
            sources.push(Value::from(utterance.source.to_hex()));
        }
    }
    let mut entries = vec![
        (
            Value::from(PROVENANCE_BIRTH_KEY),
            Value::from(CONVERT_BIRTH_PATH),
        ),
        (
            Value::from(PROVENANCE_SOURCE_MESSAGES_KEY),
            Value::Array(sources),
        ),
        (
            Value::from(PROVENANCE_DEDUP_RATIONALE_KEY),
            Value::from(rationale),
        ),
    ];
    if let Some(existing) = merge_of {
        entries.push((
            Value::from(PROVENANCE_MERGE_OF_KEY),
            Value::from(existing.to_hex()),
        ));
    }
    Value::Map(entries)
}

/// Resolves the selection into utterances, refusing anything that must not be
/// read: a non-conversational ref, a fenced one, or a selection with no words.
///
/// Every id whose WORDS enter the brief is fence-probed: the MESSAGE children a
/// witnessed turn carries, AND the turn a directly-selected message belongs to.
/// The fence is about the content, and containment cuts both ways — a clear turn
/// container says nothing about its children, and a clear child row says nothing
/// about the fenced turn it sits inside.
fn resolve_selection(vault: &Vault, request: &ConvertRequest) -> Result<Vec<ConvertUtterance>> {
    if request.message_refs.is_empty() {
        return Err(Error::InvalidSkillBody(
            "conversion needs at least one selected message",
        ));
    }
    if request.message_refs.len() > CONVERT_MAX_SOURCE_MESSAGES {
        return Err(Error::InvalidSkillBody(
            "conversion selects at most 64 messages",
        ));
    }
    let mut selected = BTreeSet::new();
    for reference in &request.message_refs {
        if !selected.insert(*reference) {
            return Err(Error::InvalidSkillBody(
                "conversion selects each message at most once",
            ));
        }
    }
    if let Some(hint) = &request.hint {
        validate_text(
            hint,
            CONVERT_HINT_MAX_BYTES,
            "hint must be a non-empty string at most 4096 bytes",
        )?;
    }

    let mut said = Vec::new();
    for reference in &request.message_refs {
        // ARCH-0052 P6: no off-record probe. A live room's turns and messages
        // are overlay rows, and this conversion holds a canonical `&Vault`
        // that cannot address them — so a selection naming one fails here as
        // `EntityNotFound`, before the refiner tier is reached, without a
        // per-call membership test.
        match entity_type(vault, reference)? {
            ENTITY_TYPE_TURN => match utterance(vault, reference, "spkr", "txt")? {
                Some(spoken) if spoken.text.is_some() => said.push(spoken),
                // A witness TURN may carry only its speaker stamp; its words
                // remain in MESSAGE children and must be read in scan order.
                _ => said.extend(witnessed_words(vault, reference)?),
            },
            ENTITY_TYPE_MESSAGE => {
                said.extend(utterance(vault, reference, "author", "content")?);
            }
            _ => {
                return Err(Error::InvalidSkillBody(
                    "conversion selects TURN or MESSAGE entities",
                ));
            }
        }
    }
    if said.iter().all(|spoken| spoken.text.is_none()) {
        return Err(Error::InvalidSkillBody(
            "the selection carries no words to refine",
        ));
    }
    Ok(said)
}

fn entity_type(vault: &Vault, id: &EntityId) -> Result<u8> {
    let rtxn = vault.store.env.read_txn()?;
    vault
        .get_entity_type_in_txn(&rtxn, id)?
        .ok_or(Error::EntityNotFound)
}

/// The decoded body map of an entity, or `None` when it is absent, truncated,
/// or not a map. The one decode prelude every body read in this module shares.
fn body_entries(vault: &Vault, id: &EntityId) -> Result<Option<Vec<(Value, Value)>>> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault.store.entities.get(&rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(body) = raw.get(ENTITY_METADATA_HEADER_LEN..) else {
        return Ok(None);
    };
    Ok(
        match rmpv::decode::read_value(&mut std::io::Cursor::new(body)) {
            Ok(Value::Map(entries)) => Some(entries),
            _ => None,
        },
    )
}

/// Reads one utterance from an entity body, or `None` when it carries no words.
///
/// Both documented spellings of each key are accepted (`spkr`/`speaker`,
/// `txt`/`text`), the tolerance `dreamer_consolidation` and the `actor.*`
/// distiller read turns with; an undecodable body simply says nothing.
fn utterance(
    vault: &Vault,
    id: &EntityId,
    speaker_key: &str,
    text_key: &str,
) -> Result<Option<ConvertUtterance>> {
    let Some(entries) = body_entries(vault, id)? else {
        return Ok(None);
    };
    let mut speaker = None;
    let mut text = None;
    for (key, value) in entries {
        let Some(key) = key.as_str() else { continue };
        if (key == speaker_key || key == "speaker") && speaker.is_none() {
            speaker = value.as_str().map(str::to_owned);
        } else if (key == text_key || key == "text") && text.is_none() {
            text = value.as_str().map(str::to_owned);
        }
    }
    Ok(
        (speaker.is_some() || text.is_some()).then_some(ConvertUtterance {
            source: *id,
            speaker,
            text,
        }),
    )
}

/// The witnessed words of a turn: its MESSAGE children, in `(order, id)`.
fn witnessed_words(vault: &Vault, turn: &EntityId) -> Result<Vec<ConvertUtterance>> {
    // `edges_in` reports the FAR end in `target`, so these are the messages
    // that named this turn as their part-of container.
    let messages: Vec<EntityId> = vault
        .edges_in(turn)?
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::PartOf)
        .map(|edge| edge.target)
        .collect();

    let mut said: Vec<(u64, EntityId, ConvertUtterance)> = Vec::new();
    for message in messages {
        if entity_type(vault, &message)? != ENTITY_TYPE_MESSAGE {
            continue;
        }
        if let Some(spoken) = utterance(vault, &message, "author", "content")? {
            said.push((message_order(vault, &message)?, message, spoken));
        }
    }
    said.sort_by_key(|(order, id, _)| (*order, *id));
    Ok(said.into_iter().map(|(_, _, spoken)| spoken).collect())
}

/// A witnessed message's position inside its turn; absent reads as first.
fn message_order(vault: &Vault, message: &EntityId) -> Result<u64> {
    let Some(entries) = body_entries(vault, message)? else {
        return Ok(0);
    };
    Ok(entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("order"))
        .and_then(|(_, value)| value.as_u64())
        .unwrap_or(0))
}

/// The nearest existing skills by name/description, nearest first.
///
/// Retrieval is over the SELECTED WORDS, because the refined name and
/// description do not exist yet — the shortlist has to be in the brief the
/// refiner reads, and a second refinement pass to earn a better query would
/// double the ticket's only LLM cost to re-rank eight rows.
///
/// Superseded revisions are excluded: they are frozen history, and a proposal
/// against one could never be admitted.
fn nearest_skills(
    vault: &Vault,
    said: &[ConvertUtterance],
    hint: Option<&str>,
) -> Result<Vec<SkillNeighbor>> {
    let mut query = BTreeSet::new();
    for spoken in said {
        if let Some(text) = &spoken.text {
            collect_tokens(text, &mut query);
        }
    }
    if let Some(hint) = hint {
        collect_tokens(hint, &mut query);
    }
    if query.is_empty() {
        return Ok(Vec::new());
    }

    let mut scored: Vec<(usize, EntityId, SkillNeighbor)> = Vec::new();
    for entity in
        vault.entities_by_type_page(ENTITY_TYPE_SKILL, None, CONVERT_NEIGHBOR_SCAN_LIMIT)?
    {
        let record = match vault.get_skill_record(&entity) {
            Ok(Some(record)) => record,
            // A body that cannot be decoded cannot be diffed against, so it is
            // not a neighbour. One unreadable legacy row must not deny the
            // whole retrieval.
            Ok(None) | Err(_) => continue,
        };
        if record.lifecycle_status == SkillLifecycle::Superseded {
            continue;
        }
        let mut tokens = BTreeSet::new();
        collect_tokens(&record.skill_id, &mut tokens);
        collect_tokens(&record.desc, &mut tokens);
        let score = query.intersection(&tokens).count();
        if score == 0 {
            continue;
        }
        scored.push((
            score,
            entity,
            SkillNeighbor {
                entity,
                skill_id: record.skill_id,
                desc: record.desc,
            },
        ));
    }
    // Score descending, then entity id: a tie resolves the same way on every
    // replica, so two vaults hand their refiners the same shortlist.
    scored.sort_by_key(|(score, entity, _)| (Reverse(*score), *entity));
    scored.truncate(CONVERT_MAX_NEIGHBORS);
    Ok(scored
        .into_iter()
        .map(|(_, _, neighbor)| neighbor)
        .collect())
}

fn collect_tokens(text: &str, out: &mut BTreeSet<String>) {
    for token in text.split(|character: char| !character.is_alphanumeric()) {
        if token.chars().count() >= CONVERT_TOKEN_MIN_CHARS {
            out.insert(token.to_lowercase());
        }
    }
}

fn validate_text(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(())
}

// ─── the stale fold (ONE-1447) ──────────────────────────────────────────
//
// A converted skill CITES conversation. When the cited words leave the active
// store the skill is no longer grounded in anything a reader can check, so it
// stops loading as canon — visibly, reversibly, and without losing the record.
// Terminal delete never happens here (ARCH-0053 §6): a silent orphan and a
// deleted skill are the two failures this fold exists to avoid.

/// `vault_meta` prefix of the reverse source index:
/// `prefix ‖ source(16) ‖ skill(16)`, empty value.
///
/// Asking "which skills cite this id" by scanning every skill's provenance is
/// O(library) on EVERY entity delete; this makes it one prefix seek. The index
/// is a CACHE with an authority — the records themselves — and
/// [`rebuild_skill_source_index`] reconstructs it from them, so a missing or
/// drifted row costs a rebuild, never truth.
const SOURCE_INDEX_PREFIX: &[u8] = b"skill_convert/source_index/v1\0";

/// `vault_meta` prefix of the staleness note: `prefix ‖ skill(16)`, carrying a
/// MessagePack map of [`STALE_NOTE_REASON_KEY`] and
/// [`STALE_NOTE_DELETED_REFS_KEY`].
const STALE_NOTE_PREFIX: &[u8] = b"skill_convert/stale_note/v1\0";

/// Staleness-note key naming WHY a record went stale.
pub const STALE_NOTE_REASON_KEY: &str = "stale_reason";

/// Staleness-note key carrying the source ids whose deletion caused it, as
/// 32-char entity-id hex strings.
pub const STALE_NOTE_DELETED_REFS_KEY: &str = "deleted_refs";

/// The [`STALE_NOTE_REASON_KEY`] value this fold writes.
pub const STALE_REASON_SOURCE_MESSAGE_DELETED: &str = "source_message_deleted";

/// Why a skill is currently stale, and which deletions caused it.
///
/// Read through [`skill_stale_note`], which answers `None` for a record that is
/// not stale: the note describes the CURRENT episode, and an owner who has
/// already flipped the skill back to `active` ended it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillStaleNote {
    /// [`STALE_REASON_SOURCE_MESSAGE_DELETED`] for this fold.
    pub reason: String,
    /// The deleted source ids, in the order their deletions landed.
    pub deleted_refs: Vec<EntityId>,
}

/// The skills citing `source` as provenance, per the reverse index.
pub fn skills_dependent_on_message(vault: &Vault, source: &EntityId) -> Result<Vec<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    dependent_skills_in_txn(&vault.store, &rtxn, source)
}

/// The staleness note of a currently-stale skill, or `None`.
pub fn skill_stale_note(vault: &Vault, skill: &EntityId) -> Result<Option<SkillStaleNote>> {
    if vault.get_skill_record(skill)?.map(|r| r.lifecycle_status) != Some(SkillLifecycle::Stale) {
        return Ok(None);
    }
    let rtxn = vault.store.env.read_txn()?;
    vault
        .store
        .vault_meta
        .get(&rtxn, &stale_note_key(skill))?
        .map(|raw| decode_stale_note(&raw))
        .transpose()
}

/// Rebuilds the reverse source index from the SKILL records (the CID-7 door).
///
/// Drops every existing row first, so a rebuild is an identity rather than a
/// merge: a row for a citation no record makes any more would otherwise
/// outlive its evidence, which is precisely the failure this index guards.
pub fn rebuild_skill_source_index(vault: &Vault) -> Result<()> {
    let store = &vault.store;
    let mut wtxn = store.env.write_txn()?;

    // Collect, then write: the cursors are dropped before the first mutation
    // (the `backfill_content_hash_index_if_needed` pattern).
    let mut dead: Vec<Vec<u8>> = Vec::new();
    for entry in store.vault_meta.prefix_iter(&wtxn, SOURCE_INDEX_PREFIX)? {
        dead.push(entry?.0.to_vec());
    }
    let mut live: Vec<(EntityId, EntityId)> = Vec::new();
    for entry in store.type_index.prefix_iter(&wtxn, &[ENTITY_TYPE_SKILL])? {
        let skill = crate::vault::entity_id_from_type_index_key(&entry?.0)?;
        let Some(record) = read_live_skill_record_in_txn(store, &wtxn, &skill)? else {
            continue;
        };
        // Lenient on the way IN to a rebuild: one corrupt linkage must not deny
        // the whole reconstruction. The write door below is where a malformed
        // linkage is refused.
        for source in source_message_refs(&record.0).unwrap_or_default() {
            live.push((source, skill));
        }
    }

    for key in &dead {
        store.vault_meta.delete(&mut wtxn, key)?;
    }
    for (source, skill) in &live {
        store
            .vault_meta
            .put(&mut wtxn, &source_index_key(source, skill), &[])?;
    }
    wtxn.commit()?;
    Ok(())
}

/// Maintains the reverse index as a SKILL body lands, at the batch put
/// chokepoint every road funnels through — the typed doors, hub import, and
/// sync rematerialization alike. `previous` is the record this put replaces.
///
/// STRICT on the incoming linkage and lenient on the outgoing one: a malformed
/// `source_messages` in the new body is refused here, where the corruption
/// would enter, so the deletion sweep can never read a broken linkage as "this
/// skill cites nothing"; an unreadable PRIOR body is already on disk and only
/// costs unindexed rows, which the rebuild door clears.
pub(crate) fn maintain_skill_source_index_for_put(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    skill: &EntityId,
    previous: Option<&SkillRecord>,
    record: &SkillRecord,
) -> Result<()> {
    let next = source_message_refs(record)?;
    let dropped = previous
        .and_then(|previous| source_message_refs(previous).ok())
        .unwrap_or_default();
    for source in dropped.iter().filter(|source| !next.contains(source)) {
        store
            .vault_meta
            .delete(wtxn, &source_index_key(source, skill))?;
    }
    for source in &next {
        store
            .vault_meta
            .put(wtxn, &source_index_key(source, skill), &[])?;
    }
    Ok(())
}

impl Vault {
    /// Marks every skill citing `deleted` as stale, inside the transaction that
    /// is erasing it — so no reader ever observes a live skill grounded in
    /// evidence this vault has already dropped.
    ///
    /// The LIFECYCLE MACHINE decides who moves, not this fold: only a record
    /// whose state may transition to `stale` flips (ARCH-0053 §6 — `active`,
    /// plus the `stale` self-loop that records a second lost source). A
    /// `candidate` has not been admitted, and `quarantined`/`superseded`
    /// already never load as canon; none of them has a legal move here, and
    /// inventing one would put this hook above the table every other door
    /// obeys.
    ///
    /// Returns the skills it staled.
    pub(crate) fn mark_dependent_skills_stale_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        deleted: &EntityId,
    ) -> Result<Vec<EntityId>> {
        let dependents = dependent_skills_in_txn(&self.store, &*wtxn, deleted)?;
        let mut staled = Vec::with_capacity(dependents.len());
        for skill in dependents {
            let Some((record, occurred)) =
                read_live_skill_record_in_txn(&self.store, wtxn, &skill)?
            else {
                // The cited skill left the active store while its row lingered.
                // Prune as we read: the index is a cache, and a row nothing can
                // answer for is the one kind that never becomes true again.
                self.store
                    .vault_meta
                    .delete(wtxn, &source_index_key(deleted, &skill))?;
                continue;
            };
            if !record
                .lifecycle_status
                .can_transition(SkillLifecycle::Stale)
            {
                continue;
            }
            let note = match record.lifecycle_status {
                // Already stale: this is another source lost in the SAME
                // episode, so the note grows and the record is left alone —
                // re-encoding an unchanged body would mint an entity revision
                // that says nothing new.
                SkillLifecycle::Stale => {
                    let mut note = self.read_stale_note_in_txn(wtxn, &skill)?;
                    if !note.deleted_refs.contains(deleted) {
                        note.deleted_refs.push(*deleted);
                    }
                    note
                }
                // A fresh episode REPLACES the note: the refs of an episode the
                // owner already reversed are history, not causes of this one.
                _ => {
                    let mut staled_record = record.clone();
                    staled_record.lifecycle_status = SkillLifecycle::Stale;
                    validate_skill_update(&record, &staled_record)?;
                    let data = encode_skill_record(&staled_record)?;
                    // `occurred` is preserved and only `learned_at` moves: the
                    // skill did not happen again, this vault merely learned its
                    // evidence is gone.
                    self.apply_skill_record_body(
                        wtxn,
                        &skill,
                        occurred,
                        crate::unix_seconds_now(),
                        data,
                        false,
                    )?;
                    SkillStaleNote {
                        reason: STALE_REASON_SOURCE_MESSAGE_DELETED.to_owned(),
                        deleted_refs: vec![*deleted],
                    }
                }
            };
            let value = encode_stale_note(&note)?;
            self.store
                .vault_meta
                .put(wtxn, &stale_note_key(&skill), &value)?;
            staled.push(skill);
        }
        Ok(staled)
    }

    fn read_stale_note_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        skill: &EntityId,
    ) -> Result<SkillStaleNote> {
        Ok(
            match self.store.vault_meta.get(wtxn, &stale_note_key(skill))? {
                Some(raw) => decode_stale_note(&raw)?,
                None => SkillStaleNote {
                    reason: STALE_REASON_SOURCE_MESSAGE_DELETED.to_owned(),
                    deleted_refs: Vec::new(),
                },
            },
        )
    }
}

fn source_index_key(source: &EntityId, skill: &EntityId) -> Vec<u8> {
    let mut key = source_index_prefix(source);
    key.extend_from_slice(skill.as_bytes());
    key
}

fn source_index_prefix(source: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(SOURCE_INDEX_PREFIX.len() + 32);
    key.extend_from_slice(SOURCE_INDEX_PREFIX);
    key.extend_from_slice(source.as_bytes());
    key
}

fn stale_note_key(skill: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(STALE_NOTE_PREFIX.len() + 16);
    key.extend_from_slice(STALE_NOTE_PREFIX);
    key.extend_from_slice(skill.as_bytes());
    key
}

fn dependent_skills_in_txn(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    source: &EntityId,
) -> Result<Vec<EntityId>> {
    const CONTEXT: &str = "skill source index";
    let prefix = source_index_prefix(source);
    let mut skills = Vec::new();
    for entry in store.vault_meta.prefix_iter(rtxn, &prefix)? {
        let key = entry?.0;
        let bytes: [u8; 16] = key
            .get(prefix.len()..)
            .and_then(|tail| tail.try_into().ok())
            .ok_or(Error::CorruptedIndex(CONTEXT))?;
        skills.push(EntityId::from_bytes(bytes).map_err(|_| Error::CorruptedIndex(CONTEXT))?);
    }
    Ok(skills)
}

/// The SKILL record behind `id` plus its `occurred` range, or `None` when the
/// entity is gone or holds a body this fold cannot read (a soft-erased 25-byte
/// shell, a non-SKILL id, a legacy-opaque body).
fn read_live_skill_record_in_txn(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<Option<(SkillRecord, TimeRange)>> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_SKILL {
        return Ok(None);
    }
    let Ok(record) = crate::skill::decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..]) else {
        return Ok(None);
    };
    Ok(Some((
        record,
        TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        },
    )))
}

fn encode_stale_note(note: &SkillStaleNote) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (
            Value::from(STALE_NOTE_REASON_KEY),
            Value::from(note.reason.as_str()),
        ),
        (
            Value::from(STALE_NOTE_DELETED_REFS_KEY),
            Value::Array(
                note.deleted_refs
                    .iter()
                    .map(|reference| Value::from(reference.to_hex()))
                    .collect(),
            ),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &value)
        .map_err(|_| Error::InvalidSkillBody("stale note MessagePack encode failed"))?;
    Ok(bytes)
}

fn decode_stale_note(bytes: &[u8]) -> Result<SkillStaleNote> {
    const CONTEXT: &str = "skill stale note";
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes)) else {
        return Err(Error::CorruptedIndex(CONTEXT));
    };
    let entry = |wanted: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(wanted))
            .map(|(_, value)| value)
    };
    let reason = entry(STALE_NOTE_REASON_KEY)
        .and_then(Value::as_str)
        .ok_or(Error::CorruptedIndex(CONTEXT))?
        .to_owned();
    let Some(Value::Array(refs)) = entry(STALE_NOTE_DELETED_REFS_KEY) else {
        return Err(Error::CorruptedIndex(CONTEXT));
    };
    let deleted_refs = refs
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .ok_or(Error::CorruptedIndex(CONTEXT))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(SkillStaleNote {
        reason,
        deleted_refs,
    })
}

#[cfg(test)]
mod tests;
