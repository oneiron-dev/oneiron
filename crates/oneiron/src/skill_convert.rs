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
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::CallPurpose;
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_SKILL, ENTITY_TYPE_TURN};
use crate::skill::{
    SkillContentHash, SkillDependency, SkillLifecycle, SkillRecord, canonical_skill_tree_hash,
};
use crate::skill_hub::HubFile;
use crate::skill_reliability::{ProvenanceTrustClass, SkillReliabilityPosterior};
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
        refuse_fenced(vault, reference)?;
        match entity_type(vault, reference)? {
            ENTITY_TYPE_TURN => match utterance(vault, reference, "spkr", "txt")? {
                Some(spoken) => said.push(spoken),
                // The witness door writes turns as empty containers and their
                // words as MESSAGE children, so an empty turn body is a normal
                // shape rather than an empty turn.
                None => said.extend(witnessed_words(vault, reference)?),
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

/// Refuses a ref that is fenced off-record — directly, or through the turn it
/// is PART OF.
///
/// Reuses the write door's own fence rejection ([`Vault::is_turn_off_record_fenced`]
/// is the same probe `batch::apply_put` consults), so a caller pattern-matches
/// ONE error kind for "off-record refused" wherever the refusal is raised.
///
/// The container hop is the load-bearing half, not belt-and-braces:
/// `tag_turn_off_record` fences the TURN id alone — one `vault_meta` row and one
/// `fenced_turns` entry — and never touches the MESSAGE children that carry the
/// actual words. Probing only the named id would hand a selection naming a
/// fenced turn's CHILD exactly the words the fence exists to make unreadable.
/// One hop is the whole chain: the witness door writes `message --PartOf--> turn`,
/// and a turn is part of nothing.
///
/// The refusal names the FENCED id rather than the selected one, so the caller
/// learns which promise it walked into instead of which id it typed.
fn refuse_fenced(vault: &Vault, id: &EntityId) -> Result<()> {
    let containers = vault
        .edges_out(id)?
        .into_iter()
        .filter(|edge| edge.kind == EdgeKind::PartOf)
        .map(|edge| edge.target);
    for candidate in std::iter::once(*id).chain(containers) {
        if vault.is_turn_off_record_fenced(&candidate)? {
            return Err(Error::OffRecordFencedTurnWriteRejected {
                turn_ref: candidate.to_hex(),
            });
        }
    }
    Ok(())
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
        refuse_fenced(vault, &message)?;
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

#[cfg(test)]
mod tests;
