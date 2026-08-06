use std::collections::HashSet;

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::temporal::TimeRange;

pub const SKILL_RECORD_BODY_KEYS: [&str; 13] = [
    "skillId",
    "desc",
    "version",
    "approvalStatus",
    "lifecycleStatus",
    "source",
    "confidence",
    "generated",
    "humanAuthored",
    "dependencies",
    "provenance",
    "contentHash",
    "forkedFrom",
];
pub const SKILL_DEPENDENCY_KEYS: [&str; 2] = ["skillId", "minVersion"];

pub const SKILL_ID_MAX_BYTES: usize = 256;
pub const SKILL_VERSION_MAX_BYTES: usize = 128;
pub const SKILL_DESC_MAX_BYTES: usize = 4096;
pub const SKILL_MAX_DEPENDENCIES: usize = 64;

/// Byte length of a lowercase-hex SHA-256 canonical content hash on the wire.
pub const SKILL_CONTENT_HASH_HEX_LEN: usize = 64;

/// Upper bound on one canonicalized skill-tree path (relative, `/`-joined).
pub const SKILL_TREE_PATH_MAX_BYTES: usize = 1024;

/// Domain-separation tag for the canonical skill-tree hash. Versioned so a
/// future canonicalization change mints a new tag instead of silently
/// re-keying every stored identity.
pub const SKILL_TREE_HASH_DOMAIN: &[u8] = b"oneiron.skill.tree.v1\0";

const KEY_SKILL_ID: &str = SKILL_RECORD_BODY_KEYS[0];
const KEY_DESC: &str = SKILL_RECORD_BODY_KEYS[1];
const KEY_VERSION: &str = SKILL_RECORD_BODY_KEYS[2];
const KEY_APPROVAL_STATUS: &str = SKILL_RECORD_BODY_KEYS[3];
const KEY_LIFECYCLE_STATUS: &str = SKILL_RECORD_BODY_KEYS[4];
const KEY_SOURCE: &str = SKILL_RECORD_BODY_KEYS[5];
const KEY_CONFIDENCE: &str = SKILL_RECORD_BODY_KEYS[6];
const KEY_GENERATED: &str = SKILL_RECORD_BODY_KEYS[7];
const KEY_HUMAN_AUTHORED: &str = SKILL_RECORD_BODY_KEYS[8];
const KEY_DEPENDENCIES: &str = SKILL_RECORD_BODY_KEYS[9];
const KEY_PROVENANCE: &str = SKILL_RECORD_BODY_KEYS[10];
const KEY_CONTENT_HASH: &str = SKILL_RECORD_BODY_KEYS[11];
const KEY_FORKED_FROM: &str = SKILL_RECORD_BODY_KEYS[12];

const KEY_DEP_SKILL_ID: &str = SKILL_DEPENDENCY_KEYS[0];
const KEY_DEP_MIN_VERSION: &str = SKILL_DEPENDENCY_KEYS[1];

/// SKILL lifecycle machine (ARCH-0053 §6, ONE-1735) — ONE machine for every
/// skill, whatever its birth path (Dreamer distill, conversation convert
/// [ONE-1446], hub import [OF-201]).
///
/// ```text
/// candidate ──admission gate──▶ active ──┬─▶ stale        (source deleted; visible, reversible)
///   (scan + held-out where scorable,     ├─▶ quarantined  (soft-retired: out of packs,
///    ONE-1449 — that gate ARMS the       │                 evidence kept, revivable,
///    candidate→active transition)        │                 ALWAYS PROPOSED, never automatic)
///                                        └─▶ superseded   (new revision admitted; this rev
///                                                          never loads as canon again)
/// ```
///
/// Laws pinned here:
/// - **Terminal delete never happens.** There is no deleted/retracted state;
///   the strictest exit is `Quarantined`, which keeps evidence and stays
///   revivable. The pre-ONE-1735 reuse of the claim lifecycle exposed a
///   `retracted` string for skills; that string no longer parses (fail
///   closed) — soft retirement is `quarantined`.
/// - **`Stale` folds ONE-1447's semantics** into the one machine instead of
///   a bespoke flag: the skill's source messages were deleted, the record
///   stays visible, and the state is reversible (`Stale → Active`) when the
///   evidence situation recovers.
/// - **`Quarantined` is outcome-driven and consent-gated**: a reliability
///   floor-crossing (SK-05) may only PROPOSE quarantine — the update door
///   rejects a transition into `Quarantined` stamped `approval = auto`.
/// - **`Superseded` is terminal for the revision** (not for the skill): the
///   old revision is frozen and never loads as canon; continuing the skill
///   means admitting a new revision ([`Vault::supersede_skill_record`]).
/// - **Identity/alignment-tier skills never enter the auto-edit loop** at
///   all (ratified with the SKILL-CONV/SKILL-OPT wave, ONE-1446..1449); the
///   auto-edit loop is SKILL-OPT machinery and enforces that law at its own
///   door — the lifecycle machine carries no bypass for it.
///
/// `AgentDefinition` (OF-334, ONE-1443) deliberately rides `SkillRecord`'s
/// lifecycle machinery; migrating its lifecycle field onto this enum is
/// ONE-1443 follow-up, not part of ONE-1735.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SkillLifecycle {
    /// Born, not yet admitted. All three birth paths start here.
    Candidate,
    /// Admitted through the gate; the only state that loads as canon.
    Active,
    /// Source evidence deleted (ONE-1447). Visible and reversible.
    Stale,
    /// Outcome-driven soft retirement: excluded from packs, evidence kept,
    /// revivable. Entering this state is ALWAYS PROPOSED, never automatic.
    Quarantined,
    /// A newer revision was admitted; this revision is frozen and never
    /// loads as canon again.
    Superseded,
}

impl SkillLifecycle {
    /// The pinned on-disk string for this state.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Active => "active",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
            Self::Superseded => "superseded",
        }
    }

    /// Parses a pinned on-disk state string. `retracted` (the pre-ONE-1735
    /// claim-lifecycle leak) deliberately does not parse: terminal delete
    /// never happens, soft retirement is `quarantined`.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "candidate" => Some(Self::Candidate),
            "active" => Some(Self::Active),
            "stale" => Some(Self::Stale),
            "quarantined" => Some(Self::Quarantined),
            "superseded" => Some(Self::Superseded),
            _ => None,
        }
    }

    /// The legal-transition table of the one lifecycle machine. Self-loops
    /// are allowed (state-preserving updates); everything else is exactly
    /// the ARCH-0053 §6 diagram plus its two documented reversals
    /// (`Stale → Active`, `Quarantined → Active`). `Superseded` has no
    /// exits: an old revision never loads as canon again.
    #[must_use]
    pub fn can_transition(self, to: Self) -> bool {
        if self == to {
            return true;
        }
        matches!(
            (self, to),
            (Self::Candidate, Self::Active)
                | (Self::Active, Self::Stale)
                | (Self::Active, Self::Quarantined)
                | (Self::Active, Self::Superseded)
                | (Self::Stale, Self::Active)
                | (Self::Quarantined, Self::Active)
        )
    }

    /// Whether a record in this state may load as canon (pack assembly,
    /// dependency resolution, tier-1 index). `Active` only: candidates are
    /// pre-admission, stale lost its evidence (reversibly), quarantined is
    /// excluded-but-revivable, superseded is frozen history.
    #[must_use]
    pub fn loads_as_canon(self) -> bool {
        self == Self::Active
    }
}

/// Canonical skill identity: SHA-256 over the canonicalized file tree
/// (ARCH-0053 §7, ONE-1735). Recomputable from any source, so the same
/// content fetched via two hubs is ONE entity — hub refs live in the
/// separate mutable alias/provenance layer, never in this hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SkillContentHash([u8; 32]);

impl SkillContentHash {
    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Pinned wire form: 64 lowercase hex characters.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(SKILL_CONTENT_HASH_HEX_LEN);
        for byte in self.0 {
            out.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble < 16"));
            out.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("nibble < 16"));
        }
        out
    }

    /// Parses the pinned wire form: exactly 64 lowercase hex characters.
    pub fn parse_hex(hex: &str) -> Result<Self> {
        const CONTEXT: &str = "contentHash must be 64 lowercase hex characters";
        if hex.len() != SKILL_CONTENT_HASH_HEX_LEN {
            return Err(Error::InvalidSkillBody(CONTEXT));
        }
        let mut bytes = [0_u8; 32];
        for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
            let hi = hex_nibble(chunk[0]).ok_or(Error::InvalidSkillBody(CONTEXT))?;
            let lo = hex_nibble(chunk[1]).ok_or(Error::InvalidSkillBody(CONTEXT))?;
            bytes[index] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Computes the canonical identity of a skill file tree (ARCH-0053 §7):
/// SHA-256 over a domain-tagged, length-prefixed, path-sorted encoding of
/// every `(relative path, content)` pair. Input order never matters; the
/// encoding is injective (lengths are prefixed), so no two distinct trees
/// collide by concatenation tricks.
///
/// Path canonicalization is strict and fail-closed: relative, `/`-joined,
/// no empty / `.` / `..` segments, no backslashes, colons (kills `C:/…`
/// drive-absolute paths), or NULs, at most [`SKILL_TREE_PATH_MAX_BYTES`]
/// bytes, no duplicates — duplicate detection ASCII-case-folds (`Foo` vs
/// `foo` alias on default Windows/macOS filesystems; full Unicode folding
/// is out of scope). An empty tree has no identity.
pub fn canonical_skill_tree_hash<'a, I>(files: I) -> Result<SkillContentHash>
where
    I: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let mut entries: Vec<(&str, &[u8])> = Vec::new();
    for (path, content) in files {
        validate_skill_tree_path(path)?;
        entries.push((path, content));
    }
    if entries.is_empty() {
        return Err(Error::InvalidSkillBody(
            "skill tree must contain at least one file",
        ));
    }
    entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    // ASCII case-fold duplicate rejection (subsumes exact duplicates):
    // `Foo` and `foo` alias on default Windows/macOS filesystems, so
    // hashing both could authenticate a different tree from the one that
    // executes.
    let mut folded = HashSet::new();
    for (path, _) in &entries {
        if !folded.insert(path.to_ascii_lowercase()) {
            return Err(Error::InvalidSkillBody("duplicate skill tree path"));
        }
    }

    let mut hasher = Sha256::new();
    hasher.update(SKILL_TREE_HASH_DOMAIN);
    hasher.update((entries.len() as u64).to_be_bytes());
    for (path, content) in entries {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((content.len() as u64).to_be_bytes());
        hasher.update(content);
    }
    Ok(SkillContentHash(hasher.finalize().into()))
}

fn validate_skill_tree_path(path: &str) -> Result<()> {
    const CONTEXT: &str = "skill tree paths must be relative, `/`-joined, without empty/dot segments, backslashes, colons, or NULs";
    if path.is_empty()
        || path.len() > SKILL_TREE_PATH_MAX_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.contains('\0')
    {
        return Err(Error::InvalidSkillBody(CONTEXT));
    }
    if path
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(Error::InvalidSkillBody(CONTEXT));
    }
    Ok(())
}

/// Cross-checks a hub-declared per-skill hash against the record's canonical
/// identity (ONE-1735; consumed by the skills-hub adapters, e.g. the
/// ONE-1741 native adapter whose hub publishes per-skill SHA-256). Case of
/// the declared hex is normalized; everything else is fail-closed: a record
/// without a canonical hash cannot be cross-checked, and a mismatch is an
/// error, never a warning.
pub fn cross_check_declared_content_hash(record: &SkillRecord, declared_hex: &str) -> Result<()> {
    let Some(canonical) = record.content_hash else {
        return Err(Error::InvalidSkillBody(
            "cannot cross-check: record carries no canonical content hash",
        ));
    };
    let declared = SkillContentHash::parse_hex(&declared_hex.to_ascii_lowercase())?;
    if declared != canonical {
        return Err(Error::InvalidSkillBody(
            "declared per-skill hash does not match canonical content hash",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkillDependency {
    pub skill_id: String,
    pub min_version: Option<String>,
}

impl SkillDependency {
    #[must_use]
    pub fn new(skill_id: impl Into<String>) -> Self {
        Self {
            skill_id: skill_id.into(),
            min_version: None,
        }
    }

    #[must_use]
    pub fn with_min_version(skill_id: impl Into<String>, min_version: impl Into<String>) -> Self {
        Self {
            skill_id: skill_id.into(),
            min_version: Some(min_version.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SkillRecord {
    pub skill_id: String,
    pub desc: String,
    pub version: String,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: SkillLifecycle,
    pub source: ClaimSource,
    /// DEMOTED CACHE (ARCH-0053 §5, ONE-1738): a materialization of the
    /// `skill.reliability` claim's Beta posterior mean, not a fact of its own.
    /// Claims are truth — the authoritative value is the claim on this SKILL
    /// entity, and [`crate::skill_reliability::rebuild_skill_confidence_cache`]
    /// recomputes this field from it (CID-7's demotion pattern).
    ///
    /// Consequences that are load-bearing rather than incidental:
    /// - selection reads the CLAIM
    ///   ([`crate::skill_reliability::skill_selection_score`]), never this
    ///   field, so a clobbered cache cannot change which skills load;
    /// - moving it mints no content revision (see `skill_content_changed`), so
    ///   a cache refresh needs no `version` bump and does not trip the
    ///   imported-content fork law.
    ///
    /// The wire key stays `confidence` and the field stays `f32`: the demotion
    /// is about AUTHORITY, and renaming it would have been an ABI break for no
    /// semantic gain.
    pub confidence: f32,
    pub generated: bool,
    pub human_authored: bool,
    pub dependencies: Vec<SkillDependency>,
    pub provenance: Value,
    /// Canonical identity layer: SHA-256 over the canonicalized file tree
    /// ([`canonical_skill_tree_hash`]). `None` when the identity has not
    /// been computed yet (legacy rows, records without a materialized
    /// tree). Hub refs are NOT here — they are the separate mutable
    /// alias/provenance layer (provenance rows; structured `hub_ref`
    /// shapes land with the SKILL_HUB entity, ONE-1736).
    pub content_hash: Option<SkillContentHash>,
    /// Fork lineage (one fork law, shared with `fork_system_agent` /
    /// ONE-1444): the parent SKILL entity this record was forked from.
    /// Immutable after birth; the fork door also writes the
    /// `DerivedFrom` lineage edge.
    pub forked_from: Option<EntityId>,
}

impl SkillRecord {
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor mirrors the pinned SKILL record fields"
    )]
    #[must_use]
    pub fn new(
        skill_id: impl Into<String>,
        desc: impl Into<String>,
        version: impl Into<String>,
        approval_status: ClaimApprovalStatus,
        lifecycle_status: SkillLifecycle,
        source: ClaimSource,
        confidence: f32,
        generated: bool,
        human_authored: bool,
        dependencies: Vec<SkillDependency>,
        provenance: Value,
    ) -> Self {
        Self {
            skill_id: skill_id.into(),
            desc: desc.into(),
            version: version.into(),
            approval_status,
            lifecycle_status,
            source,
            confidence,
            generated,
            human_authored,
            dependencies,
            provenance,
            content_hash: None,
            forked_from: None,
        }
    }

    /// Sets the canonical content hash (identity layer).
    #[must_use]
    pub fn with_content_hash(mut self, content_hash: SkillContentHash) -> Self {
        self.content_hash = Some(content_hash);
        self
    }

    /// Sets the fork-lineage parent (normally stamped by
    /// [`Vault::fork_skill_record`], not by hand).
    #[must_use]
    pub fn with_forked_from(mut self, parent: EntityId) -> Self {
        self.forked_from = Some(parent);
        self
    }
}

pub fn encode_skill_record(record: &SkillRecord) -> Result<Vec<u8>> {
    validate_skill_record(record)?;
    let mut entries = vec![
        (
            Value::from(KEY_SKILL_ID),
            Value::from(record.skill_id.as_str()),
        ),
        (Value::from(KEY_DESC), Value::from(record.desc.as_str())),
        (
            Value::from(KEY_VERSION),
            Value::from(record.version.as_str()),
        ),
        (
            Value::from(KEY_APPROVAL_STATUS),
            Value::from(record.approval_status.as_str()),
        ),
        (
            Value::from(KEY_LIFECYCLE_STATUS),
            Value::from(record.lifecycle_status.as_str()),
        ),
        (Value::from(KEY_SOURCE), Value::from(record.source.as_str())),
        (Value::from(KEY_CONFIDENCE), Value::F32(record.confidence)),
        (Value::from(KEY_GENERATED), Value::Boolean(record.generated)),
        (
            Value::from(KEY_HUMAN_AUTHORED),
            Value::Boolean(record.human_authored),
        ),
        (
            Value::from(KEY_DEPENDENCIES),
            Value::Array(
                record
                    .dependencies
                    .iter()
                    .map(encode_skill_dependency)
                    .collect(),
            ),
        ),
        (Value::from(KEY_PROVENANCE), record.provenance.clone()),
    ];
    // Elide-the-default (the claim `world`/`stale` pattern): absent means
    // "not computed" / "not a fork"; when present the shape is strict.
    if let Some(content_hash) = &record.content_hash {
        entries.push((
            Value::from(KEY_CONTENT_HASH),
            Value::from(content_hash.to_hex()),
        ));
    }
    if let Some(parent) = &record.forked_from {
        entries.push((Value::from(KEY_FORKED_FROM), Value::from(parent.to_hex())));
    }
    let value = Value::Map(entries);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &value)
        .map_err(|_| Error::InvariantViolation("SKILL record MessagePack encode failed"))?;
    Ok(out)
}

pub fn decode_skill_record(bytes: &[u8]) -> Result<SkillRecord> {
    let mut cursor = bytes;
    let value = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::InvalidSkillBody("body is not valid MessagePack"))?;
    if !cursor.is_empty() {
        return Err(Error::InvalidSkillBody("trailing bytes after body map"));
    }
    decode_skill_record_value(&value)
}

pub(crate) fn validate_skill_record_bytes(bytes: &[u8]) -> Result<()> {
    decode_skill_record(bytes).map(|_| ())
}

pub(crate) fn is_legacy_opaque_skill_body(bytes: &[u8]) -> bool {
    let mut cursor = bytes;
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return true;
    };
    !matches!(value, Value::Map(_))
}

pub(crate) fn validate_skill_update(prior: &SkillRecord, updated: &SkillRecord) -> Result<()> {
    validate_skill_update_for_door(prior, updated, false)
}

pub(crate) fn validate_hub_sync_skill_update(
    prior: &SkillRecord,
    updated: &SkillRecord,
) -> Result<()> {
    if prior.source != ClaimSource::Imported || updated.source != ClaimSource::Imported {
        return Err(Error::InvalidSkillBody(
            "hub sync only updates imported skills",
        ));
    }
    validate_skill_update_for_door(prior, updated, true)
}

fn validate_skill_update_for_door(
    prior: &SkillRecord,
    updated: &SkillRecord,
    allow_imported_content: bool,
) -> Result<()> {
    validate_skill_record(updated)?;
    if prior == updated {
        return Ok(());
    }
    if prior.skill_id != updated.skill_id {
        return Err(Error::InvalidSkillBody("skillId cannot change on update"));
    }
    if prior.generated != updated.generated || prior.human_authored != updated.human_authored {
        return Err(Error::InvalidSkillBody(
            "authorship flags cannot change on update",
        ));
    }
    if prior.source != updated.source {
        return Err(Error::InvalidSkillBody("source cannot change on update"));
    }
    if prior.forked_from != updated.forked_from {
        return Err(Error::InvalidSkillBody(
            "forkedFrom lineage cannot change on update",
        ));
    }
    // Lifecycle machine (ARCH-0053 §6): a superseded revision is frozen
    // history — it never loads as canon and never updates; continuing the
    // skill means admitting a NEW revision. All other moves must follow
    // the one transition table.
    if prior.lifecycle_status == SkillLifecycle::Superseded {
        return Err(Error::InvalidSkillBody(
            "superseded skill revision is frozen; admit a new revision instead",
        ));
    }
    if !prior
        .lifecycle_status
        .can_transition(updated.lifecycle_status)
    {
        return Err(Error::InvalidSkillBody(
            "illegal skill lifecycle transition",
        ));
    }
    // Quarantine is outcome-DRIVEN but human-RATIFIED: the proposal to
    // quarantine is a ROW (SK-05's floor-crossing proposal), never a
    // lifecycle state, so the only lawful entry is already-ratified.
    // The record-shape invariant in `validate_skill_record` enforces the
    // same law on every door; this transition-level check is kept as the
    // clearer early error.
    if updated.lifecycle_status == SkillLifecycle::Quarantined
        && prior.lifecycle_status != SkillLifecycle::Quarantined
        && updated.approval_status != ClaimApprovalStatus::Approved
    {
        return Err(Error::InvalidSkillBody(
            "quarantine entry is human-ratified: the proposal is a row, never a lifecycle state",
        ));
    }
    // Lifecycle/approval are STATE axes riding the record; flipping them
    // (stale ⇄ active, proposed → approved, supersession) does not mint a
    // content revision. Everything else is content and must bump `version`.
    if skill_content_changed(prior, updated) {
        if prior.version == updated.version {
            return Err(Error::InvalidSkillBody(
                "version must change when updating skill body",
            ));
        }
        // Fork law (ONE-1735, shared with ONE-1444): imported content
        // changes in place through NO generic door, whatever the approval
        // stamp — an in-place update marked "proposed" replaces canon the
        // moment it lands, which is a silent overwrite with a label. A
        // local edit is a fork (`Vault::fork_skill_record`); an upstream
        // update lands through the hub-sync door's own policy-checked
        // inlet (ONE-1736), which mints proposal artifacts / new
        // revisions instead of mutating this one.
        if prior.source == ClaimSource::Imported && !allow_imported_content {
            return Err(Error::InvalidSkillBody(
                "imported skill content never changes in place; local edits fork and upstream updates land through the hub-sync door",
            ));
        }
    }
    Ok(())
}

/// Whether anything OTHER than the two state axes (`approval_status`,
/// `lifecycle_status`) and the demoted `confidence` cache differs between the
/// two records.
fn skill_content_changed(prior: &SkillRecord, updated: &SkillRecord) -> bool {
    let mut normalized = updated.clone();
    normalized.approval_status = prior.approval_status;
    normalized.lifecycle_status = prior.lifecycle_status;
    // `confidence` is a CACHE of the `skill.reliability` claim's posterior mean
    // (ONE-1738), so refreshing it asserts nothing new about the skill's
    // CONTENT: it is normalized away exactly like the state axes. Requiring a
    // version bump for it would mint a revision per attributed outcome, and
    // banning it on imports would make an imported skill's reliability
    // permanently unmaterializable.
    normalized.confidence = prior.confidence;
    normalized != *prior
}

fn decode_skill_record_value(value: &Value) -> Result<SkillRecord> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidSkillBody("body must be a MessagePack map"));
    };

    let mut skill_id = None;
    let mut desc = None;
    let mut version = None;
    let mut approval_status = None;
    let mut lifecycle_status = None;
    let mut source = None;
    let mut confidence = None;
    let mut generated = None;
    let mut human_authored = None;
    let mut dependencies = None;
    let mut provenance = None;
    let mut content_hash = None;
    let mut forked_from = None;
    let mut seen = [false; SKILL_RECORD_BODY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidSkillBody("body keys must be strings"));
        };
        let Some(index) = SKILL_RECORD_BODY_KEYS
            .iter()
            .position(|known| *known == key)
        else {
            return Err(Error::InvalidSkillBody(
                "body key is not in the pinned SKILL_RECORD_BODY_KEYS set",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidSkillBody("duplicate body key"));
        }
        seen[index] = true;

        match SKILL_RECORD_BODY_KEYS[index] {
            KEY_SKILL_ID => {
                skill_id = Some(text_value(
                    value,
                    SKILL_ID_MAX_BYTES,
                    "skillId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_DESC => {
                desc = Some(text_value(
                    value,
                    SKILL_DESC_MAX_BYTES,
                    "desc must be a non-empty UTF-8 string at most 4096 bytes",
                )?);
            }
            KEY_VERSION => {
                version = Some(text_value(
                    value,
                    SKILL_VERSION_MAX_BYTES,
                    "version must be a non-empty UTF-8 string at most 128 bytes",
                )?);
            }
            KEY_APPROVAL_STATUS => {
                approval_status = Some(value.as_str().and_then(ClaimApprovalStatus::parse).ok_or(
                    Error::InvalidSkillBody(
                        "approvalStatus must be one of auto|proposed|approved|rejected",
                    ),
                )?);
            }
            KEY_LIFECYCLE_STATUS => {
                lifecycle_status = Some(value.as_str().and_then(SkillLifecycle::parse).ok_or(
                    Error::InvalidSkillBody(
                        "lifecycleStatus must be one of candidate|active|stale|quarantined|superseded",
                    ),
                )?);
            }
            KEY_SOURCE => {
                source =
                    Some(
                        value
                            .as_str()
                            .and_then(ClaimSource::parse)
                            .ok_or(Error::InvalidSkillBody(
                                "source must be one of user_stated|observed|inferred|imported|tool_output|generated",
                            ))?,
                    );
            }
            KEY_CONFIDENCE => {
                confidence = Some(crate::claim::unit_interval_f32(value).ok_or(
                    Error::InvalidSkillBody("confidence must be finite in [0, 1]"),
                )?);
            }
            KEY_GENERATED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidSkillBody("generated must be a boolean"));
                };
                generated = Some(*flag);
            }
            KEY_HUMAN_AUTHORED => {
                let Value::Boolean(flag) = value else {
                    return Err(Error::InvalidSkillBody("humanAuthored must be a boolean"));
                };
                human_authored = Some(*flag);
            }
            KEY_DEPENDENCIES => dependencies = Some(decode_skill_dependencies(value)?),
            KEY_PROVENANCE => provenance = Some(value.clone()),
            KEY_CONTENT_HASH => {
                let hex = value.as_str().ok_or(Error::InvalidSkillBody(
                    "contentHash must be 64 lowercase hex characters",
                ))?;
                content_hash = Some(SkillContentHash::parse_hex(hex)?);
            }
            KEY_FORKED_FROM => {
                let hex = value.as_str().ok_or(Error::InvalidSkillBody(
                    "forkedFrom must be a 32-char entity id hex string",
                ))?;
                forked_from = Some(EntityId::from_hex(hex).map_err(|_| {
                    Error::InvalidSkillBody("forkedFrom must be a 32-char entity id hex string")
                })?);
            }
            _ => unreachable!("index resolved from SKILL_RECORD_BODY_KEYS"),
        }
    }

    let record = SkillRecord {
        skill_id: skill_id.ok_or(Error::InvalidSkillBody("missing required key skillId"))?,
        desc: desc.ok_or(Error::InvalidSkillBody("missing required key desc"))?,
        version: version.ok_or(Error::InvalidSkillBody("missing required key version"))?,
        approval_status: approval_status.ok_or(Error::InvalidSkillBody(
            "missing required key approvalStatus",
        ))?,
        lifecycle_status: lifecycle_status.ok_or(Error::InvalidSkillBody(
            "missing required key lifecycleStatus",
        ))?,
        source: source.ok_or(Error::InvalidSkillBody("missing required key source"))?,
        confidence: confidence.ok_or(Error::InvalidSkillBody("missing required key confidence"))?,
        generated: generated.ok_or(Error::InvalidSkillBody("missing required key generated"))?,
        human_authored: human_authored.ok_or(Error::InvalidSkillBody(
            "missing required key humanAuthored",
        ))?,
        dependencies: dependencies
            .ok_or(Error::InvalidSkillBody("missing required key dependencies"))?,
        provenance: provenance.ok_or(Error::InvalidSkillBody("missing required key provenance"))?,
        // Optional identity/lineage layer: absent on pre-ONE-1735 bodies
        // and on records whose canonical tree is not materialized.
        content_hash,
        forked_from,
    };
    validate_skill_record(&record)?;
    Ok(record)
}

fn encode_skill_dependency(dependency: &SkillDependency) -> Value {
    Value::Map(vec![
        (
            Value::from(KEY_DEP_SKILL_ID),
            Value::from(dependency.skill_id.as_str()),
        ),
        (
            Value::from(KEY_DEP_MIN_VERSION),
            dependency
                .min_version
                .as_deref()
                .map_or(Value::Nil, Value::from),
        ),
    ])
}

fn decode_skill_dependencies(value: &Value) -> Result<Vec<SkillDependency>> {
    let Value::Array(values) = value else {
        return Err(Error::InvalidSkillBody(
            "dependencies must be a MessagePack array",
        ));
    };
    if values.len() > SKILL_MAX_DEPENDENCIES {
        return Err(Error::InvalidSkillBody(
            "dependencies must contain at most 64 entries",
        ));
    }
    values.iter().map(decode_skill_dependency).collect()
}

fn decode_skill_dependency(value: &Value) -> Result<SkillDependency> {
    let Value::Map(entries) = value else {
        return Err(Error::InvalidSkillBody(
            "dependency must be a MessagePack map",
        ));
    };

    let mut skill_id = None;
    let mut min_version = None;
    let mut seen = [false; SKILL_DEPENDENCY_KEYS.len()];

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidSkillBody("dependency keys must be strings"));
        };
        let Some(index) = SKILL_DEPENDENCY_KEYS.iter().position(|known| *known == key) else {
            return Err(Error::InvalidSkillBody(
                "dependency key must be skillId|minVersion",
            ));
        };
        if seen[index] {
            return Err(Error::InvalidSkillBody("duplicate dependency key"));
        }
        seen[index] = true;
        match SKILL_DEPENDENCY_KEYS[index] {
            KEY_DEP_SKILL_ID => {
                skill_id = Some(text_value(
                    value,
                    SKILL_ID_MAX_BYTES,
                    "dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
                )?);
            }
            KEY_DEP_MIN_VERSION => {
                min_version = Some(match value {
                    Value::Nil => None,
                    _ => Some(text_value(
                        value,
                        SKILL_VERSION_MAX_BYTES,
                        "dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
                    )?),
                });
            }
            _ => unreachable!("index resolved from SKILL_DEPENDENCY_KEYS"),
        }
    }

    Ok(SkillDependency {
        skill_id: skill_id.ok_or(Error::InvalidSkillBody(
            "missing required dependency key skillId",
        ))?,
        min_version: min_version.ok_or(Error::InvalidSkillBody(
            "missing required dependency key minVersion",
        ))?,
    })
}

fn validate_skill_record(record: &SkillRecord) -> Result<()> {
    validate_text_field(
        &record.skill_id,
        SKILL_ID_MAX_BYTES,
        "skillId must be a non-empty UTF-8 string at most 256 bytes",
    )?;
    validate_text_field(
        &record.desc,
        SKILL_DESC_MAX_BYTES,
        "desc must be a non-empty UTF-8 string at most 4096 bytes",
    )?;
    validate_text_field(
        &record.version,
        SKILL_VERSION_MAX_BYTES,
        "version must be a non-empty UTF-8 string at most 128 bytes",
    )?;
    if !record.confidence.is_finite() || !(0.0..=1.0).contains(&record.confidence) {
        return Err(Error::InvalidSkillBody(
            "confidence must be finite in [0, 1]",
        ));
    }
    if record.generated == record.human_authored {
        return Err(Error::InvalidSkillBody(
            "exactly one of generated or humanAuthored must be true",
        ));
    }
    if record.generated != (record.source == ClaimSource::Generated) {
        return Err(Error::InvalidSkillBody(
            "generated flag must match generated source",
        ));
    }
    // Record-SHAPE invariant (ONE-1735 review r1): quarantined is a
    // HUMAN-RATIFIED state — the proposal to quarantine is a row, never a
    // lifecycle state — so the only lawful shape is approval = approved.
    // Holds on EVERY door (create, update, sync replay): `quarantined`
    // did not exist on the skill wire before ONE-1735, so no lawful
    // legacy or peer row carries any other shape.
    if record.lifecycle_status == SkillLifecycle::Quarantined
        && record.approval_status != ClaimApprovalStatus::Approved
    {
        return Err(Error::InvalidSkillBody(
            "quarantined is a human-ratified state: approval must be approved",
        ));
    }
    validate_provenance(&record.provenance)?;
    validate_dependencies(&record.skill_id, &record.dependencies)?;
    Ok(())
}

fn validate_provenance(provenance: &Value) -> Result<()> {
    let Value::Map(entries) = provenance else {
        return Err(Error::InvalidSkillBody(
            "provenance must be a non-empty MessagePack map",
        ));
    };
    if entries.is_empty() {
        return Err(Error::InvalidSkillBody(
            "provenance must be a non-empty MessagePack map",
        ));
    }
    let mut seen = HashSet::new();
    for (key, _) in entries {
        let Some(key) = key.as_str() else {
            return Err(Error::InvalidSkillBody("provenance keys must be strings"));
        };
        if key.trim().is_empty() {
            return Err(Error::InvalidSkillBody(
                "provenance keys must be non-empty strings",
            ));
        }
        if !seen.insert(key) {
            return Err(Error::InvalidSkillBody("duplicate provenance key"));
        }
    }
    Ok(())
}

fn validate_dependencies(skill_id: &str, dependencies: &[SkillDependency]) -> Result<()> {
    if dependencies.len() > SKILL_MAX_DEPENDENCIES {
        return Err(Error::InvalidSkillBody(
            "dependencies must contain at most 64 entries",
        ));
    }
    let mut seen = HashSet::new();
    for dependency in dependencies {
        validate_text_field(
            &dependency.skill_id,
            SKILL_ID_MAX_BYTES,
            "dependency skillId must be a non-empty UTF-8 string at most 256 bytes",
        )?;
        if dependency.skill_id == skill_id {
            return Err(Error::InvalidSkillBody("skill must not depend on itself"));
        }
        if !seen.insert(dependency.skill_id.as_str()) {
            return Err(Error::InvalidSkillBody("duplicate skill dependency"));
        }
        if let Some(min_version) = &dependency.min_version {
            validate_text_field(
                min_version,
                SKILL_VERSION_MAX_BYTES,
                "dependency minVersion must be nil or a non-empty UTF-8 string at most 128 bytes",
            )?;
        }
    }
    Ok(())
}

fn text_value(value: &Value, max_bytes: usize, context: &'static str) -> Result<String> {
    let text = value.as_str().ok_or(Error::InvalidSkillBody(context))?;
    validate_text_field(text, max_bytes, context)?;
    Ok(text.to_owned())
}

fn validate_text_field(text: &str, max_bytes: usize, context: &'static str) -> Result<()> {
    if text.trim().is_empty() || text.len() > max_bytes {
        return Err(Error::InvalidSkillBody(context));
    }
    Ok(())
}

impl Vault {
    /// Typed SKILL put door. New records are born `candidate` — all three
    /// birth paths (Dreamer distill, conversation convert, hub import)
    /// enter the one lifecycle machine at the same state; the admission
    /// gate (ONE-1449) owns `candidate → active`. Existing records flow
    /// through the update gate at the batch chokepoint. The raw
    /// `put_entity` door stays state-agnostic on purpose: sync remat and
    /// legacy-body upgrades write already-lifecycled records.
    pub fn put_skill_record(
        &self,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_skill_record(record)?;
        if self.get_raw(id)?.is_none() {
            if record.lifecycle_status != SkillLifecycle::Candidate {
                return Err(Error::InvalidSkillBody(
                    "new skills are born candidate; the admission gate activates them",
                ));
            }
            // Fork lineage is not forgeable at the local create door: a
            // named parent must be a real type-7 SKILL. The DerivedFrom
            // edge stays door-authored (it references the fork, so it
            // cannot precede this create in the txn) and is not required
            // here. The batch chokepoint re-runs both checks for local
            // raw creates; sync remat (`replicated`) is exempt.
            if let Some(parent) = record.forked_from {
                self.validate_local_fork_parent(id, &parent)?;
            }
        }
        let mut wtxn = self.store.env.write_txn()?;
        self.apply_skill_record_body(&mut wtxn, id, occurred, learned_at, data, false)?;
        wtxn.commit()?;
        Ok(())
    }

    fn validate_local_fork_parent(&self, fork_id: &EntityId, parent: &EntityId) -> Result<()> {
        if parent == fork_id {
            return Err(Error::InvalidSkillBody(
                "forkedFrom cannot name the fork itself",
            ));
        }
        let Some(raw) = self.get_raw(parent)? else {
            return Err(Error::InvalidSkillBody(
                "forkedFrom parent must exist as a type-7 SKILL",
            ));
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::InvalidSkillBody(
                "forkedFrom parent must exist as a type-7 SKILL",
            ));
        }
        Ok(())
    }

    /// Forks a skill into a new entity — the ONE fork law, shared with
    /// [`Vault::fork_system_agent`] (ONE-1444): a local edit of an import
    /// is a fork, never an in-place overwrite. The fork is a NEW entity
    /// carrying `forked_from` lineage plus a `DerivedFrom` lineage edge to
    /// the parent (written in the same transaction); upstream auto-updates
    /// stop at the fork and arrive as merge PROPOSALs against the parent.
    ///
    /// The fork is stamped as an explicit local act
    /// (`source = UserStated`, `approval = Approved`) and is born
    /// `candidate` on its own version line: edited content re-enters
    /// through the admission gate like any other birth. `content_hash` is
    /// cleared — identity is recomputed from the edited tree, so an
    /// unedited fork never collides with its parent's canonical identity
    /// row.
    pub fn fork_skill_record(
        &self,
        parent_id: &EntityId,
        fork_id: &EntityId,
        fork_skill_id: &str,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<SkillRecord> {
        let parent = self
            .get_skill_record(parent_id)?
            .ok_or(Error::EntityNotFound)?;
        if fork_id == parent_id || self.get_raw(fork_id)?.is_some() {
            return Err(Error::InvalidSkillBody("fork target entity already exists"));
        }
        if fork_skill_id == parent.skill_id {
            return Err(Error::InvalidSkillBody(
                "fork must take its own skillId; the parent keeps the imported one",
            ));
        }
        let mut fork = SkillRecord::new(
            fork_skill_id,
            parent.desc.clone(),
            "1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            parent.dependencies.clone(),
            Value::Map(vec![
                (Value::from("forkOf"), Value::from(parent.skill_id.as_str())),
                (Value::from("forkOfEntity"), Value::from(parent_id.to_hex())),
                (
                    Value::from("forkOfVersion"),
                    Value::from(parent.version.as_str()),
                ),
            ]),
        );
        fork.forked_from = Some(*parent_id);
        let data = encode_skill_record(&fork)?;
        let mut wtxn = self.store.env.write_txn()?;
        self.apply_skill_record_body(&mut wtxn, fork_id, occurred, learned_at, data, false)?;
        self.batch_in()
            .edge(
                fork_id,
                EdgeKind::DerivedFrom,
                parent_id,
                EdgeKind::DerivedFrom.default_weight().unwrap_or(0.2),
            )
            .apply(&mut wtxn)?;
        wtxn.commit()?;
        Ok(fork)
    }

    /// Marks an old revision superseded by an admitted new revision of the
    /// SAME skill (ARCH-0053 §6): the old record flips
    /// `active → superseded` (frozen; never loads as canon again) and a
    /// `Supersedes` edge `new → old` records the succession, in one
    /// transaction. This door does NOT activate `new_id` — admission
    /// (`candidate → active`, ONE-1449) is the gate's act, not this one's.
    pub fn supersede_skill_record(
        &self,
        old_id: &EntityId,
        new_id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if old_id == new_id {
            return Err(Error::InvalidSkillBody(
                "a skill revision cannot supersede itself",
            ));
        }
        let old = self
            .get_skill_record(old_id)?
            .ok_or(Error::EntityNotFound)?;
        let new = self
            .get_skill_record(new_id)?
            .ok_or(Error::EntityNotFound)?;
        if new.skill_id != old.skill_id {
            return Err(Error::InvalidSkillBody(
                "supersession links two revisions of one skill",
            ));
        }
        if new.version == old.version {
            return Err(Error::InvalidSkillBody(
                "superseding revision must carry a new version",
            ));
        }
        // Canon (ARCH-0053 §6): superseded means "new version ADMITTED".
        // A non-active successor would leave the skillId with no admitted
        // canon revision at all. Activation itself stays the admission
        // gate's act (ONE-1449): callers admit first, then supersede.
        if new.lifecycle_status != SkillLifecycle::Active {
            return Err(Error::InvalidSkillBody(
                "superseding revision must be admitted (active) before it supersedes",
            ));
        }
        // Explicit Active check, NOT `can_transition(Superseded)`: the table's
        // self-loop allowance would let an already-superseded revision pass and
        // mint a second (bogus) succession edge.
        if old.lifecycle_status != SkillLifecycle::Active {
            return Err(Error::InvalidSkillBody(
                "only an active skill revision can be superseded",
            ));
        }
        let mut frozen = old;
        frozen.lifecycle_status = SkillLifecycle::Superseded;
        let data = encode_skill_record(&frozen)?;
        self.batch()
            .put(old_id, ENTITY_TYPE_SKILL, occurred, learned_at, &data)
            .edge(
                new_id,
                EdgeKind::Supersedes,
                old_id,
                EdgeKind::Supersedes.default_weight().unwrap_or(0.3),
            )
            .commit()
    }

    /// Typed SKILL update door. Rejects transitions INTO `superseded`:
    /// supersession is [`Vault::supersede_skill_record`]'s act (admitted
    /// successor + succession edge) — a bare flip here would orphan a
    /// frozen revision with no successor. The substrate gate
    /// (`validate_skill_update`) deliberately still admits the transition:
    /// the supersede door's own batch write and sync replay flow through
    /// it.
    pub fn update_skill_record(
        &self,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_skill_record(record)?;
        let mut wtxn = self.store.env.write_txn()?;
        let existing = self.read_skill_record_in_txn(&wtxn, id)?;
        if record.lifecycle_status == SkillLifecycle::Superseded
            && existing.lifecycle_status != SkillLifecycle::Superseded
        {
            return Err(Error::InvalidSkillBody(
                "supersession is supersede_skill_record's act; a bare flip would orphan a frozen revision",
            ));
        }
        validate_skill_update(&existing, record)?;
        self.apply_skill_record_body(&mut wtxn, id, occurred, learned_at, data, false)?;
        wtxn.commit()?;
        Ok(())
    }

    /// Writes the demoted `confidence` CACHE from the reliability projector
    /// (ONE-1738), inside the caller's write transaction.
    ///
    /// Every other field is copied from the STORED record, so a cache refresh
    /// structurally cannot smuggle a content edit — and the write still runs
    /// the ordinary update gate, so the lifecycle machine and the fork law keep
    /// their say. `skill_content_changed` normalizes `confidence` away, which
    /// is what lets this land on an imported skill without a version bump.
    ///
    /// Crate-private on purpose: hosts move this value by projecting the claim
    /// ([`crate::skill_reliability::rebuild_skill_confidence_cache`]), never by
    /// asserting a number.
    ///
    /// A SUPERSEDED revision keeps the cache it was frozen with. The lifecycle
    /// machine below hard-rejects any update to a frozen revision, and this
    /// door shares its caller's write transaction — so a late outcome
    /// attributed to v1 after v2 was admitted would roll back the OUTCOME and
    /// the reliability CLAIM alongside the cache write, losing valid evidence
    /// to a materialization. Truth still lands; only the cache, which the
    /// frozen revision no longer serves anything from, is skipped.
    pub(crate) fn refresh_skill_confidence_cache_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        confidence: f32,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let stored = self.read_skill_record_in_txn(wtxn, id)?;
        if stored.lifecycle_status == SkillLifecycle::Superseded {
            return Ok(());
        }
        let mut refreshed = stored.clone();
        refreshed.confidence = confidence;
        validate_skill_update(&stored, &refreshed)?;
        let data = encode_skill_record(&refreshed)?;
        self.apply_skill_record_body(wtxn, id, occurred, learned_at, data, false)
    }

    pub(crate) fn apply_hub_sync_skill_record(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        let data = encode_skill_record(record)?;
        self.apply_skill_record_body(wtxn, id, occurred, learned_at, data, true)
    }

    pub(crate) fn apply_hub_import_skill_record(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        record: &SkillRecord,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if record.source != ClaimSource::Imported {
            return Err(Error::InvalidSkillBody(
                "hub import package must carry imported source",
            ));
        }
        let data = encode_skill_record(record)?;
        self.apply_skill_record_body(wtxn, id, occurred, learned_at, data, false)
    }

    pub fn get_skill_record(&self, id: &EntityId) -> Result<Option<SkillRecord>> {
        let Some(raw) = self.get_raw(id)? else {
            return Ok(None);
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::InvalidSkillBody("entity is not a type-7 SKILL"));
        }
        decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
    }

    pub(crate) fn read_skill_record_in_txn(
        &self,
        txn: &heed::RwTxn<'_>,
        id: &EntityId,
    ) -> Result<SkillRecord> {
        let raw = self
            .store
            .entities
            .get(txn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != ENTITY_TYPE_SKILL {
            return Err(Error::InvalidSkillBody("entity is not a type-7 SKILL"));
        }
        decode_skill_record(&raw[ENTITY_METADATA_HEADER_LEN..])
    }

    fn apply_skill_record_body(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: Vec<u8>,
        hub_sync_imported: bool,
    ) -> Result<()> {
        // ONE-1741: a content-hash change no longer relocates scan verdicts.
        // Verdicts anchor to the immortal content bytes, so the departing hash's
        // verdicts stay discoverable on their own anchor and this holder simply
        // stops carrying that hash (the content-hash index is maintained by the
        // batch put/delete paths).
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            wtxn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: ENTITY_TYPE_SKILL,
                occurred,
                learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
