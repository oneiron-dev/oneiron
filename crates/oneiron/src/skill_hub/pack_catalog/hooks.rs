//! The `hooks/` folder a pack carries (ARCH-0053 §7; ARCH-0080 §8,
//! PACK-HOOKS = A). One folder per hook: `HOOK.md`, an optional `intent.md`
//! and `body.js`. Owner consent binds an installed pack's hooks: each becomes
//! a CODE entity plus a binding claim, the row kind a connector subscription
//! writes. The runner is L11's; nothing here executes a body.
use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{PackManifest, PackSource, invalid};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::code_artifact::{
    CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES, CodeArtifactBody, CodeArtifactClass,
    encode_code_artifact_body,
};
use crate::consent::AuthenticatedOwner;
use crate::skill_hub::HubFile;
use crate::store::Store;
use crate::{
    ClaimApprovalStatus, ClaimCandidate, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
    EdgeActorClass, EdgeKind, EntityId, Error, Result, TimeRange, Vault, WriteActor, WriteEnvelope,
    WriteProvenance,
};

/// The binding's predicate: the same row kind a pack's `wakes` write.
const PREDICATE: &str = "agent.connector_subscription";
/// A hook binding's payload version; version 1 is a connector-event
/// subscription under the same predicate.
pub(crate) const HOOK_BINDING_VERSION: u8 = 2;
const HOOK_DIR: &str = "hooks/";
const HOOK_MANIFEST: &str = "HOOK.md";
const HOOK_INTENT: &str = "intent.md";
const HOOK_BODY: &str = "body.js";
const MAX_HOOK_BUDGET_MS: u32 = 60_000;
const MAX_SELECTOR_ENTRIES: usize = 64;

/// When a hook fires (ARCH-0080 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPhase {
    /// Before a verb, inside the call; it may stop the act.
    Pre,
    /// After a verb, inside the call.
    Post,
    /// After a write commits, on its own runner.
    Fact,
}

impl HookPhase {
    /// The time budget for one run when HOOK.md names none.
    const fn default_budget_ms(self) -> u32 {
        match self {
            Self::Pre => 50,
            Self::Post => 200,
            Self::Fact => 1_000,
        }
    }
}

/// The closed actor classes a selector may name (ARCH-0067 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookActorClass {
    Human,
    Agent,
    System,
}

/// How a hook's body may spend model time (ARCH-0035 render classes;
/// ARCH-0080 §4 Its shape).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookRenderClass {
    /// No model call: the body stays deterministic inside its budget.
    #[default]
    DeterministicEager,
    /// A fact hook that may call `ai.verdict`, paid from its pack's budget
    /// line.
    Generative,
}

impl HookRenderClass {
    const fn is_deterministic(&self) -> bool {
        matches!(self, Self::DeterministicEager)
    }
}

/// The one outcome set; the phase decides which kinds apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookOutcomeKind {
    Continue,
    Rewrite,
    Skip,
    Ask,
    AddBlock,
    Annotate,
    Redact,
    Propose,
    Enqueue,
    Effect,
    Nothing,
}

impl HookOutcomeKind {
    pub(crate) fn applies_in(self, phase: HookPhase) -> bool {
        use HookOutcomeKind::{
            AddBlock, Annotate, Ask, Continue, Effect, Enqueue, Nothing, Propose, Redact, Rewrite,
            Skip,
        };
        match phase {
            HookPhase::Pre => matches!(self, Continue | Rewrite | Skip | Ask | AddBlock),
            HookPhase::Post => matches!(
                self,
                Continue | Annotate | Redact | AddBlock | Propose | Enqueue | Effect
            ),
            HookPhase::Fact => matches!(self, Propose | Enqueue | Effect | AddBlock | Nothing),
        }
    }
}

/// What a HOOK.md declares: the selector table of ARCH-0080 §3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HookSelector {
    /// Globs over row names and SelfEffect labels; for a fact hook, over
    /// predicates.
    pub verbs: Vec<String>,
    /// Empty selects every class.
    pub actors: Vec<HookActorClass>,
    /// A world, facet, room or project; a scope only narrows.
    pub scope: Option<String>,
    pub phase: HookPhase,
    /// Higher runs first; ties break on the content hash.
    pub priority: i32,
    pub budget_ms: u32,
    /// The owner's narrowing dial. Off by default.
    pub blocking: bool,
    /// The engine refuses any other kind from this hook.
    pub outcomes: Vec<HookOutcomeKind>,
    /// A post-hook's served-row filter: it runs only on a call that served
    /// rows (a recall's pack, a deadline's cut pack included) when one of
    /// them matches, and reads only those. An entry is `<kind glob>:<predicate
    /// glob>`, or a bare predicate glob over served claims.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub served: Vec<String>,
    /// `generative` lets a fact hook call `ai.verdict`.
    #[serde(default, skip_serializing_if = "HookRenderClass::is_deterministic")]
    pub render_class: HookRenderClass,
}

/// One hook folder as the pack carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackHook {
    pub name: String,
    pub version: String,
    pub selector: HookSelector,
    /// The prompt the body came from, when the author kept it.
    pub intent: Option<String>,
    /// BLAKE3 of `body.js`: the code identity the binding names.
    pub body_hash: [u8; 32],
}

impl PackHook {
    /// The capability set the update rule compares: an update that adds a
    /// token asks consent again (ARCH-0080 §9).
    pub(super) fn capability_tokens(&self) -> Vec<String> {
        let selector = &self.selector;
        let name = &self.name;
        let mut tokens = vec![
            format!("{name}/phase:{}", wire(&selector.phase)),
            format!("{name}/budget_ms:{}", selector.budget_ms),
        ];
        tokens.extend(
            selector
                .verbs
                .iter()
                .map(|verb| format!("{name}/verb:{verb}")),
        );
        if selector.actors.is_empty() {
            tokens.push(format!("{name}/actor:*"));
        }
        tokens.extend(
            selector
                .actors
                .iter()
                .map(|actor| format!("{name}/actor:{}", wire(actor))),
        );
        tokens.push(format!(
            "{name}/scope:{}",
            selector.scope.as_deref().unwrap_or("*")
        ));
        tokens.extend(
            selector
                .outcomes
                .iter()
                .map(|outcome| format!("{name}/outcome:{}", wire(outcome))),
        );
        if selector.blocking {
            tokens.push(format!("{name}/blocking"));
        }
        if selector.phase == HookPhase::Post {
            if selector.served.is_empty() {
                tokens.push(format!("{name}/served:*"));
            }
            tokens.extend(
                selector
                    .served
                    .iter()
                    .map(|entry| format!("{name}/served:{entry}")),
            );
        }
        if !selector.render_class.is_deterministic() {
            tokens.push(format!("{name}/render_class:{}", wire(&selector.render_class)));
        }
        tokens
    }

    fn parse(folder: &str, text: &str, body: &[u8], intent: Option<String>) -> Result<Self> {
        let front = super::super::folder::source_frontmatter(text)?
            .ok_or_else(|| invalid("HOOK.md requires frontmatter"))?;
        let mut fields = BTreeMap::new();
        for line in front.lines() {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with(char::is_whitespace) {
                return Err(invalid("nested HOOK.md YAML requires normalization"));
            }
            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| invalid("invalid HOOK.md field"))?;
            if !matches!(
                key,
                "name"
                    | "version"
                    | "verbs"
                    | "actors"
                    | "scope"
                    | "phase"
                    | "priority"
                    | "budget_ms"
                    | "blocking"
                    | "outcomes"
                    | "served"
                    | "render_class"
            ) {
                return Err(invalid("unknown HOOK.md field"));
            }
            if fields.insert(key, value.trim()).is_some() {
                return Err(invalid("duplicate HOOK.md field"));
            }
        }
        let scalar = |key| {
            fields
                .get(key)
                .map(|value| super::manifest::scalar(value, false))
                .transpose()
        };
        let name = scalar("name")?.ok_or_else(|| invalid("HOOK.md requires a name"))?;
        if name != folder {
            return Err(invalid("HOOK.md name must match its folder"));
        }
        let version = scalar("version")?.ok_or_else(|| invalid("HOOK.md requires a version"))?;
        if version.len() > 128 {
            return Err(invalid("hook version exceeds its bound"));
        }
        let phase: HookPhase = serde_json::from_value(serde_json::Value::String(
            scalar("phase")?.ok_or_else(|| invalid("HOOK.md requires a phase"))?,
        ))
        .map_err(|_| invalid("hook phase is pre, post or fact"))?;
        // An entry is a verb glob, or `<fact kind>:<predicate glob>`; the
        // first ':' splits them.
        let verbs: Vec<String> = json_list(&fields, "verbs")?;
        if verbs.is_empty() || !verbs.iter().all(|verb| selector_entry(verb)) {
            return Err(invalid("a hook selects one or more verb globs"));
        }
        // Served rows are a post-hook's to filter on.
        let served: Vec<String> = json_list(&fields, "served")?;
        if !served.iter().all(|entry| selector_entry(entry))
            || (!served.is_empty() && phase != HookPhase::Post)
        {
            return Err(invalid("only a post-hook filters served rows, by row globs"));
        }
        let render_class = match scalar("render_class")? {
            None => HookRenderClass::DeterministicEager,
            Some(class) => serde_json::from_value(serde_json::Value::String(class))
                .map_err(|_| invalid("hook render_class is deterministic_eager or generative"))?,
        };
        // A verb hook calls no model (ARCH-0080 §6).
        if !render_class.is_deterministic() && phase != HookPhase::Fact {
            return Err(invalid("only a fact hook may declare the generative class"));
        }
        let actors: Vec<HookActorClass> = json_list(&fields, "actors")?;
        let scope = scalar("scope")?;
        if scope.as_ref().is_some_and(|scope| scope.len() > 256) {
            return Err(invalid("hook scope exceeds its bound"));
        }
        let priority = scalar("priority")?
            .map(|value| value.parse::<i32>())
            .transpose()
            .map_err(|_| invalid("hook priority is an integer"))?
            .unwrap_or(0);
        let budget_ms = scalar("budget_ms")?
            .map(|value| value.parse::<u32>())
            .transpose()
            .map_err(|_| invalid("hook budget_ms is a whole number"))?
            .unwrap_or_else(|| phase.default_budget_ms());
        if budget_ms == 0 || budget_ms > MAX_HOOK_BUDGET_MS {
            return Err(invalid("hook budget_ms is out of bounds"));
        }
        let blocking = match scalar("blocking")?.as_deref() {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err(invalid("hook blocking is true or false")),
        };
        let outcomes: Vec<HookOutcomeKind> = json_list(&fields, "outcomes")?;
        if outcomes.is_empty() || outcomes.iter().any(|kind| !kind.applies_in(phase)) {
            return Err(invalid(
                "a hook returns only outcome kinds its phase allows",
            ));
        }
        Ok(Self {
            name,
            version,
            selector: HookSelector {
                verbs,
                actors,
                scope,
                phase,
                priority,
                budget_ms,
                blocking,
                outcomes,
                served,
                render_class,
            },
            intent,
            body_hash: *blake3::hash(body).as_bytes(),
        })
    }
}

/// A selector entry: a glob, or `<kind>:<glob>` split at the first ':';
/// bounded and lowercase.
fn selector_entry(entry: &str) -> bool {
    !entry.is_empty()
        && entry.len() <= 256
        && !entry.starts_with(':')
        && !entry.ends_with(':')
        && entry.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'*' | b':')
        })
}

/// A JSON string list, bounded and without repeats.
fn json_list<T: DeserializeOwned + Ord>(
    fields: &BTreeMap<&str, &str>,
    key: &str,
) -> Result<Vec<T>> {
    let Some(value) = fields.get(key) else {
        return Ok(Vec::new());
    };
    let entries: Vec<T> =
        serde_json::from_str(value).map_err(|_| invalid("HOOK.md list must be a JSON array"))?;
    let distinct = entries.iter().collect::<BTreeSet<_>>().len();
    if entries.len() > MAX_SELECTOR_ENTRIES || distinct != entries.len() {
        return Err(invalid("HOOK.md list is too long or repeats an entry"));
    }
    Ok(entries)
}

fn wire<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub(super) fn validate_hook_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
    {
        return Err(invalid("hook names are short lowercase folder names"));
    }
    Ok(())
}

/// The hooks a source's `hooks:` key names, each read from its folder. A
/// folder the key does not name, or any other file in a hook folder, is
/// refused.
pub(super) fn parse_source_hooks(
    manifest: &PackManifest,
    files: &[HubFile],
) -> Result<Vec<PackHook>> {
    let mut folders = BTreeMap::<&str, BTreeMap<&str, &[u8]>>::new();
    for file in files {
        let Some(relative) = file.path.strip_prefix(HOOK_DIR) else {
            continue;
        };
        let (folder, name) = relative
            .split_once('/')
            .ok_or_else(|| invalid("a hook must have a folder"))?;
        if !matches!(name, HOOK_MANIFEST | HOOK_INTENT | HOOK_BODY) {
            return Err(invalid(
                "a hook folder holds HOOK.md, intent.md and body.js only",
            ));
        }
        if !manifest.hooks.contains(folder) {
            return Err(invalid("hook folder is not named under hooks:"));
        }
        folders
            .entry(folder)
            .or_default()
            .insert(name, file.content.as_slice());
    }
    let mut hooks = Vec::new();
    for name in &manifest.hooks {
        let folder = folders
            .get(name.as_str())
            .ok_or_else(|| invalid("declared hook folder is absent"))?;
        let text = folder
            .get(HOOK_MANIFEST)
            .ok_or_else(|| invalid("a hook requires HOOK.md"))?;
        let body = folder
            .get(HOOK_BODY)
            .ok_or_else(|| invalid("a hook requires body.js"))?;
        let intent = folder
            .get(HOOK_INTENT)
            .map(|bytes| std::str::from_utf8(bytes).map(|text| text.trim().to_owned()))
            .transpose()
            .map_err(|_| invalid("intent.md is not UTF-8"))?
            .filter(|text| !text.is_empty());
        if intent
            .as_ref()
            .is_some_and(|text| text.len() > CODE_ARTIFACT_SUMMARY_PROMPT_MAX_BYTES)
        {
            return Err(invalid("intent.md exceeds the CODE prompt bound"));
        }
        let text = std::str::from_utf8(text).map_err(|_| invalid("HOOK.md is not UTF-8"))?;
        hooks.push(PackHook::parse(name, text, body, intent)?);
    }
    Ok(hooks)
}

/// A hook's binding: the claim payload under the subscription predicate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackHookBinding {
    /// [`HOOK_BINDING_VERSION`].
    pub version: u8,
    /// The CODE entity the binding names; the claim's subject.
    #[serde(with = "crate::serialize::entity_ref")]
    pub code: EntityId,
    #[serde(with = "crate::serialize::entity_ref")]
    pub owner: EntityId,
    /// The exact pack source the body came from.
    #[serde(with = "crate::serialize::entity_ref")]
    pub source: EntityId,
    pub pack: String,
    pub hook: String,
    pub hook_version: String,
    /// BLAKE3 of `body.js`, lowercase hex.
    pub body_hash: String,
    pub selector: HookSelector,
    /// Row state, like `AgentDefinition.enabled`; a rebind never flips it.
    pub enabled: bool,
}

/// Whether a subscription-predicate claim carries a hook binding rather than
/// a connector-event subscription.
pub(crate) fn is_hook_binding(body: &crate::ClaimBody) -> bool {
    #[derive(Deserialize)]
    struct Version {
        version: u8,
    }
    body.value
        .as_str()
        .and_then(|text| serde_json::from_str::<Version>(text).ok())
        .is_some_and(|row| row.version == HOOK_BINDING_VERSION)
}

/// Every live, approved hook binding, enabled or not. A claim whose payload
/// is no binding of its CODE entity is skipped with a warning, so one bad row
/// fails no call; a storage error still fails.
fn bindings_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, PackHookBinding)>> {
    let mut result = Vec::new();
    for id in crate::claim::claim_ids_for_predicate_in_txn(store, txn, PREDICATE)? {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)? else {
            continue;
        };
        let header =
            EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || raw.len() == ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if body.predicate != PREDICATE
            || !is_hook_binding(&body)
            || body.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                body.approval,
                ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
            )
        {
            continue;
        }
        match serde_json::from_str::<PackHookBinding>(body.value.as_str().unwrap_or_default()) {
            Ok(row) if body.subject == ClaimSubject::Entity(row.code) => result.push((id, row)),
            Ok(_) => tracing::warn!(
                claim = %id.to_hex(),
                "hook binding subject is not its CODE entity; skipped"
            ),
            Err(error) => tracing::warn!(
                claim = %id.to_hex(),
                %error,
                "hook binding is malformed; skipped"
            ),
        }
    }
    Ok(result)
}

/// The owner's dial on the binding claim at `id`, read from the raw claim so
/// a row [`bindings_in_txn`] skips as malformed still keeps its off choice.
/// `None` when no live, approved binding claim stands there; `Some(false)`
/// when one stands but its `enabled` flag cannot be read.
fn prior_enabled_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<bool>> {
    #[derive(Deserialize)]
    struct Dial {
        enabled: bool,
    }
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(None);
    };
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
        || raw.len() == ENTITY_METADATA_HEADER_LEN
    {
        return Ok(None);
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.predicate != PREDICATE
        || body.lifecycle != ClaimLifecycleStatus::Active
        || !matches!(
            body.approval,
            ClaimApprovalStatus::Approved | ClaimApprovalStatus::Auto
        )
    {
        return Ok(None);
    }
    Ok(Some(
        body.value
            .as_str()
            .and_then(|text| serde_json::from_str::<Dial>(text).ok())
            .is_some_and(|dial| dial.enabled),
    ))
}

fn binding_candidate(row: &PackHookBinding) -> Result<ClaimCandidate> {
    let value = serde_json::to_string(row).map_err(|_| invalid("hook binding encoding"))?;
    Ok(ClaimCandidate::new(
        PREDICATE,
        ClaimSubject::Entity(row.code),
        Value::from(value),
        1.0,
    ))
}

fn owner_envelope(
    owner: &AuthenticatedOwner,
    owner_id: EntityId,
    pack: &str,
    source: &EntityId,
) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        WriteActor::new(owner_id, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("pack.hooks")),
            (Value::from("pack"), Value::from(pack)),
            (
                Value::from("source"),
                Value::Binary(source.as_bytes().to_vec()),
            ),
            (
                Value::from("owner_decision"),
                Value::Binary(owner.decision_id().as_bytes().to_vec()),
            ),
        ]))?,
        ClaimApprovalStatus::Approved,
    ))
}

impl Vault {
    /// Every live hook binding, enabled or not. The hook runner reads these.
    pub fn pack_hook_bindings(&self) -> Result<Vec<(EntityId, PackHookBinding)>> {
        let txn = self.store.env.read_txn()?;
        bindings_in_txn(&self.store, &txn)
    }

    /// The body a binding names, read from its exact pack source and checked
    /// against the binding's hash.
    pub fn pack_hook_body(&self, binding: &PackHookBinding) -> Result<Vec<u8>> {
        let source = self
            .get_pack_source(&binding.source)?
            .ok_or_else(|| invalid("pack source missing"))?;
        let path = format!("{HOOK_DIR}{}/{HOOK_BODY}", binding.hook);
        let body = source
            .files()
            .iter()
            .find(|file| file.path == path)
            .ok_or_else(|| invalid("hook body missing"))?;
        if blake3::hash(&body.content).to_hex().as_str() != binding.body_hash {
            return Err(invalid("hook body does not match its binding"));
        }
        Ok(body.content.clone())
    }

    /// Owner consent binds an installed pack's hooks. A hub install lands
    /// the bytes; content never installs a hook by itself (ARCH-0080 §8).
    pub fn bind_pack_hooks(&self, owner: &AuthenticatedOwner, pack: &str) -> Result<Vec<EntityId>> {
        let bound = self.with_write_txn_grouped(|txn| {
            let receipt = self
                .installed_pack_in_txn(txn, pack)?
                .ok_or_else(|| invalid("pack is not installed"))?;
            let source_id = EntityId::from_hex(&receipt.source_id)?;
            let source = self
                .pack_source_in_txn(txn, &source_id)?
                .ok_or_else(|| invalid("pack source missing"))?;
            self.bind_pack_hooks_in_txn(txn, owner, source_id, &source)
        })?;
        self.verb_hook_bindings_changed();
        Ok(bound)
    }

    /// The owner's dial on one binding. The CODE entity stays.
    pub fn set_pack_hook_enabled(
        &self,
        owner: &AuthenticatedOwner,
        binding: EntityId,
        enabled: bool,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            let owner_id = owner.revalidate_in_txn(self, txn)?;
            let (id, mut row) = bindings_in_txn(&self.store, txn)?
                .into_iter()
                .find(|(id, _)| *id == binding)
                .ok_or(Error::EntityNotFound)?;
            row.enabled = enabled;
            let envelope = owner_envelope(owner, owner_id, &row.pack, &row.source)?;
            let at = crate::unix_seconds_now();
            self.batch_in()
                .claim_candidate(
                    &id,
                    binding_candidate(&row)?,
                    &envelope,
                    TimeRange { start: at, end: at },
                    at,
                )
                .apply(txn)
        })?;
        self.verb_hook_bindings_changed();
        Ok(())
    }

    /// Every enabled binding of `pack` stops, each under the owner's
    /// envelope for its own source. The CODE entities stay.
    pub(super) fn disable_pack_hooks_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        pack: &str,
    ) -> Result<()> {
        let owner_id = owner.revalidate_in_txn(self, txn)?;
        let at = crate::unix_seconds_now();
        let occurred = TimeRange { start: at, end: at };
        let mut batch = self.batch_in();
        let mut stopped = false;
        for (id, mut row) in bindings_in_txn(&self.store, txn)? {
            if row.pack != pack || !row.enabled {
                continue;
            }
            row.enabled = false;
            let envelope = owner_envelope(owner, owner_id, &row.pack, &row.source)?;
            batch = batch.claim_candidate(&id, binding_candidate(&row)?, &envelope, occurred, at);
            stopped = true;
        }
        if stopped {
            batch.apply(txn)?;
        }
        Ok(())
    }

    /// Each hook of `source` becomes a CODE entity, derived from the pack
    /// source, plus its owner-approved binding. A binding the source no
    /// longer carries, or whose body moved, stops. The caller tells the verb
    /// hooks once its write commits, so no reader caches the list before it.
    pub(super) fn bind_pack_hooks_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        source_id: EntityId,
        source: &PackSource,
    ) -> Result<Vec<EntityId>> {
        let owner_id = owner.revalidate_in_txn(self, txn)?;
        let pack = source.manifest.name.as_str();
        let content_hash = source.content_hash().to_hex();
        let envelope = owner_envelope(owner, owner_id, pack, &source_id)?;
        let at = crate::unix_seconds_now();
        let occurred = TimeRange { start: at, end: at };
        let prior = bindings_in_txn(&self.store, txn)?;
        let mut batch = self.batch_in();
        let mut bound = Vec::new();
        for hook in source.hooks() {
            let material: [&[u8]; 3] = [pack.as_bytes(), hook.name.as_bytes(), &hook.body_hash];
            let code =
                crate::codebase::entity_id_from_hash_material(b"oneiron.pack-hook.v1", &material)?;
            let id = crate::codebase::entity_id_from_hash_material(
                b"oneiron.pack-hook-binding.v1",
                &material,
            )?;
            if crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &code)?.is_none() {
                let body = CodeArtifactBody::new(
                    hook.intent
                        .clone()
                        .unwrap_or_else(|| format!("Hook {} of pack {pack}.", hook.name)),
                    hook.body_hash,
                    format!("pack:{pack}@{content_hash}/hooks/{}", hook.name),
                )
                .with_class(CodeArtifactClass::Artifact);
                batch = batch
                    .put(
                        &code,
                        crate::registry::ENTITY_TYPE_CODE_ARTIFACT,
                        occurred,
                        at,
                        &encode_code_artifact_body(&body)?,
                    )
                    .edge(&code, EdgeKind::DerivedFrom, &source_id, 1.0);
            }
            // The owner's dial from the claim at this id, malformed or not;
            // only a fresh id starts on.
            let enabled = prior_enabled_in_txn(&self.store, txn, &id)?.unwrap_or(true);
            let row = PackHookBinding {
                version: HOOK_BINDING_VERSION,
                code,
                owner: owner_id,
                source: source_id,
                pack: pack.to_owned(),
                hook: hook.name.clone(),
                hook_version: hook.version.clone(),
                body_hash: blake3::Hash::from_bytes(hook.body_hash)
                    .to_hex()
                    .to_string(),
                selector: hook.selector.clone(),
                enabled,
            };
            batch = batch.claim_candidate(&id, binding_candidate(&row)?, &envelope, occurred, at);
            // The body passed under this engine's contract (ARCH-0080 §8 regen).
            crate::runtime_hooks::note_bound_hook_in_txn(
                self,
                txn,
                id,
                &row.body_hash,
                hook.intent.as_deref(),
            )?;
            bound.push(id);
        }
        for (id, mut row) in prior {
            if row.pack == pack && row.enabled && !bound.contains(&id) {
                row.enabled = false;
                batch =
                    batch.claim_candidate(&id, binding_candidate(&row)?, &envelope, occurred, at);
            }
        }
        batch.apply(txn)?;
        Ok(bound)
    }
}
