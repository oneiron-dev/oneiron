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

mod author;
mod bindings;

pub use self::author::{FOREIGN_SKILL_PUBLISHER, HookAuthor};
pub use self::bindings::PackHookBinding;
pub(crate) use self::bindings::is_hook_binding;

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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HookActorClass {
    Human,
    Agent,
    System,
}

/// How a hook's body may spend model time (ARCH-0035 render classes;
/// ARCH-0080 §4 Its shape).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookSelector {
    /// Globs over row names and SelfEffect labels; for a fact hook, over
    /// predicates.
    pub verbs: Vec<String>,
    /// Empty selects every class.
    pub actors: Vec<HookActorClass>,
    /// A world, facet, room or project as `<axis>:<32 hex id>`; a scope
    /// only narrows.
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
    /// token no prior one covers asks consent again (ARCH-0080 §9). A lower
    /// `budget_ms`, or a specific scope where `*` stood, is covered.
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
            tokens.push(format!(
                "{name}/render_class:{}",
                wire(&selector.render_class)
            ));
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
            return Err(invalid(
                "only a post-hook filters served rows, by row globs",
            ));
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
        // A world, facet, room or project id; no other grammar.
        let scope = scalar("scope")?;
        if scope
            .as_deref()
            .is_some_and(|scope| crate::runtime_hooks::HookScope::parse(scope).is_none())
        {
            return Err(invalid(
                "hook scope is world, facet, room or project:<32 lowercase hex id>",
            ));
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
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'-' | b'*' | b':')
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
    /// ARCH-0080 §9's update rule, once `receipt` installed `source` over a
    /// pack whose hooks are bound: a same-capability update rebinds them,
    /// each hook keeping its owner's dial; a wider one leaves them on the old
    /// source, and the receipt's `widening_hooks` is the ask the owner's
    /// [`Self::bind_pack_hooks`] answers.
    pub(super) fn follow_pack_hook_update_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        receipt: &super::PackInstallReceipt,
        source_id: EntityId,
        source: &PackSource,
    ) -> Result<()> {
        let bound = bindings_in_txn(&self.store, txn)?
            .iter()
            .any(|(_, row)| row.pack == receipt.pack_name && row.source != source_id);
        if bound && receipt.permissions.widening_hooks.is_empty() {
            self.bind_pack_hooks_in_txn(txn, owner, source_id, source)?;
        }
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
        let mut transitions = Vec::new();
        for (id, mut row) in bindings_in_txn(&self.store, txn)? {
            if row.pack != pack || !row.enabled {
                continue;
            }
            let previous = row.clone();
            row.enabled = false;
            transitions.push((id, previous, row.clone()));
            let envelope = owner_envelope(owner, owner_id, &row.pack, &row.source)?;
            batch = batch.claim_candidate(&id, binding_candidate(&row)?, &envelope, occurred, at);
            stopped = true;
        }
        if stopped {
            batch.apply(txn)?;
        }
        for (id, previous, row) in transitions {
            crate::runtime_hooks::sync_binding_cursor_in_txn(self, txn, id, Some(&previous), &row)?;
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
        let receipt = self
            .installed_pack_in_txn(txn, pack)?
            .ok_or_else(|| invalid("pack is not installed"))?;
        let author = self.hook_author_in_txn(txn, &receipt)?;
        let mut batch = self.batch_in();
        // A publisher acts through its own vault-resident person.
        if let HookAuthor::ForeignActor {
            actor, identity, ..
        } = &author
            && !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, actor)?
        {
            let mut body = Vec::new();
            rmpv::encode::write_value(
                &mut body,
                &Value::Map(vec![(
                    Value::from("display_name"),
                    Value::from(identity.as_str()),
                )]),
            )
            .map_err(|_| Error::InvariantViolation("publisher person body encoding failed"))?;
            batch = batch.put(
                actor,
                crate::registry::ENTITY_TYPE_PERSON,
                occurred,
                at,
                &body,
            );
        }
        let mut bound = Vec::new();
        let mut transitions = Vec::new();
        for hook in source.hooks() {
            // A moved body keeps its hook's dial: on while any of its
            // bindings runs, off once the owner stopped every one.
            let (id, mut row) =
                PackHookBinding::for_hook(pack, source_id, owner_id, author.clone(), hook, true)?;
            row.enabled = match prior.iter().find(|(prior_id, _)| *prior_id == id) {
                Some((_, kept)) => kept.enabled,
                // A claim at this id the reader skipped as malformed keeps
                // the owner's dial.
                None => match prior_enabled_in_txn(&self.store, txn, &id)? {
                    Some(enabled) => enabled,
                    None => {
                        let mut same = prior
                            .iter()
                            .filter(|(_, kept)| kept.pack == pack && kept.hook == hook.name)
                            .peekable();
                        same.peek().is_none() || same.any(|(_, kept)| kept.enabled)
                    }
                },
            };
            let previous = prior
                .iter()
                .find(|(prior_id, _)| *prior_id == id)
                .map(|(_, kept)| kept.clone());
            transitions.push((id, previous, row.clone()));
            let code = row.code;
            if !crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &code)? {
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
                let previous = row.clone();
                row.enabled = false;
                transitions.push((id, Some(previous), row.clone()));
                batch =
                    batch.claim_candidate(&id, binding_candidate(&row)?, &envelope, occurred, at);
            }
        }
        batch.apply(txn)?;
        for (id, previous, row) in transitions {
            crate::runtime_hooks::sync_binding_cursor_in_txn(
                self,
                txn,
                id,
                previous.as_ref(),
                &row,
            )?;
        }
        Ok(bound)
    }
}
