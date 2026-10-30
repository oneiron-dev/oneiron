//! FIX 1873 (ARCH-0072 slate, ARCH-0080 §6): a hub hook's author holds one
//! owner-minted Grant, bounded to what its hooks' manifests declare.
//!
//! A hub pack's hooks run as its publisher's vault-resident PERSON, acting as
//! an agent ([`HookAuthor::ForeignActor`]). The owner's act on those hooks
//! (his bind, the update rule's rebind in a hub install's own writer, his
//! dial, a removal) settles that author's slate in the same writer: one
//! owner agent Grant, the FEDERATION_GRANT row every Grant reader reads, whose
//! explicit verbs are `read` when one of its running hooks declares a read,
//! plus one `hook.<outcome>` verb per outcome kind its hooks declare that
//! lands a change, and whose worlds and facets are those its reading hooks
//! name. A Grant whose reach is unchanged stays; a changed reach revokes it
//! and mints the new one; no running hook revokes it. The author then reads
//! under it as an agent reads under its own Grant (FIX 7462), each hook
//! further held to the predicates it declares (`HookGrant::author_ceiling`),
//! and its queued outcomes land only while it stands for their verb
//! ([`Vault::hook_author_write_refusal`]). The owner reviews and revokes it in
//! `vault.consent.registry` like any agent Grant.

use std::collections::{BTreeMap, BTreeSet};

use crate::batch::{BatchOp, apply_ops};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::{
    FederationGrant, FederationGrantKind, FederationGrantPreset, FederationGrantRole,
    FederationGrantScope, Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling,
    encode_federation_grant_body, own_device_residence_scope,
};
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::runtime_hooks::HookScope;
use crate::skill_hub::pack_catalog::{
    HookAuthor, HookOutcomeKind, HookPhase, HookSelector, PackHookBinding,
};
use crate::{TimeRange, Vault};

/// The verb a hook author's Grant lists when one of its hooks reads.
pub(crate) const HOOK_READ_VERB: &str = "read";

/// The highest band a hook author's Grant reads (CALLS `FIX 1873 hook author
/// sensitivity`): public, as a foreign actor's slate row starts (ARCH-0072
/// mcp:slate-handles). The owner widens one hook by setting its grant.
pub(crate) const HOOK_AUTHOR_SENSITIVITY: SensitivityCeiling =
    SensitivityCeiling::AtMost(Sensitivity::Public);

/// The code a queued outcome's refusal leads with when its author's Grant
/// does not list the outcome's verb.
pub(crate) const HOOK_AUTHOR_GRANT_MISSING: &str = "hook_author_grant_missing: the hub hook's \
     author holds no Grant that lists this outcome's verb";

/// What records the owner's will for a hook author's Grant (CALLS `FIX 1873
/// hook author grant act`).
#[derive(Debug, Clone, Copy)]
enum HookAuthorGrantAct {
    /// The owner-stamped act on the hooks the Grant is settled in, in the
    /// same writer: no second signed agent Grant act, so an install that
    /// carries no owner act still binds its hooks as before.
    TheHookAct,
}

const HOOK_AUTHOR_GRANT_ACT: HookAuthorGrantAct = HookAuthorGrantAct::TheHookAct;

/// The verb a hook author's Grant lists for an outcome of `kind`, `None` for
/// a kind that changes nothing.
#[must_use]
pub(crate) const fn hook_outcome_verb(kind: HookOutcomeKind) -> Option<&'static str> {
    match kind {
        HookOutcomeKind::Continue | HookOutcomeKind::Nothing => None,
        HookOutcomeKind::Rewrite => Some("hook.rewrite"),
        HookOutcomeKind::Skip => Some("hook.skip"),
        HookOutcomeKind::Ask => Some("hook.ask"),
        HookOutcomeKind::AddBlock => Some("hook.add_block"),
        HookOutcomeKind::Annotate => Some("hook.annotate"),
        HookOutcomeKind::Redact => Some("hook.redact"),
        HookOutcomeKind::Propose => Some("hook.propose"),
        HookOutcomeKind::Enqueue => Some("hook.enqueue"),
        HookOutcomeKind::Effect => Some("hook.effect"),
    }
}

/// The predicate globs a hook's manifest declares it reads: a fact hook's
/// selector entries, a post-hook's served rows, each entry's predicate glob.
/// `None` for a hook that declares no read (a pre-hook, or a post-hook with
/// no served filter); an empty list where one entry reads every predicate.
#[must_use]
pub(crate) fn hook_declared_reads(selector: &HookSelector) -> Option<Vec<String>> {
    let entries = match selector.phase {
        HookPhase::Fact => &selector.verbs,
        HookPhase::Post => &selector.served,
        HookPhase::Pre => return None,
    };
    if entries.is_empty() {
        return None;
    }
    let globs: BTreeSet<&str> = entries
        .iter()
        .map(|entry| {
            entry
                .split_once(':')
                .map_or(entry.as_str(), |(_, glob)| glob)
        })
        .collect();
    if globs.contains("*") {
        return Some(Vec::new());
    }
    Some(globs.into_iter().map(str::to_owned).collect())
}

/// The Scope one author's Grant holds for its running hooks' `selectors`:
/// `read` and the worlds and facets its reading hooks name (every one where
/// a reading hook names none), and the verb of each outcome kind they declare.
/// `None` when they declare nothing to grant.
fn hook_author_reach<'a>(selectors: impl IntoIterator<Item = &'a HookSelector>) -> Option<Scope> {
    let mut verbs = BTreeSet::new();
    let mut reads = false;
    let mut worlds = Some(BTreeSet::new());
    let mut facets = Some(BTreeSet::new());
    for selector in selectors {
        verbs.extend(
            selector
                .outcomes
                .iter()
                .filter_map(|kind| hook_outcome_verb(*kind))
                .map(str::to_owned),
        );
        if hook_declared_reads(selector).is_none() {
            continue;
        }
        reads = true;
        match selector.scope.as_deref().and_then(HookScope::parse) {
            Some(HookScope::World(world)) => {
                if let Some(worlds) = worlds.as_mut() {
                    worlds.insert(ScopeId(world));
                }
                facets = None;
            }
            Some(HookScope::Facet(facet)) => {
                if let Some(facets) = facets.as_mut() {
                    facets.insert(ScopeId(facet));
                }
                worlds = None;
            }
            Some(HookScope::Room(_) | HookScope::Project(_)) | None => {
                worlds = None;
                facets = None;
            }
        }
    }
    if reads {
        verbs.insert(HOOK_READ_VERB.to_owned());
    }
    if verbs.is_empty() {
        return None;
    }
    let read_axis = |held: Option<BTreeSet<ScopeId>>| match (reads, held) {
        (false, _) => ScopeAxis::Bottom,
        (true, Some(held)) => ScopeAxis::Some(held),
        (true, None) => ScopeAxis::All,
    };
    Some(Scope {
        worlds: read_axis(worlds),
        facets: read_axis(facets),
        bands: ScopeAxis::All,
        audience: ScopeAxis::All,
        verbs: ScopeAxis::Some(verbs),
        sensitivity: HOOK_AUTHOR_SENSITIVITY,
    })
}

impl Vault {
    /// The owner's act on hub hooks settles each foreign author's one Grant
    /// in the caller's writer `txn`, from `bindings`, every hook binding as
    /// that writer holds it: an author whose enabled hooks still declare the
    /// reach its live Grant holds keeps it; one whose reach changed has it
    /// revoked and the new one minted; one with no enabled hook left, or
    /// whose hooks grant nothing, has it revoked. `owner` is revalidated as
    /// the vault's live owner, who gives each Grant.
    pub(crate) fn settle_hook_author_grants_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        bindings: &[(EntityId, PackHookBinding)],
    ) -> Result<()> {
        let mut authors = BTreeMap::<EntityId, Vec<&HookSelector>>::new();
        for (_, binding) in bindings {
            if let HookAuthor::ForeignActor { actor, .. } = &binding.author {
                let running = authors.entry(*actor).or_default();
                if binding.enabled {
                    running.push(&binding.selector);
                }
            }
        }
        if authors.is_empty() {
            return Ok(());
        }
        let owner_id = owner.revalidate_in_txn(self, txn)?;
        let held = self.agent_grants_in_txn(txn)?;
        for (author, running) in authors {
            let reach = hook_author_reach(running);
            let mut kept = false;
            for standing in held
                .iter()
                .filter(|standing| standing.grant.member_ref == author)
            {
                let same = reach.as_ref() == Some(&standing.grant.authority_scope)
                    && standing.delegated_by == owner_id
                    && standing.grant.expires_at.is_none();
                if same && !kept {
                    kept = true;
                    continue;
                }
                self.revoke_hook_author_grant_in_txn(txn, standing.id)?;
            }
            if let (Some(reach), false) = (reach, kept) {
                self.mint_hook_author_grant_in_txn(txn, owner_id, author, reach)?;
            }
        }
        Ok(())
    }

    /// Why a hub hook's author may not land an outcome of `kind` now, or
    /// `None` when it may: the outcome's verb ([`hook_outcome_verb`]) must
    /// be one its own live Grant lists, by the rule every agent's work in
    /// its name stands by ([`super::principal_standing_in_txn`]). An owner's
    /// or a resident agent's hook, and a kind that changes nothing, are not
    /// held here.
    pub(crate) fn hook_author_write_refusal(
        &self,
        binding: &PackHookBinding,
        kind: HookOutcomeKind,
    ) -> Result<Option<String>> {
        let HookAuthor::ForeignActor { actor, .. } = &binding.author else {
            return Ok(None);
        };
        let Some(verb) = hook_outcome_verb(kind) else {
            return Ok(None);
        };
        let txn = self.store.env.read_txn()?;
        Ok(
            match super::principal_standing_in_txn(self, &txn, *actor, EdgeActorClass::Agent, verb)?
            {
                Some(_) => None,
                None => Some(format!("{HOOK_AUTHOR_GRANT_MISSING} ({verb})")),
            },
        )
    }

    /// Puts `author`'s Grant of `reach`, given by `owner`, in `txn`: an
    /// owner agent Grant with no expiry, under the vault's recorded scope on
    /// a shared vault and the home's residence scope on a personal one, as
    /// the agent Grant door puts its own.
    fn mint_hook_author_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: EntityId,
        author: EntityId,
        reach: Scope,
    ) -> Result<()> {
        match HOOK_AUTHOR_GRANT_ACT {
            // His act on the hooks lands in this writer; no second act is
            // signed for the Grant it settles.
            HookAuthorGrantAct::TheHookAct => {}
        }
        let scope = self
            .shared_vault_creation_in_txn(txn)?
            .map_or_else(own_device_residence_scope, |shared| {
                FederationGrantScope::vault(shared.vault_id)
            });
        let grant = FederationGrant {
            authority_scope: reach,
            scope,
            member_ref: author,
            role: FederationGrantRole::Delegate,
            preset: FederationGrantPreset::Delegate,
            expires_at: None,
            delegated_by: Some(owner),
            guest: None,
            owner_agent: true,
            repo_bounds: None,
            kind: FederationGrantKind::Access,
            git_push_bounds: None,
        };
        let data = encode_federation_grant_body(&grant)?;
        let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
        self.apply_hook_author_grant_op_in_txn(
            txn,
            BatchOp::Put {
                id: EntityId::now(),
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                occurred: TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            },
        )
    }

    /// Revokes the hook author's Grant `grant` in `txn`: its withdrawal stays
    /// known here and reaches its peers, and its row is deleted, as the
    /// agent Grant door revokes one.
    fn revoke_hook_author_grant_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        grant: EntityId,
    ) -> Result<()> {
        super::withdraw_grant_row_in_txn(&self.store, txn, grant)?;
        self.apply_hook_author_grant_op_in_txn(txn, BatchOp::Delete { id: grant })
    }

    fn apply_hook_author_grant_op_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        op: BatchOp,
    ) -> Result<()> {
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![op],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }
}
