//! Pack hook binding writes: the owner's bind of an installed pack's hooks,
//! the update rule's rebind and the stop of a removed pack's bindings.
//! Entry: `Vault::bind_pack_hooks_in_txn`. Defines its own items; the binding
//! scan and row codecs stay in `hooks`.

use super::*;

/// Who binds a pack's hooks, and whose stamp the binding claims carry.
#[derive(Clone, Copy)]
pub(in crate::skill_hub::pack_catalog) enum HookBinder<'a> {
    /// The owner's consent: each hook binds as the pack's author, and a
    /// binding an agent stamped stays the agent's.
    Owner(&'a AuthenticatedOwner),
    /// A resident agent writing the `local` pack (ARCH-0080 §7): each hook
    /// whose body it wrote binds as its own, in a claim stamped with the
    /// agent; a binding another author stands on is left as it is.
    Agent(WriteActor),
}

impl HookBinder<'_> {
    /// Whether this binder writes `row`: the owner every binding, an agent
    /// only its own.
    fn writes(self, row: &PackHookBinding) -> bool {
        match self {
            Self::Owner(_) => true,
            Self::Agent(agent) => matches!(
                &row.author,
                HookAuthor::Agent { agent: author } if *author == agent.entity_ref()
            ),
        }
    }
}

/// The stamp of a binding claim an agent writes: the agent itself, as
/// Generated content, placed by the gate at the agent's own ceiling.
fn agent_envelope(agent: WriteActor, pack: &str, source: &EntityId) -> Result<WriteEnvelope> {
    Ok(WriteEnvelope::new(
        agent,
        ClaimSource::Generated,
        WriteProvenance::new(Value::Map(vec![
            (Value::from("surface"), Value::from("pack.hooks")),
            (Value::from("pack"), Value::from(pack)),
            (
                Value::from("source"),
                Value::Binary(source.as_bytes().to_vec()),
            ),
        ]))?,
        ClaimApprovalStatus::Auto,
    ))
}

impl Vault {
    /// ARCH-0080 §9's update rule, once `receipt` installed `source` over a
    /// pack whose hooks are bound: a same-capability update rebinds them,
    /// each hook keeping its owner's dial; a wider one leaves them on the old
    /// source, and the receipt's `widening_hooks` is the ask the owner's
    /// [`Self::bind_pack_hooks`] answers.
    pub(in crate::skill_hub::pack_catalog) fn follow_pack_hook_update_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        receipt: &super::super::PackInstallReceipt,
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
    pub(in crate::skill_hub::pack_catalog) fn disable_pack_hooks_in_txn(
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
    /// longer carries, or whose body moved, stops; a moved body's new binding
    /// keeps its hook's dial and the owner's grant. The caller tells the verb
    /// hooks once its write commits, so no reader caches the list before it.
    pub(in crate::skill_hub::pack_catalog) fn bind_pack_hooks_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        source_id: EntityId,
        source: &PackSource,
    ) -> Result<Vec<EntityId>> {
        self.bind_hooks_in_txn(txn, HookBinder::Owner(owner), source_id, source)
    }

    /// [`Self::bind_pack_hooks_in_txn`] for `binder`. An agent binds only in
    /// the `local` pack, as a live writer, and its claims name the vault
    /// owner whose ask it carries; it stops only bindings of its own. Only
    /// the owner marks a hook blocking (ARCH-0080 §10), so an agent's own
    /// binding is not blocking; a hook that asks wider than the agent's
    /// ceiling also records the owner's proposal
    /// ([`Self::approve_pack_hook_proposal`]), and a binding the owner
    /// approved as asked stays standing. The owner's bind of a hook approves
    /// an open proposal that asked exactly that.
    pub(in crate::skill_hub::pack_catalog) fn bind_hooks_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        binder: HookBinder<'_>,
        source_id: EntityId,
        source: &PackSource,
    ) -> Result<Vec<EntityId>> {
        let pack = source.manifest.name.as_str();
        let (owner_id, envelope) = match binder {
            HookBinder::Owner(owner) => {
                let owner_id = owner.revalidate_in_txn(self, txn)?;
                (owner_id, owner_envelope(owner, owner_id, pack, &source_id)?)
            }
            HookBinder::Agent(agent) => {
                if pack != super::super::LOCAL_PACK_NAME {
                    return Err(invalid("an agent binds hooks in the local pack only"));
                }
                self.verify_write_actor_in_txn(txn, &agent)?;
                let owner_id = crate::policy_model::owners_in_txn(self, txn)?
                    .first()
                    .copied()
                    .ok_or_else(|| invalid("the vault has no live owner"))?;
                (owner_id, agent_envelope(agent, pack, &source_id)?)
            }
        };
        let content_hash = source.content_hash().to_hex();
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
        let mut grants = Vec::new();
        for hook in source.hooks() {
            let (id, mut row) =
                PackHookBinding::for_hook(pack, source_id, owner_id, author.clone(), hook, true)?;
            let standing = prior
                .iter()
                .find(|(prior_id, _)| *prior_id == id)
                .map(|(_, kept)| kept);
            // An agent leaves another author's binding as it stands, and a
            // binding an agent stamped stays the agent's on the owner's put.
            match (binder, standing) {
                (HookBinder::Agent(_), Some(kept)) if !binder.writes(kept) => continue,
                // The owner bound this hook as the agent asked: the agent's
                // put leaves the owner's binding standing.
                (HookBinder::Agent(_), Some(_))
                    if self.hook_proposal_approved_in_txn(txn, &id, &hook.selector)? =>
                {
                    bound.push(id);
                    continue;
                }
                (HookBinder::Agent(agent), _) => {
                    row.author = HookAuthor::Agent {
                        agent: agent.entity_ref(),
                    };
                    row.selector.blocking = false;
                    // A wider ask goes to the owner as a proposal (ARCH-0080
                    // §10); the binding runs at the agent's ceiling meanwhile.
                    self.propose_wider_hook_in_txn(txn, id, &row, &hook.selector, at)?;
                }
                (HookBinder::Owner(_), Some(kept))
                    if matches!(kept.author, HookAuthor::Agent { .. }) =>
                {
                    row.author = kept.author.clone();
                }
                (HookBinder::Owner(_), _) => {}
            }
            if let HookBinder::Owner(_) = binder {
                self.settle_hook_proposal_in_txn(txn, id, &row.selector, owner_id, at)?;
            }
            // A moved body keeps its hook's dial: on while any of its
            // bindings runs, off once the owner stopped every one.
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
            if previous.is_none() {
                // A moved body keeps the owner's grant on its hook too (FIX
                // 10123): the same author's, a running binding's first.
                let mut from: Vec<_> = prior
                    .iter()
                    .filter(|(prior_id, kept)| {
                        *prior_id != id
                            && kept.pack == pack
                            && kept.hook == hook.name
                            && kept.author_id() == row.author_id()
                            && kept.author_class() == row.author_class()
                    })
                    .collect();
                from.sort_by_key(|(_, kept)| !kept.enabled);
                let from: Vec<EntityId> = from.into_iter().map(|(prior_id, _)| *prior_id).collect();
                grants.push((id, from));
            }
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
            if row.pack == pack && row.enabled && !bound.contains(&id) && binder.writes(&row) {
                let previous = row.clone();
                row.enabled = false;
                transitions.push((id, Some(previous), row.clone()));
                batch =
                    batch.claim_candidate(&id, binding_candidate(&row)?, &envelope, occurred, at);
                if let HookBinder::Agent(_) = binder {
                    self.withdraw_hook_proposal_in_txn(txn, id, at)?;
                }
            }
        }
        batch.apply(txn)?;
        for (id, from) in grants {
            crate::runtime_hooks::carry_hook_grant_in_txn(self, txn, &from, id)?;
        }
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
