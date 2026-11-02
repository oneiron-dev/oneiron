//! A branch's declared sources (FIX 7524): every part's conversation and
//! its queued TURNs, pinned at one revision. A conversation is admitted only
//! as a declared part's parent, and a TURN only through its own part's
//! parent: never because it belongs to some conversation the branch reads.
use super::*;
use crate::dreamer_consolidation::branch::QueuedBranch;
use crate::dreamer_consolidation::neighbourhood::Neighbourhood;
use crate::dreamer_runner::dreamer_extraction_role_admissible;
use crate::edge::EdgeKind;

impl<'a> BranchResources<'a> {
    /// Admit the already queued branch, never a model-selected resource set.
    /// Every part keeps its own bucket; the scope bounds them all.
    pub(in crate::dreamer_consolidation) fn open_branch(
        vault: &'a Vault,
        actor: WriteActor,
        branch: &QueuedBranch,
        attempt: AttemptId,
        requested: Option<&Scope>,
        prepared_wake: Option<&'a PreparedWake>,
        known: Option<&Neighbourhood>,
    ) -> Result<Self> {
        let actor_key = ScopedReadActorKey::with_actor_class(
            actor.entity_ref().to_hex(),
            actor.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| invalid_consolidation("invalid consolidation read actor"))?;
        let read = vault.scoped_read(actor_key);
        let buckets: BTreeSet<_> = branch
            .partition_keys()
            .map(|key| ScopeResource::Bucket {
                key: bytes_to_hex_lower(&key.partition_hash()),
            })
            .collect();
        let turn_ids = branch.turn_ids();
        let parents: BTreeSet<EntityId> = branch.conversations().collect();
        // Real sink boundary over the queued TURN slice. Its key is available
        // before enqueue; the future queue id is not permission a parent can
        // guess. Candidate/vector identities remain bound to the actual attempt.
        let output = branch.output_resource();
        let mut sources = BTreeMap::new();
        let mut readable = buckets.clone();
        // One LMDB read transaction pins all branch sources at one ledger
        // revision: every part's parent, then every TURN. Later reads and the
        // write fence must match these pins.
        let source_ids: Vec<_> = branch
            .conversations()
            .chain(turn_ids.iter().copied())
            .collect();
        let (source_rows, read_receipt, texts): (Vec<_>, _, _) = if let Some(pin) = prepared_wake {
            // The wake's one scoped read supplied these bytes; its receipt
            // travels with the branch.
            let mut read_receipt = read.read_receipt(None, 0)?;
            if let Some(wake_receipt) = pin.read_receipt() {
                read_receipt.restrict_with(wake_receipt);
            }
            (
                source_ids.iter().map(|id| pin.source(id)).collect(),
                read_receipt,
                None,
            )
        } else {
            let ScopedReadResult {
                value: (rows, texts),
                receipt,
            } = crate::dreamer_consolidation::turn_text::read_sources(&read, &source_ids)?;
            (rows, receipt, Some(texts))
        };
        let position_txn = vault.store.env.read_txn()?;
        for (id, row) in source_ids.iter().zip(source_rows) {
            let (entity_type, learned_at, body) =
                row.ok_or_else(|| invalid_consolidation("branch source is not readable"))?;
            let parent = parents.contains(id);
            if (parent && !matches!(entity_type, ENTITY_TYPE_SESSION | ENTITY_TYPE_CONVERSATION))
                || (!parent && entity_type != ENTITY_TYPE_TURN)
            {
                return Err(invalid_consolidation("invalid branch source type"));
            }
            let resource = document_version(*id, &body);
            readable.insert(resource.clone());
            let project = stored_project(&vault.store, &position_txn, *id, entity_type, &body)?;
            #[cfg(test)]
            let trust_class = (entity_type == ENTITY_TYPE_TURN)
                .then(|| {
                    let facts = decode_turn_body(&body);
                    turn_trust_class(
                        dreamer_turn_role(
                            facts.speaker.as_deref(),
                            &vault.config.assistant_display_names,
                        ),
                        facts.imported,
                    )
                })
                .flatten();
            sources.insert(
                *id,
                SourcePin {
                    resource,
                    entity_type,
                    learned_at,
                    project,
                    body_hash: *blake3::hash(&body).as_bytes(),
                    #[cfg(test)]
                    trust_class,
                },
            );
        }
        // One read txn per thread: the admission reads below open their own.
        drop(position_txn);
        let texts = match (texts, prepared_wake) {
            (Some(texts), _) => texts,
            (None, Some(pin)) => pin.turn_texts(&turn_ids)?,
            (None, None) => return Err(invalid_consolidation("branch turn text not read")),
        };
        let messages = texts.values().flat_map(TurnText::versions);
        readable.extend(messages.map(|(_, version)| version.clone()));
        // The queued/caller scope is an actual upper bound supplied by the
        // trusted host. It binds TURNs to relationship/project slices through
        // exact versions: neither axis is a conversation column. A TURN's own
        // project stamp (pinned above) still bounds what it may support.
        let mut granted = Scope {
            world: branch.world_ref,
            facet: branch.facet_ref,
            relationship: requested.and_then(|scope| scope.relationship.clone()),
            project: requested.and_then(|scope| scope.project),
            readable,
            writable: BTreeSet::from([output.clone()]),
        };
        let signals = branch.signals_resource();
        granted.readable.insert(signals.clone());
        granted
            .writable
            .insert(crate::dreamer_consolidation::gap::branch_gap_projection(
                branch, &granted,
            ));
        // An unscoped branch holds the heads its neighbourhood lists as exact
        // priors, read through this actor's scoped read at the wake's pin.
        for (_, version) in known.into_iter().flat_map(Neighbourhood::claim_versions) {
            granted.readable.insert(version.clone());
            granted.writable.insert(version.clone());
        }
        // Never replace explicit missing rights with generated defaults. Extra
        // exact documents are the caller's graph/project slice, not source TURNs.
        // A supplied scope is authority, not a request to infer more authority.
        let scope = requested.cloned().unwrap_or(granted);
        let mut resources = Self {
            actor,
            read,
            prepared_wake,
            branch: branch.clone(),
            sources,
            turns: branch.turn_parts(),
            texts,
            buckets,
            output,
            scope,
            attempt,
            fallback_binding: Cell::new(None),
            signals,
            priors: BTreeMap::new(),
            provisional: BTreeSet::new(),
            known: known.cloned().unwrap_or_default(),
            rules: vault.consolidation_key_rules()?,
            read_receipt: std::sync::Mutex::new(read_receipt),
        };
        resources.check_axes(&resources.scope)?;
        for parent in &parents {
            resources.source(&resources.scope, parent)?;
        }
        // Membership and coordinates are structural admission, not prompt text.
        for turn in &turn_ids {
            resources.turn(&resources.scope, turn)?;
        }
        resources.admit_priors()?;
        Ok(resources)
    }

    /// One queued TURN, read through its own part: exactly one `ChildOf`
    /// parent, that part's conversation, the branch's axes and an
    /// admissible role.
    pub(in crate::dreamer_consolidation) fn turn(
        &self,
        scope: &Scope,
        id: &EntityId,
    ) -> Result<TurnBodyFacts> {
        let conversation = *self
            .turns
            .get(id)
            .ok_or_else(|| invalid_consolidation("unlisted branch turn"))?;
        let (_, body) = self.source(scope, id)?;
        let (_, parent_body) = self.source(scope, &conversation)?;
        let mut facts = decode_turn_body(&body);
        let text = self.texts.get(id);
        facts.text = text
            .ok_or_else(|| invalid_consolidation("unlisted branch turn"))?
            .recheck(scope, &self.read, id)?;
        let parent = decode_turn_body(&parent_body);
        // Membership is the TURN's ChildOf edge alone. An edge of another
        // kind may reach a row the Dreamer no longer reads, as a head an
        // earlier branch of the pass closed, which never refuses the turn.
        let edges = self.read.edges_out_of_kind(id, EdgeKind::ChildOf)?;
        self.fold_read_receipt(&edges.receipt)?;
        if edges.receipt.suppressed_count != 0 {
            return Err(invalid_consolidation("branch turn graph is incomplete"));
        }
        let edges = edges
            .value
            .ok_or_else(|| invalid_consolidation("branch turn is not readable"))?;
        let parents: Vec<_> = edges
            .iter()
            .filter(|edge| edge.kind == EdgeKind::ChildOf)
            .collect();
        if parents.len() != 1
            || parents[0].target != conversation
            || facts.world_ref.or(parent.world_ref) != self.branch.world_ref
            || facts.facet_ref.or(parent.facet_ref) != self.branch.facet_ref
            || !dreamer_extraction_role_admissible(dreamer_turn_role(
                facts.speaker.as_deref(),
                &self.read.vault().config.assistant_display_names,
            ))
        {
            return Err(invalid_consolidation("branch turn crossed its partition"));
        }
        Ok(facts)
    }

    /// Whether `scope` reads every part's bucket: the branch reads whole.
    pub(super) fn buckets_readable(&self, scope: &Scope) -> bool {
        self.buckets.iter().all(|bucket| scope.allows_read(bucket))
    }

    /// Whether `id` is a declared part's conversation.
    pub(in crate::dreamer_consolidation) fn is_part_parent(&self, id: &EntityId) -> bool {
        self.branch.conversations().any(|parent| parent == *id)
    }
}
