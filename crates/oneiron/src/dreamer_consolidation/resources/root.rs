//! A typed root is a resource origin, not a conversation partition.
use super::*;
use crate::dreamer_consolidation::branch::{BranchAxes, QueuedBranch};
use crate::dreamer_consolidation::root_evidence::bridge::{RootBinding, RootPayload};
use crate::ports::EdgeStoreRead;

pub(super) enum ResourceOrigin {
    Branch(QueuedBranch),
    Root(RootBinding),
}

impl ResourceOrigin {
    pub(super) fn axes(&self) -> BranchAxes {
        match self {
            Self::Branch(branch) => branch.axes(),
            Self::Root(binding) => BranchAxes {
                world_ref: binding.key().world,
                facet_ref: binding.key().facet,
            },
        }
    }

    pub(super) fn root_binding(&self) -> Option<&RootBinding> {
        match self {
            Self::Branch(_) => None,
            Self::Root(binding) => Some(binding),
        }
    }

    pub(super) fn gap_projection(&self, scope: &Scope) -> ScopeResource {
        match self {
            Self::Branch(branch) => super::super::gap::branch_gap_projection(branch, scope),
            Self::Root(binding) => ScopeResource::Projection {
                key: format!(
                    "dreamer:gap-branch:v1:root:{}:",
                    bytes_to_hex_lower(&binding.identity()),
                ),
            },
        }
    }
}

impl<'a> BranchResources<'a> {
    pub(in crate::dreamer_consolidation) fn root_bucket(
        &self,
    ) -> Result<&super::super::ConsolidationBucketKey> {
        self.origin
            .root_binding()
            .map(RootBinding::key)
            .ok_or_else(|| invalid_consolidation("resources have no evidence root"))
    }

    /// Admit every citation of the queued children under the actual Dreamer.
    /// CLAIM-only roots have no TURNs, parents or extraction transcript.
    pub(in crate::dreamer_consolidation) fn open_root_pinned(
        vault: &'a Vault,
        actor: WriteActor,
        payload: &RootPayload,
        attempt: AttemptId,
        requested: Option<&Scope>,
    ) -> Result<Self> {
        let actor_key = ScopedReadActorKey::with_actor_class(
            actor.entity_ref().to_hex(),
            actor.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| invalid_consolidation("invalid consolidation read actor"))?;
        let read = vault.scoped_read(actor_key);
        let (binding, turns) = {
            let txn = vault.store.env.read_txn()?;
            let binding = RootBinding::load(vault, &read, &txn, payload, actor, attempt)?;
            let mut turns = BTreeMap::new();
            for pin in binding.pins() {
                let reference = super::super::root_evidence::reference(&pin.reference)?;
                if reference.claim_id.is_some() {
                    continue;
                }
                let parents = vault
                    .store
                    .port_edge_peers(
                        &txn,
                        &reference.source_id,
                        crate::ports::EdgeDirection::Out,
                        crate::EdgeKind::ChildOf,
                    )?
                    .collect::<Result<Vec<_>>>()?;
                let [parent] = parents.as_slice() else {
                    return Err(invalid_consolidation("root TURN needs its conversation"));
                };
                turns.insert(reference.source_id, *parent);
            }
            (binding, turns)
        };
        let key = binding.key();
        let buckets = BTreeSet::from([ScopeResource::Bucket {
            key: format!("root:{}", bytes_to_hex_lower(&binding.identity())),
        }]);
        let mut ids = BTreeSet::new();
        for pin in binding.pins() {
            ids.insert(EntityId::from_hex(&pin.reference.source_id)?);
        }
        ids.extend(turns.values().copied());
        let ids: Vec<_> = ids.into_iter().collect();
        let live_ids: Vec<_> = ids
            .iter()
            .filter(|id| !binding.has_closed(id))
            .copied()
            .collect();
        let ScopedReadResult {
            value: (rows, texts),
            mut receipt,
        } = super::super::turn_text::read_sources(&read, &live_ids)?;
        let mut by_id: BTreeMap<_, _> = live_ids.into_iter().zip(rows).collect();
        for id in &ids {
            if let Some(recovered) = binding.read_recovered(vault, &read, *id)? {
                receipt.restrict_with(&recovered.receipt);
                by_id.insert(*id, Some(recovered.value));
            }
        }
        let rows: Vec<_> = ids.iter().map(|id| by_id.remove(id).flatten()).collect();
        let mut readable = buckets.clone();
        let mut claim_versions = BTreeSet::new();
        let mut sources = BTreeMap::new();
        let position_txn = vault.store.env.read_txn()?;
        for (id, row) in ids.iter().zip(rows) {
            let (entity_type, learned_at, body) =
                row.ok_or_else(|| invalid_consolidation("root source is not readable"))?;
            let body_hash = *blake3::hash(&body).as_bytes();
            let mut is_claim = false;
            for pin in binding.pins() {
                if EntityId::from_hex(&pin.reference.source_id)? == *id {
                    is_claim |= pin.reference.claim_id.is_some();
                    if pin.source_revision != body_hash {
                        return Err(invalid_consolidation("root source revision changed"));
                    }
                }
            }
            let expected = if is_claim {
                entity_type == ENTITY_TYPE_CLAIM
            } else if turns.contains_key(id) {
                entity_type == ENTITY_TYPE_TURN
            } else {
                matches!(entity_type, ENTITY_TYPE_SESSION | ENTITY_TYPE_CONVERSATION)
            };
            if !expected {
                return Err(invalid_consolidation("invalid root source type"));
            }
            let resource = document_version(*id, &body);
            readable.insert(resource.clone());
            if is_claim {
                // Only admit_priors may create the paired CLAIM SourcePin/PriorHead.
                claim_versions.insert(resource);
                continue;
            }
            let project = stored_project(&vault.store, &position_txn, *id, entity_type, &body)?;
            sources.insert(
                *id,
                SourcePin {
                    resource,
                    entity_type,
                    learned_at,
                    project,
                    body_hash,
                    #[cfg(test)]
                    trust_class: None,
                },
            );
        }
        drop(position_txn);
        readable.extend(
            texts
                .values()
                .flat_map(TurnText::versions)
                .map(|(_, v)| v.clone()),
        );
        let output = ScopeResource::Projection {
            key: format!(
                "dreamer:root-consolidation:v1:{}",
                bytes_to_hex_lower(&binding.identity())
            ),
        };
        let signals = ScopeResource::Projection {
            key: format!(
                "dreamer:root-signals:v1:{}",
                bytes_to_hex_lower(&binding.identity())
            ),
        };
        readable.insert(signals.clone());
        let mut scope = Scope {
            world: key.world,
            facet: key.facet,
            relationship: key.rel.clone(),
            project: Some(key.project),
            readable,
            writable: claim_versions,
        };
        scope.writable.insert(output.clone());
        if let Some(bound) = requested {
            if bound.world != key.world
                || bound.facet != key.facet
                || bound.project.is_some_and(|project| project != key.project)
                || bound.relationship.as_ref().is_some_and(|relationships| {
                    !key.rel
                        .as_ref()
                        .is_some_and(|rel| rel.is_subset(relationships))
                })
            {
                return Err(invalid_consolidation("root crossed the caller scope"));
            }
            // Exact rights remain the caller's, while the root narrows the axes.
            scope.readable = bound.readable.clone();
            scope.writable = bound.writable.clone();
        }
        let origin = ResourceOrigin::Root(binding);
        if requested.is_none() {
            scope.writable.insert(origin.gap_projection(&scope));
        }
        let mut resources = Self {
            actor,
            read,
            prepared_wake: None,
            origin,
            sources,
            turns,
            texts,
            buckets,
            output,
            scope,
            attempt,
            fallback_binding: Cell::new(None),
            signals,
            priors: BTreeMap::new(),
            provisional: BTreeSet::new(),
            known: Default::default(),
            rules: vault.consolidation_key_rules()?,
            read_receipt: std::sync::Mutex::new(receipt),
        };
        resources.check_axes(resources.scope())?;
        resources.require_output(resources.scope())?;
        resources.admit_priors(&BTreeSet::new())?;
        for id in &ids {
            resources.source(resources.scope(), id)?;
        }
        for turn in resources.turns.keys() {
            resources.turn(resources.scope(), turn)?;
        }
        let txn = vault.store.env.read_txn()?;
        resources
            .origin
            .root_binding()
            .expect("root origin")
            .validate_in_txn(vault, &resources.read, &txn)?;
        Ok(resources)
    }
}

impl BranchResources<'_> {
    pub(super) fn root_recovered_source(&self, id: EntityId) -> Result<Option<(u8, u64, Vec<u8>)>> {
        let Some(binding) = self.origin.root_binding() else {
            return Ok(None);
        };
        let Some(row) = binding.read_recovered(self.read.vault(), &self.read, id)? else {
            return Ok(None);
        };
        self.fold_read_receipt(&row.receipt)?;
        Ok(Some(row.value))
    }

    pub(super) fn root_source_closed(&self, id: &EntityId) -> bool {
        self.origin
            .root_binding()
            .is_some_and(|binding| binding.has_closed(id))
    }
}
