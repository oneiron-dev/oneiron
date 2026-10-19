//! Credential-bound admission; every write rechecks its inputs in its writer.
use super::*;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::consent::AuthenticatedOwner;
use crate::edit_roundtrip::deck_create::{
    DeckCreateError, DeckCreateOutcome, DeckCreateRequest, DirectionOutcome,
};
use crate::memory::{Memory, MemoryError, MemoryResult, resolve_entity_ref};
use crate::{EntityId, WriteActor};
use oneiron_docedit::design_plan::Brief;
use oneiron_docedit::emit::Names;

fn creation_error(error: DeckCreateError) -> MemoryError {
    match error {
        DeckCreateError::Vault(error) => error.into(),
        other => MemoryError::bad_request(other.to_string()),
    }
}

fn outline_bytes(markdown: &str) -> MemoryResult<Vec<u8>> {
    let text = markdown
        .split_once("```json")
        .and_then(|(_, rest)| rest.split_once("```"))
        .map_or(markdown.trim(), |(block, _)| block.trim());
    Brief::parse(text.as_bytes()).map_err(|error| MemoryError::bad_request(error.to_string()))?;
    Ok(text.as_bytes().to_vec())
}

fn outline_sources(bytes: &[u8]) -> MemoryResult<Vec<EntityId>> {
    let brief = Brief::parse(bytes).map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let mut sources = Vec::new();
    for block in brief.pages.iter().flat_map(|page| &page.blocks) {
        if let oneiron_docedit::design_plan::BlockContent::Claim { evidence, .. } = &block.content {
            for pin in evidence {
                sources.push(EntityId::from_hex(&pin.document)?);
                if let Some(claim) = &pin.claim {
                    sources.push(EntityId::from_hex(claim)?);
                }
            }
        }
    }
    Ok(sources)
}

fn require_sources(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
) -> MemoryResult<()> {
    if lane
        .get_entities_parts_in_txn(txn, sources)?
        .iter()
        .any(Option::is_none)
    {
        return Err(MemoryError::not_found(
            "deck input does not resolve under this credential",
        ));
    }
    Ok(())
}

impl Memory<'_> {
    /// A typed outline is a brief NOTE, authored through the existing NOTE write gate.
    pub fn artifacts_propose_outline(
        &self,
        input: &DeckOutlineProposeRequest,
    ) -> MemoryResult<DeckOutlineView> {
        let bytes = serde_json::to_vec(&input.outline)
            .map_err(|_| MemoryError::bad_request("outline encoding"))?;
        let receipt = self.author_deck_outline(&bytes)?;
        self.artifacts_outline(&DeckOutlineRefRequest {
            outline_ref: receipt.id_hex,
        })
    }

    pub fn artifacts_outline(
        &self,
        input: &DeckOutlineRefRequest,
    ) -> MemoryResult<DeckOutlineView> {
        let note = resolve_entity_ref(self.vault(), &input.outline_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let txn = self
            .vault()
            .store
            .env
            .read_txn()
            .map_err(crate::Error::from)?;
        require_sources(&lane, &txn, &[note])?;
        let document = crate::note::deck_outline_document_in_txn(self.vault(), &txn, note)?;
        let bytes = outline_bytes(&document.markdown)?;
        require_sources(&lane, &txn, &outline_sources(&bytes)?)?;
        let kept = self.vault().kept_deck_outline_in_txn(&txn, note)?;
        let freshness = self
            .vault()
            .deck_outline_freshness_in_txn(&txn, note)
            .map_err(creation_error)?;
        let outline = serde_json::from_slice(&bytes)
            .map_err(|_| MemoryError::bad_request("outline wire grammar"))?;
        Ok(DeckOutlineView {
            outline_ref: note.to_hex(),
            frontier: document.frontier,
            outline,
            kept,
            freshness,
        })
    }

    pub fn artifacts_keep_outline(
        &self,
        input: &DeckOutlineSettleRequest,
    ) -> MemoryResult<KeptOutline> {
        self.artifacts_keep_outline_as_owner(
            &self.embedded_owner("vault.artifacts.keep_outline")?,
            input,
        )
    }

    pub fn artifacts_keep_outline_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &DeckOutlineSettleRequest,
    ) -> MemoryResult<KeptOutline> {
        let note = resolve_entity_ref(self.vault(), &input.outline_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        self.with_verified_actor_write_txn(|txn| {
            self.admit_outline_settle(owner, input, note, &lane, txn)?;
            self.vault()
                .keep_deck_outline_in_txn(
                    txn,
                    note,
                    WriteActor::new(self.actor(), self.actor_class()),
                )
                .map_err(creation_error)
        })
    }

    pub fn artifacts_decline_outline(
        &self,
        input: &DeckOutlineSettleRequest,
    ) -> MemoryResult<DeckOutlineDeclined> {
        self.artifacts_decline_outline_as_owner(
            &self.embedded_owner("vault.artifacts.decline_outline")?,
            input,
        )
    }

    pub fn artifacts_decline_outline_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        input: &DeckOutlineSettleRequest,
    ) -> MemoryResult<DeckOutlineDeclined> {
        let note = resolve_entity_ref(self.vault(), &input.outline_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        self.with_verified_actor_write_txn(|txn| {
            self.admit_outline_settle(owner, input, note, &lane, txn)?;
            self.vault().decline_deck_outline_in_txn(txn, note)?;
            Ok(DeckOutlineDeclined {
                outline_ref: note.to_hex(),
                declined: true,
            })
        })
    }

    fn admit_outline_settle(
        &self,
        owner: &AuthenticatedOwner,
        input: &DeckOutlineSettleRequest,
        note: EntityId,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
    ) -> MemoryResult<()> {
        if owner.revalidate_in_txn(self.vault(), txn)? != self.actor() {
            return Err(MemoryError::new(
                crate::memory::MEMORY_CODE_FORBIDDEN,
                "owner proof names another actor",
                &[],
            ));
        }
        require_sources(lane, txn, &[note])?;
        let document = crate::note::deck_outline_document_in_txn(self.vault(), txn, note)?;
        if document.frontier != input.expected_frontier {
            return Err(MemoryError::bad_request(
                "outline changed since it was read",
            ));
        }
        require_sources(
            lane,
            txn,
            &outline_sources(&outline_bytes(&document.markdown)?)?,
        )
    }

    pub fn artifacts_design_deck(&self, input: &DeckDesignRequest) -> MemoryResult<DeckDesignView> {
        let note = resolve_entity_ref(self.vault(), &input.outline_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        self.with_verified_actor_write_txn(|txn| {
            let kept = self.admit_deck_keep(&lane, txn, note, &input.kept)?;
            let refs: Vec<_> = input
                .templates
                .iter()
                .chain(input.assets.values())
                .chain(&input.fonts)
                .copied()
                .collect();
            self.admit_deck_versions(&lane, txn, &refs)?;
            let (spec, plans, decisions) = self
                .vault()
                .design_deck_directions_in_txn(
                    txn,
                    note,
                    &input.templates,
                    &input.assets,
                    &input.fonts,
                )
                .map_err(creation_error)?;
            let outline: DeckOutline = serde_json::from_slice(&kept.bytes)
                .map_err(|_| MemoryError::bad_request("kept outline encoding"))?;
            Ok(DeckDesignView {
                spec,
                plans: plans
                    .iter()
                    .map(|plan| {
                        plan.as_ref()
                            .map(|plan| DeckPlanView::of(plan, &outline.datasets))
                    })
                    .collect(),
                decisions: decisions
                    .iter()
                    .map(|questions| {
                        questions
                            .iter()
                            .map(plan::DeckDesignDecision::from)
                            .collect()
                    })
                    .collect(),
            })
        })
    }

    pub fn artifacts_create_deck(
        &self,
        input: &DeckEmissionRequest,
    ) -> MemoryResult<DeckEmissionOutcome> {
        let note = resolve_entity_ref(self.vault(), &input.outline_ref)?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        self.with_verified_actor_write_txn(|txn| {
            self.admit_deck_keep(&lane, txn, note, &input.kept)?;
            let refs: Vec<_> = std::iter::once(&input.template)
                .chain(input.assets.values())
                .chain(&input.fonts)
                .copied()
                .collect();
            self.admit_deck_versions(&lane, txn, &refs)?;
            if let Some(trigger) = &input.trigger {
                require_sources(&lane, txn, &[trigger.row()])?;
            }
            let spec = self
                .vault()
                .deck_design_spec_in_txn(txn, note)?
                .ok_or_else(|| {
                    MemoryError::bad_request("design the kept outline before creating its deck")
                })?;
            if spec.content_hash != input.kept.content_hash
                || !spec.directions.iter().any(|direction| {
                    direction.template == input.template
                        && matches!(direction.outcome, DirectionOutcome::Plan { .. })
                })
            {
                return Err(MemoryError::bad_request(
                    "template is not a planned direction of this keep",
                ));
            }
            let names = &input.names;
            let result = self
                .vault()
                .create_deck_from_outline_in_txn(
                    txn,
                    &DeckCreateRequest {
                        outline: note,
                        template: input.template,
                        assets: &input.assets,
                        fonts: &input.fonts,
                        names: Names {
                            text: &names.text,
                            table: &names.table,
                            chart: &names.chart,
                            picture: &names.picture,
                            figure: &names.figure,
                            sheet: &names.sheet,
                        },
                        name: &input.name,
                        run_ref: &input.run_ref,
                        made_by: Some(self.actor()),
                        trigger: input.trigger.clone(),
                        actor: WriteActor::new(self.actor(), self.actor_class()),
                    },
                )
                .map_err(creation_error)?;
            Ok(match result {
                DeckCreateOutcome::Created(record) => DeckEmissionOutcome::Created { record },
                DeckCreateOutcome::Ask { pages } => DeckEmissionOutcome::Ask { pages },
            })
        })
    }

    fn admit_deck_keep(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        note: EntityId,
        expected: &DeckKeepBinding,
    ) -> MemoryResult<KeptOutline> {
        require_sources(lane, txn, &[note])?;
        let kept = self
            .vault()
            .fresh_outline_in_txn(txn, note)
            .map_err(creation_error)?;
        require_sources(lane, txn, &outline_sources(&kept.bytes)?)?;
        if kept.version != expected.version || kept.content_hash != expected.content_hash {
            return Err(MemoryError::bad_request("keep version or hash changed"));
        }
        Ok(kept)
    }

    fn admit_deck_versions(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        versions: &[ArtifactVersionRef],
    ) -> MemoryResult<()> {
        let ids: Vec<_> = versions.iter().map(|at| at.artifact).collect();
        require_sources(lane, txn, &ids)?;
        // No stored secret bytes may be copied into a new deck by a masked reader.
        for at in versions {
            let metadata = self
                .vault()
                .blob_artifact_version_metadata_in_txn(txn, &at.artifact, at.version)?
                .ok_or_else(|| MemoryError::not_found("deck input version not found"))?;
            require_sources(lane, txn, &[metadata.claim_id])?;
            let bytes = self
                .vault()
                .read_blob_artifact_version_in_txn(txn, &at.artifact, at.version)?
                .ok_or_else(|| MemoryError::not_found("deck input version not found"))?;
            let sight = if lane.actor_key().reads_as_vault_owner() {
                crate::secret_custody::SecretSight::Owner
            } else {
                crate::secret_custody::SecretSight::Masked
            };
            let sighted = crate::secret_custody::sighted_bytes_in_txn(
                &self.vault().store,
                txn,
                bytes,
                sight,
            )?;
            if *blake3::hash(&sighted).as_bytes() != metadata.content_hash {
                return Err(MemoryError::new(
                    crate::memory::MEMORY_CODE_FORBIDDEN,
                    "a masked input cannot be copied into a new deck",
                    &[],
                ));
            }
        }
        Ok(())
    }
}
