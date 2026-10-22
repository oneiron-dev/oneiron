//! Credential-bound admission; every write rechecks its inputs in its writer.
use super::*;
use crate::claim::{ClaimReadStatus, ScopedRead};
use crate::consent::AuthenticatedOwner;
use crate::edit_roundtrip::deck_create::{
    DeckCreateError, DeckCreateOutcome, DeckCreateRequest, DirectionOutcome,
};
use crate::batch::secret_scan::LiftedKeys;
use crate::memory::{Memory, MemoryError, MemoryResult, resolve_entity_ref};
use crate::secret_custody::SecretSight;
use crate::typed_body::LiftedSources;
use crate::{EntityId, WriteActor};
use oneiron_docedit::design_plan::Brief;
use oneiron_docedit::emit::Names;
use serde::de::DeserializeOwned;

/// The keys a masked reader's view of a deck response is judged and masked
/// by, found in the outline texts the engine decoded for it (FIX 9605).
type Lifted = Option<(LiftedKeys, LiftedSources)>;

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

fn sources_readable(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
) -> MemoryResult<bool> {
    Ok(!lane
        .get_entities_parts_in_txn(txn, sources)?
        .iter()
        .any(Option::is_none))
}

/// A kept outline goes out only when every frozen source it cites still reads
/// under this credential; otherwise it is omitted with a reason, never refused.
fn readable_keep(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    kept: Option<KeptOutline>,
) -> MemoryResult<(Option<KeptOutline>, Option<KeptOutlineOmissionReason>)> {
    let Some(kept) = kept else {
        return Ok((None, None));
    };
    let Ok(sources) = outline_sources(&kept.bytes) else {
        return Ok((None, Some(KeptOutlineOmissionReason::InvalidFrozenOutline)));
    };
    if sources_readable(lane, txn, &sources)? {
        Ok((Some(kept), None))
    } else {
        Ok((None, Some(KeptOutlineOmissionReason::SourcesUnreadable)))
    }
}

fn view_error(_: serde_json::Error) -> MemoryError {
    crate::Error::InvariantViolation("a deck response did not encode").into()
}

/// `view` with each lifted value its strings hold as its handle.
fn masked_json<T: Serialize + DeserializeOwned>(view: &mut T, keys: &LiftedKeys) -> MemoryResult<()> {
    let mut value = serde_json::to_value(&*view).map_err(view_error)?;
    if keys.mask_json(&mut value) {
        *view = serde_json::from_value(value).map_err(view_error)?;
    }
    Ok(())
}

/// An outline view masked: its live outline, and a copy of the kept bytes
/// decoded, masked and encoded again. The stored keep, its hash and the
/// bytes a plan compiles from stay as they are.
fn masked_outline(view: &mut DeckOutlineView, keys: &LiftedKeys) -> MemoryResult<()> {
    masked_json(&mut view.outline, keys)?;
    if let Some(kept) = &mut view.kept {
        let mut held: serde_json::Value =
            serde_json::from_slice(&kept.bytes).map_err(view_error)?;
        if keys.mask_json(&mut held) {
            kept.bytes = serde_json::to_vec(&held).map_err(view_error)?;
        }
    }
    Ok(())
}

fn require_sources(
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    sources: &[EntityId],
) -> MemoryResult<()> {
    if !sources_readable(lane, txn, sources)? {
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
            why: None,
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
        let (mut kept, mut kept_omission) = readable_keep(
            &lane,
            &txn,
            self.vault().kept_deck_outline_in_txn(&txn, note)?,
        )?;
        let freshness = self
            .vault()
            .deck_outline_freshness_in_txn(&txn, note)
            .map_err(creation_error)?;
        // A masked reader's keys are those of the texts it is shown: the
        // live outline's, and the kept outline's at its keep (FIX 9605).
        let lifted = if self.reads_lifted_keys_masked_in_txn(&txn)? {
            let mut texts = vec![document.markdown.clone()];
            if let Some(held) = kept.as_ref().filter(|held| held.frontier != document.frontier) {
                match crate::note::deck_outline_markdown_at_in_txn(
                    self.vault(),
                    &txn,
                    note,
                    &held.frontier,
                )? {
                    Some(text) => texts.push(text),
                    None => {
                        kept = None;
                        kept_omission = Some(KeptOutlineOmissionReason::KeysUnknown);
                    }
                }
            }
            Some(self.vault().lifted_projection_texts_in_txn(&txn, texts)?)
        } else {
            None
        };
        // Evidence observations go out only beside a keep that does.
        let evidence_changed = if kept.is_some() {
            self.vault()
                .deck_outline_evidence_in_txn(&txn, note)
                .map_err(creation_error)?
        } else {
            Vec::new()
        };
        let outline = serde_json::from_slice(&bytes)
            .map_err(|_| MemoryError::bad_request("outline wire grammar"))?;
        drop(txn);
        let view = DeckOutlineView {
            outline_ref: note.to_hex(),
            frontier: document.frontier,
            outline,
            kept,
            freshness,
            kept_omission,
            evidence_changed,
            presentation: DeckPresentation::Whole,
        };
        let (mut view, presentation) = self.present_deck(
            &note,
            view,
            lifted,
            input.why.as_deref(),
            "oneiron deck outline view v1",
            masked_outline,
        )?;
        view.presentation = presentation;
        Ok(view)
    }

    /// `view` as this reader may see it (OF-067, FIX 9605): whole for the
    /// owner, for texts that hold no lifted key, and for an agent that says
    /// `why` once a grant covers their keys (`typed_body_read_sight`, after
    /// the response's snapshot or writer closed, its receipts written); with
    /// each lifted value as its handle otherwise.
    fn present_deck<T: Serialize>(
        &self,
        note: &EntityId,
        mut view: T,
        lifted: Lifted,
        why: Option<&str>,
        domain: &str,
        mask: impl FnOnce(&mut T, &LiftedKeys) -> MemoryResult<()>,
    ) -> MemoryResult<(T, DeckPresentation)> {
        let Some((keys, sources)) = lifted.filter(|(keys, _)| !keys.is_empty()) else {
            return Ok((view, DeckPresentation::Whole));
        };
        let shown = serde_json::to_vec(&view).map_err(view_error)?;
        let fingerprint = blake3::derive_key(domain, &shown);
        if self.typed_body_read_sight(note, &fingerprint, &sources, why)? != SecretSight::Masked {
            return Ok((view, DeckPresentation::Whole));
        }
        mask(&mut view, &keys)?;
        Ok((view, DeckPresentation::Masked))
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
        let (view, lifted) = self.with_verified_actor_write_txn(|txn| {
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
            // A fresh keep is the live outline's: its text holds the keys.
            let lifted = if self.reads_lifted_keys_masked_in_txn(txn)? {
                let document = crate::note::deck_outline_document_in_txn(self.vault(), txn, note)?;
                Some(
                    self.vault()
                        .lifted_projection_texts_in_txn(txn, vec![document.markdown])?,
                )
            } else {
                None
            };
            let view = DeckDesignView {
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
                presentation: DeckPresentation::Whole,
            };
            Ok((view, lifted))
        })?;
        let (mut view, presentation) = self.present_deck(
            &note,
            view,
            lifted,
            input.why.as_deref(),
            "oneiron deck design view v1",
            masked_json,
        )?;
        view.presentation = presentation;
        Ok(view)
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
