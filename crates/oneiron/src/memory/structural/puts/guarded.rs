//! The guarded structural put: kind checks, then body, edges and text fields in one content write.
//! `Memory::put_structural_guarded` is its call surface.
//! `memory::structural` defines `StructuralPutInput` and `EntityRefReceipt`.

use super::*;

impl Memory<'_> {
    pub(crate) fn put_structural_guarded(
        &self,
        input: &StructuralPutInput,
        guard: impl FnOnce(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<EntityRefReceipt> {
        let type_byte = type_byte_for_kind(&input.kind)?;
        if type_byte == ENTITY_TYPE_CLAIM {
            return Err(MemoryError::bad_request_with(
                "CLAIM entities cannot be written structurally",
                &["Use vault.commit/vault.claims.upsert so the write gate sees the claim."],
            ));
        }
        if type_byte == ENTITY_TYPE_MACHINE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "MACHINE entities cannot be written through the facade",
                &[
                    "MACHINE is the system-actor class type; minting one would forge an actor.",
                    "System actors are provisioned by the engine host, not the bridge.",
                ],
            ));
        }
        // NOTE bodies carry `author_ref`, and attribution is engine-stamped by
        // construction: a caller who could hand-write the body could forge
        // another actor's take. This broad door has no way to bind one, so it
        // refuses the kind outright rather than validating a body it cannot
        // trust.
        if type_byte == ENTITY_TYPE_NOTE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "NOTE entities cannot be written through the structural door",
                &[
                    "NOTE bodies are actor-attributed; a caller-supplied author_ref would be a forgery.",
                    "Use author_take, which stamps the bound facade actor.",
                ],
            ));
        }
        // ONE-1686 (RT-04): MESSAGE bodies carry the six-axis witness envelope
        // — author, type, content, metadata, visibility, order — and the
        // approval-ceiling door authorizes exactly those axes at the witness
        // write boundary. A caller who could hand-write the body here would
        // author an unattributed `system` row, hide a row, or smuggle a
        // metadata side channel through a door that never asked. Same posture
        // as the NOTE refusal above: this broad door has no envelope to bind,
        // so it refuses the kind rather than validating a body it cannot trust.
        if type_byte == ENTITY_TYPE_MESSAGE {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                "MESSAGE entities cannot be written through the structural door",
                &[
                    "MESSAGE bodies are gated envelopes; a caller-supplied body would bypass the witness ceiling.",
                    "Use witness, which binds author, type, content, metadata, visibility and order to the acting actor.",
                ],
            ));
        }
        if type_byte == ENTITY_TYPE_PERSON && self.actor_class != EdgeActorClass::Human {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!(
                    "actor class {} may not mint PERSON entities; PERSON is actor-capable",
                    self.actor_class.gate_actor_class(),
                ),
                &[
                    "PERSON entities rebind as human/agent actors; only the owner mints them.",
                    "Bind a verified human-class owner actor key to create people.",
                ],
            ));
        }
        if !input.body.is_object() {
            return Err(MemoryError::bad_request(
                "structural body must be a JSON object",
            ));
        }
        let id = id_from_optional_hex(self.vault, input.id.as_deref())?;
        let occurred = TimeRange {
            start: input.occurred_at,
            end: input.occurred_at,
        };
        let learned_at = input.learned_at.unwrap_or(input.occurred_at);
        // A TURN's learned time feeds the consolidation watermark: this door
        // holds it to the witness door's clock ceiling (F30).
        if type_byte == ENTITY_TYPE_TURN {
            let now = self.vault.store.clock.now_recorded_at();
            crate::memory::witness::validate_witness_occurrence(now, learned_at)?;
        }
        let data = encode_rmpv(&json_to_rmpv(&input.body))?;

        let mut resolved_edges = Vec::new();
        if let Some(edges) = &input.edges {
            for spec in edges {
                let kind = EdgeKind::from_name(&spec.edge_kind).ok_or_else(|| {
                    MemoryError::bad_request_with(
                        format!("unknown edge kind {:?}", spec.edge_kind),
                        &["Use a snake_case EdgeKind name such as belongs_to or attached."],
                    )
                })?;
                // ONE-1414: `same_as` asserts cross-vault identity, and the
                // assertion is only meaningful together with the status Claim
                // and per-pact consent surface that
                // `federation::put_coreference_link` writes in ONE actor-gated
                // transaction. A raw link minted here would be an identity
                // claim with no status, no consent, and no attributed actor —
                // and the export filter reads the link's consent to decide
                // what crosses a grant, so a forgeable link is a disclosure
                // surface. The federation helper is the owning write door.
                if kind == EdgeKind::SameAs {
                    return Err(MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "same_as edges cannot be written through the structural door",
                        &[
                            "same_as is a cross-vault identity link carrying status and per-pact share consent.",
                            "Use the federation coreference door so the link and its status claim land atomically.",
                        ],
                    ));
                }
                let target = self.resolve_ref(&spec.target_ref)?;
                let weight = spec.weight.or_else(|| kind.default_weight()).unwrap_or(1.0);
                resolved_edges.push((kind, target, weight));
            }
        }
        // A text written from ASSETs is born under their one facet, with its
        // `DerivedFrom` edges (facet rule C); sources in two facets refuse it.
        let (sources, resolved_edges): (Vec<_>, Vec<_>) =
            resolved_edges.into_iter().partition(|(kind, _, _)| {
                type_byte == ENTITY_TYPE_ASSET_TEXT && *kind == EdgeKind::DerivedFrom
            });
        let sources: Vec<_> = sources
            .into_iter()
            .map(|(_, source, weight)| (source, weight))
            .collect();
        let text_fields: Vec<(String, String)> = input
            .text_fields
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|field| (field.field.clone(), field.value.clone()))
            .collect();
        if !text_fields.is_empty() {
            self.vault.ensure_text_index_trusted()?;
        }
        // Rule A: an ASSET_TEXT is born in its writer's class from the ASSETs
        // it derives from, every one of them; a non-person's
        // text that derives from none names no input, so it has no birth.
        let birth = if type_byte == ENTITY_TYPE_ASSET_TEXT {
            let inputs: Vec<_> = sources.iter().map(|(source, _)| *source).collect();
            RowBirth::written(
                WriteActor::new(self.actor, self.actor_class),
                MadeByClass::of_writer(self.actor_class),
                "structural.asset_text",
                &inputs,
                &[],
                learned_at,
            )
        } else {
            None
        };

        // Marker check and put share ONE write transaction (A1): a
        // concurrent hard delete either commits first (refused here) or
        // after this txn (its purge then erases what we wrote).
        let refused = self.with_actor_content_write_txn(|content| {
            // An actor-capable PERSON is still an owner verb; the content
            // transaction does not substitute for that domain authority.
            if type_byte == ENTITY_TYPE_PERSON {
                verify_owner_actor_binding_in_txn(self.vault, content.read(), self.actor)?;
            }
            if self
                .vault
                .local_hard_delete_marker_exists_in_txn(content.read(), &id)?
            {
                return Ok(true);
            }
            ensure_structural_create_in_txn(self.vault, content.read(), &id)?;
            guard(content.read())?;
            let mut batch = if sources.is_empty() {
                self.vault
                    .batch_in()
                    .put(&id, type_byte, occurred, learned_at, &data)
            } else {
                self.vault
                    .batch_in()
                    .asset_text_birth(&id, occurred, learned_at, &data, &sources)
            };
            batch = batch.made_by(&id, birth);
            for (kind, target, weight) in &resolved_edges {
                batch = batch.edge(&id, *kind, target, *weight);
            }
            if !text_fields.is_empty() {
                let fields: Vec<(&str, &str)> = text_fields
                    .iter()
                    .map(|(field, value)| (field.as_str(), value.as_str()))
                    .collect();
                batch = batch.text(&id, &fields);
            }
            content.apply_batch(batch)?;
            Ok(false)
        })?;
        if refused {
            return Err(hard_deleted_refusal(&id));
        }
        self.entity_ref_receipt_of(&id, type_byte)
    }
}
