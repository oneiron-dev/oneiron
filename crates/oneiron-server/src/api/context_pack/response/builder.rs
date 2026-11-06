//! The server's context-pack builder run: the scoped filter, the reactions,
//! the response limits and the projection behind one typed response.

use super::super::super::{MemoriesRequest, advance_memories_cursor, core_engine_error};
use super::super::instruction_files::returned_instruction_files;
use super::super::response_limits::{
    ContextPackResponseLimits, apply_context_pack_response_limits,
};
use super::{
    CoreContextPackResponse, core_context_pack_evidence, core_context_pack_evidence_for_results,
    core_context_pack_response,
};
use crate::error::ApiError;
use oneiron::context_board::MemorySource;
use std::collections::BTreeSet;
use std::collections::HashMap;

pub(crate) async fn run_context_pack_builder(
    server: &crate::server::SyncServer,
    scoped_read: &oneiron::claim::ScopedRead<'_>,
    builder: oneiron::ContextPackBuilder<'_>,
    projection: oneiron::serialize::SerializeConfig,
    response_limits: ContextPackResponseLimits,
    memories: Option<MemoriesRequest>,
    disclosure: Option<oneiron::DisclosureContext>,
) -> Result<
    (
        CoreContextPackResponse,
        Option<oneiron::MemoriesSection>,
        Option<oneiron::MemoriesCursor>,
    ),
    ApiError,
> {
    let vault = &server.vault;
    let subjects: Vec<_> = memories
        .as_ref()
        .and_then(|request| request.companion.as_ref())
        .into_iter()
        .flat_map(|companion| {
            [
                companion.person_ref.as_deref(),
                companion.counterpart_person_ref.as_deref(),
            ]
        })
        .flatten()
        .filter_map(|reference| oneiron::EntityId::from_hex(reference).ok())
        .collect();
    let builder = builder
        .l2_summary_subjects(&subjects)
        .l2_summary_reader(scoped_read);
    let mut pack = builder.run_unfinalized_with_telemetry().map_err(|error| {
        tracing::error!(kind = ?error.kind(), "core context-pack failed");
        core_engine_error("core context-pack failed", error)
    })?;
    // The clamp's count names only rows the caller reads: a hidden row that
    // matched the query must not show up as a number.
    let clamped_out = pack.clamped_out_under(scoped_read).map_err(|error| {
        pack.discard_telemetry();
        tracing::error!(kind = ?error.kind(), "core context-pack clamp count failed");
        core_engine_error("core context-pack scoped read failed", error)
    })?;
    let mut narrowing = pack
        .filter_scoped_under(scoped_read, disclosure.as_ref())
        .map_err(|error| {
            pack.discard_telemetry();
            tracing::error!(kind = ?error.kind(), "core context-pack scoped read failed");
            core_engine_error("core context-pack scoped read failed", error)
        })?;
    // A MESSAGE carries its current reactions, read through the same scope
    // and clamp, and that read narrows the pack's receipt (FIX 8669).
    let reactions = scoped_read
        .attach_reactions_under(&mut pack.value, disclosure.as_ref())
        .map_err(|error| {
            pack.discard_telemetry();
            tracing::error!(kind = ?error.kind(), "core context-pack reactions failed");
            core_engine_error("core context-pack reactions failed", error)
        })?;
    narrowing.restrict_with(&reactions);
    apply_context_pack_response_limits(&mut pack, response_limits);
    let assembly = disclosure.as_ref().map(|ctx| ctx.assembly(clamped_out));
    // Keep provenance from the authorized snapshot: the JSON profile can
    // remove source and world fields needed for trust labels and fences.
    let projected_memories = memories
        .as_ref()
        .and_then(|request| {
            request.memory_board_budget.map(|budget| {
                vault.project_memories_section(
                    &pack.value,
                    budget,
                    request.companion.clone(),
                    assembly.clone(),
                    &BTreeSet::new(),
                )
            })
        })
        .transpose()
        .map_err(|error| core_engine_error("memory provenance projection failed", error))?;
    // Instruction files name only units the projection's cuts kept (FIX 9761).
    let pack = pack
        .finish_projected_json(&projection, |pack| {
            returned_instruction_files(scoped_read, pack, disclosure.as_ref())
        })
        .map_err(|error| {
            tracing::error!(kind = ?error.kind(), "core context-pack instruction files failed");
            core_engine_error("core context-pack scoped read failed", error)
        })?;
    let run_id = pack.run_id;
    let pack = pack.value;
    let projected_memories = projected_memories.map(|mut section| {
        let visible_rows: HashMap<_, _> = pack
            .results
            .iter()
            .map(|entity| ((MemorySource::Result, entity.id.to_hex()), entity))
            .chain(
                pack.neighbors
                    .iter()
                    .map(|entity| ((MemorySource::Neighbor, entity.id.to_hex()), entity)),
            )
            .collect();
        // Optional rows keep their authorized labels, but only the final
        // projection supplies their presence and snippet bytes.
        section.rows.retain_mut(|row| {
            let Some(entity) = visible_rows.get(&(row.source, row.id.clone())) else {
                return false;
            };
            if row.snippet.is_some() {
                row.snippet = entity
                    .fields
                    .as_ref()
                    .and_then(|fields| fields.get("val"))
                    .map(|value| {
                        let mut value = value.clone();
                        oneiron::batch::export::redact_credentials(&mut value);
                        value.to_string()
                    });
            }
            true
        });
        for (index, row) in section.rows.iter_mut().enumerate() {
            row.row_index = index;
        }
        section
    });
    let evidence = core_context_pack_evidence(vault, run_id)?;
    let evidence = core_context_pack_evidence_for_results(evidence, &pack.results);
    let mut pin_narrowing = Vec::new();
    let (section, cursor) = match memories.as_ref() {
        Some(request) => {
            // FIX 8142: `memories.enabled=false` drops only the optional
            // projection; the mandatory pins still assemble.
            let mut section = projected_memories
                .or_else(|| Some(oneiron::MemoriesSection::pins_only(assembly.clone())));
            if let Some(section) = &mut section {
                pin_narrowing = section
                    .include_pinned_refs_with_disclosure(
                        scoped_read,
                        &request.pinned_refs,
                        disclosure.as_ref(),
                    )
                    .map_err(|error| core_engine_error("memory pin read failed", error))?;
                let automatic = scoped_read
                    .manifest_pinned_refs()
                    .map_err(|error| core_engine_error("manifest pin read failed", error))?;
                pin_narrowing.push(automatic.receipt);
                pin_narrowing.extend(
                    section
                        .include_pinned_refs_with_disclosure(
                            scoped_read,
                            &automatic.value,
                            disclosure.as_ref(),
                        )
                        .map_err(|error| {
                            core_engine_error("manifest pin disclosure failed", error)
                        })?,
                );
                pin_narrowing.extend(
                    section
                        .include_hook_pins(scoped_read, &request.hook_pins, disclosure.as_ref())
                        .map_err(|error| core_engine_error("hook pin read failed", error))?,
                );
            }
            let section = section.filter(|section| {
                request.memory_board_budget.is_some() || !section.rows.is_empty()
            });
            let (cursor, observed) = advance_memories_cursor(
                server,
                &request.session_scope_id,
                &request.session_id,
                &pack,
                &evidence,
                scoped_read,
            )
            .await
            .map_err(|error| core_engine_error("context-pack observations failed", error))?;
            narrowing.restrict_with(&observed);
            (section, Some(cursor))
        }
        None => (None, None),
    };
    let mut response = core_context_pack_response(pack, evidence, assembly, narrowing);
    response.pin_narrowing = pin_narrowing;
    Ok((response, section, cursor))
}
