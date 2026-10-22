//! `vault.packs.sections.list`: one page of pending proposals through the
//! engine's single paged proposal walk, plus the admitted and pack-origin
//! sections from the same registry rebuild the board renders.
use super::{
    PluginSectionAdmittedRow, PluginSectionListRequest, PluginSectionPackRow,
    PluginSectionPendingRow, PluginSectionsView, plugin_error,
};
use crate::context_board::{
    EngineSectionBindings, PluginSectionRegistry, pending_plugin_proposal_page,
    render_pack_sections,
};
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryResult};

impl Memory<'_> {
    /// One page of pending offers, every admitted section and every
    /// pack-origin section. The pending page carries the truthful total and
    /// remaining counts of its read snapshot, a cursor bound to this caller,
    /// and an explicit end; a positive `limit` is served in full.
    pub fn plugin_sections_list(
        &self,
        input: &PluginSectionListRequest,
    ) -> MemoryResult<PluginSectionsView> {
        let vault = self.vault();
        let limit = input
            .limit
            .map(|limit| usize::try_from(limit).unwrap_or(usize::MAX));
        let page =
            pending_plugin_proposal_page(vault, self.actor(), input.cursor.as_deref(), limit)
                .map_err(plugin_error)?;
        let registry =
            PluginSectionRegistry::rebuild(vault, &EngineSectionBindings).map_err(plugin_error)?;
        let rendered = render_pack_sections(&registry, &[]).map_err(plugin_error)?;
        let mut rows: Vec<EntityId> = page.rows.iter().map(|row| row.install_claim_id).collect();
        let admitted: Vec<PluginSectionAdmittedRow> = registry
            .sections()
            .map(|section| {
                rows.push(section.install_claim_id);
                PluginSectionAdmittedRow {
                    claim_ref: section.install_claim_id.to_hex(),
                    section_id: section.manifest.section_id().0.clone(),
                    manifest: section.manifest.envelope().clone(),
                }
            })
            .collect();
        let pack_sections: Vec<PluginSectionPackRow> = registry
            .pack_sections()
            .map(|entry| {
                if let Ok(source) = EntityId::from_hex(&entry.source_id) {
                    rows.push(source);
                }
                PluginSectionPackRow {
                    section_id: entry.section.section_id.clone(),
                    pack_name: entry.pack_name.clone(),
                    source_id: entry.source_id.clone(),
                    content_hash: entry.content_hash.clone(),
                    section: entry.section.clone(),
                }
            })
            .collect();
        self.produced_from(rows);
        Ok(PluginSectionsView {
            pending: page
                .rows
                .into_iter()
                .map(|row| PluginSectionPendingRow {
                    claim_ref: row.install_claim_id.to_hex(),
                    pack_id: row.pack_id,
                    section_id: row.section_id.0,
                    label: row.label,
                    origin: row.origin.kind().to_owned(),
                    awaiting_owner_consent: row.awaiting_owner_consent,
                })
                .collect(),
            pending_total: page.matching_total,
            pending_remaining: page.remaining,
            next_cursor: page.next_cursor,
            end: page.end,
            admitted,
            pack_sections,
            rendered_pack_sections: rendered
                .iter()
                .map(|section| section.name().to_owned())
                .collect(),
        })
    }
}
