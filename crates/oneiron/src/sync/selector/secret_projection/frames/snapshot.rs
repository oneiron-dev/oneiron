//! Same-span neutral history for held full snapshots.

use super::*;

impl SyncSecretProjection {
    pub(super) fn admit_held_full_snapshot<'a>(
        &self,
        store: &Store,
        context: Option<&LoroDoc>,
        doc: &LoroDoc,
        input: &ImportBlobMetadata,
    ) -> Option<WindowAdmission<'a>> {
        if input.mode != EncodedBlobMode::Snapshot {
            return None;
        }
        let mut json = doc.export_json_updates(&VersionVector::default(), &doc.oplog_vv());
        self.resolve_copy_carriers(store, &mut json);
        let translated = self.translate_history(store, context, &mut json).ok()?;
        if translated.held.is_empty()
            || super::super::history::needs_whole_hold_except_shells(&json, |key, op| {
                crate::entity_id::EntityId::from_hex(key).is_ok_and(|id| {
                    translated.source_shells.contains(&op)
                        || translated.held.iter().all(|held| held.source != id)
                })
            })
        {
            return None;
        }
        self.unread_rows(store, context, &json).ok()?;
        let target = LoroDoc::new();
        if target.import_json_updates(json).ok()?.pending.is_some() {
            return None;
        }
        let bytes = target.export(ExportMode::Snapshot).ok()?;
        if !same_span(input, &meta(&bytes)?, &input.mode) {
            return None;
        }

        // The checkpoint visits retained row values, not just state winners.
        // A transform needed here must not be discarded with this check copy.
        let check_doc = LoroDoc::from_snapshot(&bytes).ok()?;
        let mut check_parts = parts_of(&check_doc)?;
        let mut check_held = Vec::new();
        let mut check_landings = Vec::new();
        if self
            .admit_parts(
                store,
                context,
                &mut check_parts,
                &mut check_held,
                &mut check_landings,
            )
            .ok()?
            || !check_held.is_empty()
            || !check_landings.is_empty()
        {
            return None;
        }
        Some(WindowAdmission::Admit(
            Cow::Owned(bytes),
            translated.landings,
            translated.held,
        ))
    }
}
