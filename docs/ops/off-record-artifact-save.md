# Explicit scratch artifact saves

`vault.off_record.artifacts.save` preserves a selected scratch NOTE or CLAIM from a live off-record session in the current vault. Its input is `{ "session_ref": "<live handle>", "artifact_ref": "<room alias or entity id>" }`.

The native entry points are `OffRecordSession::save_artifact_by` (the actual holder's verified slip) and `save_artifact_as` (the vault owner's authenticated proof). The save rechecks the vault write grant and current room membership in the committing writer. A session name, actor label, or broad read permission is not save authority. Write-only credentials use the existing target-key bounds; the save does not add a read-verb requirement.

The selected artifact keeps its identity, original authorship, source revision, birth and supplied evidence. Supplied room evidence remains as supplied, not authenticated evidence or a new claim by the saver. NOTE saves load the actual composed document, its current head and complete Loro state; they do not rebuild text from the birth body. Ordinary structural, source-trust, privacy, mask, citation, deletion and shared-vault write checks still apply. A saved document cannot replace a different durable document merely because its immutable NOTE birth body matches.

The result lists the actual saved closure and room-to-vault short-id pairs. Unsaved scratch and talk remain in the overlay. The native save posts `saved_artifact`, naming the actual saver, only after its commit succeeds. Retirement then removes only the saved source footprints that still match the captured overlay snapshot; it never masks the durable rows or removes newer concurrent values. Close continues to dispose of the remaining overlay.

This adds a normal engine/server/client verb. It requires matching engine/server and regenerated clients at rollout. It adds no configuration, migration, background service, guest change or durable session registry.
