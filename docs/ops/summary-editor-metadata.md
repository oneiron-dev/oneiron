# SUMMARY editor metadata

`Vault::edit_entity_metadata` edits the existing document under its ordinary
write authority and history. For the SUMMARY editor `keep` memo, removing
`keep` (`MetadataEdit.value = None`) or writing MessagePack Nil clears the
memo. A SUMMARY metadata read represents either clear as the empty string,
which the native `set_scope_summary_keep` setter also accepts.

The document keeps the selected metadata operation and its original history;
a read does not rewrite Nil or recreate a removed field. The SUMMARY read
view and the proposal's live/base memo comparison use the same interpretation.
A nonempty memo must still match on both sides of the proposal fence.
Malformed metadata values and malformed purpose or derivation still error.
Other fields, body edits, source admission and authority checks are unchanged.

This covers only SUMMARY `keep` clearing. It is not a native-record codec audit
of every generic metadata field (FIX762 remains partial).
