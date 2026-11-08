# Converting a notes folder to Files

On a running server, the vault owner can call `vault.files.sources.convert`
through the SDK, HTTP facade, or MCP. Pass `path` for a notes folder already
attached on that server's host. The host canonicalizes the folder and uses the
same native owner conversion as `oneiron files convert`.

The request's optional `exclude` uses the Files attachment rules: absent keeps
the Files default exclusions; a list, including an empty list, replaces them.
The existing notes, history, links, source filters, kind, trust, and provenance
stay in place. The native conversion resets the old source ledger and installs
the Files placement in the same writer. It then uses the ordinary Files rescan
and returns the existing `FilesSourceAttachAnswer` (world, source, and rescan).
A rescan failure does not undo an already committed conversion, as with attach.

The stopped-vault CLI remains `oneiron files convert <folder>`. Its `--exclude`
adds to defaults, while `--no-default-exclude` replaces the defaults. An embedded
SDK handle has no host folder walk and keeps the same typed host-walk-only
behavior as Files attachment and rescan. Use a server for this operation.

The SDK verb is owner-grade. A path is a locator, not permission to read or
convert another caller's source. A missing source or one already using Files
keeps the native conversion's existing error behavior.
