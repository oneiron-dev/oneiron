# Code snapshot identity and custody views

A full owner or trusted local import uses the repository discovered by Git.
Passing a folder inside that repository still imports the enclosing commit tree,
not a subtree.
The snapshot's local repository path names that discovered worktree root (or the
Git directory of a bare repository). If the discovered worktree cannot be
canonicalized, the same discovered Git directory keeps commit-only imports
available; the importer does not substitute another repository or host folder.
The commit, file paths and accepted files come from the same selected commit as
before. No repository registration, grant
or editable whitelist is created by an import.

The local repository path is data identity. It does not replace the caller's
native owner or run admission. Run imports retain the exact existing admitted
repository namespace: changing it would break their pinned read's repository
match. They still select only the paths their existing grant admits and re-check
that admission in the final writer. Custody uses the same snapshot identity when
it anchors absolute file declarations. Normalizing a run's admitted namespace
and custody root together remains separate work; no read alias or broader grant
is introduced here.

The custody lift can quarantine a file of a snapshot that was stored earlier.
Its stored manifest and fork hash stay unchanged. The mount reads that file as
absent. Snapshot get and projected-get omit its file entry, including its path,
hashes, size and mode. The raw stored manifest remains available to internal
code that needs its immutable identity; this is not a rewrite of stored files
or a claim that every internal raw-manifest consumer is a reader-facing view.
The native mount listing omits the same custody-withheld paths. Its existing
owned-mount materializer already skipped those paths when their read returned
absent; its returned file bodies do not change.

These changes need only the normal matching engine/server update. They add no
settings, numeric defaults, wire formats, guest images, artifact pins, storage
migrations or old-format readers. Existing snapshots are not rekeyed or migrated.
