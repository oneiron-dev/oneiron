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
that admission in the final writer. For a new local import, absolute custody
file declarations use the same discovered worktree or Git directory that the
commit tree came from, not the run's admitted namespace. Both the early pass and
the final writer use that same physical root; the final writer still reads the
current declarations. Relative declarations and registered hashes are unchanged.
New snapshots store that declaration anchor in `custody_root`, separately from
the admitted repository namespace. Filtering and publication reconstruction keep
the original stored anchor. Historical residue checks use each prior snapshot's
own stored anchor, never today's checkout or a root guessed from its namespace.
Direct snapshot callers supply their declaration anchor explicitly; the native
binding carries it as nullable `custodyRoot` and does not infer it from `repoRef`.
A null anchor records that no anchor was supplied. It is not proof that every
file has no filesystem origin. Mixed, temporary tested-revision manifests have
no single supplied anchor and are not stored as physical captures.
No read alias or broader grant is introduced here. The anchor changes neither
repository admission nor the existing fork and scope hashes.

The custody lift can quarantine a file of a snapshot that was stored earlier.
Its stored manifest and fork hash stay unchanged. The mount reads that file as
absent. Snapshot get and projected-get omit its file entry, including its path,
hashes, size and mode. The raw stored manifest remains available to internal
code that needs its immutable identity; this is not a rewrite of stored files
or a claim that every internal raw-manifest consumer is a reader-facing view.
The native mount listing omits the same custody-withheld paths. Its existing
owned-mount materializer already skipped those paths when their read returned
absent; its returned file bodies do not change.

The stored MessagePack snapshot has a required seventh key, `custody_root`,
containing a string or null. A missing key is an error; there is no old-format
reader. Rollout requires matching engine/server and native-binding code for
this snapshot format. These changes add no settings, numeric defaults, guest
images, artifact pins or storage migrations. Existing snapshots are not rekeyed
or migrated.
