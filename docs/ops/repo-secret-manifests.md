# Published repository secret manifests

A repository declares secret names, custody classes, bindings and paths in
`.oneiron/secret-manifest.toml`. The origin reads the file at the commit its
publication journal advertises for a branch, never at an unapproved raw ref.
The manifest declares metadata, not secret values. Existing floor validation
and the holder's manifest recheck still govern registration and use.

Manifest reads use the git wire's configured process-output budget. There is
no separate 256 KiB manifest limit. The existing git-wire default is 16 MiB;
this change neither sets nor raises that default. A body that exceeds the
configured wire budget still returns the git wire's output-overflow error.
It is never parsed or reported as a complete manifest. Missing objects,
UTF-8 checks and parsing retain their existing behavior.

A failed read still propagates from the published-manifest list. An unstated
registration records that its manifest check was unread; a stated registration
keeps the underlying error. The reader does not silently omit a failed branch
and claim the remaining list is complete. Per-branch incomplete coverage is
not implemented by this change.

The parser keeps the current table's accepted key paths in an ordered set.
They cannot prefix one another: a duplicate, parent or child key is already
an error. Adjacent paths therefore detect those same conflicts without
scanning every earlier extension key. Quoted and dotted keys, table resets,
unknown-key handling, error text, grammar and custody-floor semantics stay
the same. No new entry count, byte cap or manifest format is introduced.
