# Snapshot-bound symbol neighbors

`vault.code.symbols.neighbors` reads recorded one-hop relations for the authenticated
owner. `self.code.symbols.neighbors` and `vault.repo.symbols.neighbors` read them for
an attached leased run under its actual repo Grant and read lane.

## Selectors and output

Name the snapshot's artifact and fork hash for the owner door. For a run, name the
registered repo, its full `ref`, and the snapshot fork hash. Both inputs require the
seed's `symbol` id and exact `path`, as returned by the pinned definitions door.
The path is admitted before a run resolves its snapshot. A symbol id alone is not
a revision, permission, or snapshot relation witness.

`kinds` selects `calls`, `imports`, and/or `refs`. Missing selects all three; an
empty list selects none. `direction` is `in`, `out`, or `both`; missing means `both`.
These defaults live in `DEFAULT_CODE_RELATION_KINDS` and
`DEFAULT_CODE_RELATION_DIRECTION`. There is no total-result cap or PPR score.
Results retain stored relation order and the original source-to-target direction.
A recursive relation appears once, including when reading both directions.

Each returned endpoint and the seed carry a symbol definition, its fingerprint and
line range, and `content_hash_blake3` from that same pinned snapshot's full-file
entry. This is not the symbol span's SHA-256, nor a document-version citation.
The source extractors determine which facts exist: CommonJS lexical calls, reads,
and exact captured relative imports are recorded; a Rust `Mentions` edge is never
relabelled as a call. Dynamic, unresolved, export and method relations are not
invented. No neighbors means no matching **recorded** relations, not a proof that
the program has no other runtime relations.

## Scope before relation selection

The door loads one symbol manifest and compares its repo and commit with the same
pinned snapshot mount. It then uses that loaded manifest, not a second lookup or
the latest import. Owner candidates pass the credential-bound entity reader. Run
candidates pass both the current Grant's read-path bounds and the run's native read
lane. Withheld or absent rows and custody-withheld files do not enter the allowed
symbol set. Both source and target must be in that set before the seed, kind or
direction is considered. A withheld or missing seed reads as not found. Native
storage errors propagate; they do not become empty successful answers.

## Persistence and restore

The symbol manifest has five required MessagePack keys: `repo_ref`, `commit_hash`,
`chunks`, `symbols`, and `relations`. Each relation has required `source`, `kind`,
and `target` fields. The actual graph writer records sorted, unique typed relations
from the same validated endpoint sink while retaining its existing global derived
edge writes. Those global edges are not the neighbor query's source: symbol ids
are version-shared, and an old edge can remain after another snapshot is ingested.
The existing 1,024-edge batch is a working buffer, never a total limit.

The relation field is part of the existing CONTENT manifest row. Generic checkpoint
snapshot and landing copy its raw codec bytes. Actor-chain scrubs round-trip the
whole row while clearing actors only from producing-operation chains. Replacing
or deleting the manifest carries or removes its relations with that row. This
format has no old-four-key reader or migration. These paths do not establish a
global erase-race or runtime correctness proof.

No worker, guest protocol, image, config, SDK connection or VM change is needed.
An authorized engine/server rollout must use matching code and generated clients.
