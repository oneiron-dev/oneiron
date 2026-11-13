# Searching the Files world

The vault owner searches the Files world's sources with `vault.files.sources.search`
(`{ "query": "budget", "sources": [<source id>], "limit": 20 }`; `sources` absent searches every
Files source, `limit` defaults to 20 and stops at 100). Search goes by name first and meaning
second (ARCH-0027 #files-world).

- **Name tier.** Every file a chosen source's ledger holds, a file held by its name only included
  and a file that left its folder not, is matched against the query in lower case. A file whose
  name or name without its extension is the query comes first (`exact`), then a name that starts
  with it (`prefix`), then a name holding every word of it (`name_words`), then a path under the
  folder holding every word of it (`path_words`). Within a class, the file written last comes first.
- **Meaning tier.** One recall as the owner over this install's Files world alone, base declined.
  A recalled note is mapped back to its file through the source's ledger (a long file's parts map
  to the file), and its text excerpt is the hit's `snippet`. A file the name tier listed is not
  listed again. A running server runs this recall through its own recall pipeline, so the query is
  embedded where the host embeds; an embedded handle recalls with no query vector.
- `meaning` in the answer is `ran`, or `unavailable` with the reason (no Files world on this
  install, or the recall refused). The name tier's hits stand either way.

The answer names each file by its source and path, with its install, ledger state, readiness,
note, revision, size and the time it was last written.
