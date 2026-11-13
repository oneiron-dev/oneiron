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

# Asking about files

The vault owner asks a question of the Files world with `vault.files.sources.ask`
(`{ "query": "What is the quarter's budget?" }`, or `{ "query": ..., "file": { "source": <source
id>, "path": "budget.md" } }` for one file; `sources` narrows the search as above and is not taken
beside `file`). The owner can ask about a file and get an answer with citations (ARCH-0027
#files-world).

- **The files read.** With no `file`, the door runs `vault.files.sources.search` for the question
  and reads the first 5 files with text it found, in its order; a file held by its name only has no
  text and is passed over. Each file's note is read from its start, up to 12,000 characters, at the
  revision its ledger holds. `read` in the answer lists them, numbered from 1; `hits` is the
  search's answer.
- **One model call.** The question and the files go in one call of this server's house chat role,
  metered on the owner's budget line. The model is asked for JSON: an answer with `[n]` after each
  claim, and citations, each a file number and a quote copied from that file.
- **Where the text may go.** Each rung of the call is sent the files only when the release verdict
  admits their notes at that rung's destination, judged before the rung is admitted and again just
  before it is sent. The Files world is read on this install only, so a model off this install is
  sent nothing; with no rung on this install the door refuses with `MODEL_UNAVAILABLE`.
- **The check, in fixed code.** A citation holds when its number names a file the model was given,
  that file still reads as it was read, and its quote is an exact run of the file's text. Any other
  citation is dropped. The answer stands (`outcome.kind` = `cited`) only when one citation holds
  and every `[n]` it carries names a file a citation that holds cites; otherwise the outcome is
  `no_cited_answer` with `why` = `no_citation_held`, and the owner opens the files. With no file
  to read, no model is asked and `why` is `no_text_file`.
