"""Matched Pyserini/Lucene baseline over one pack slice (ONE-318).

Reads one pack slice file (the ``oneiron.retrieval_pack.v1`` JSON layout)
and, per corpus, writes a Pyserini JsonCollection (``{"id": record_id,
"contents": text}``), indexes it with Lucene at Pyserini defaults, and
searches each of the corpus's queries, writing TREC run lines with the
pack ``record_id`` as the docid. Grade the run file with
``scorecard grade-run``; compare it with ``scorecard compare --reference``.

Each corpus is indexed and searched under its own language: the part
after ``-`` in the query category (``miracl-ja`` becomes ``ja``). The
language is passed to Pyserini verbatim (``ja`` Kuromoji, ``ko`` Nori,
``zh`` CJK, ``th``, ``id``, ``en``); check
``python -m pyserini.index.lucene --help`` if a name is refused.
BM25 runs at k1 0.9, b 0.4, top 100, tag ``pyserini-bm25-<lang>``.

Requires Python with ``pyserini==1.6.0`` (the current release, verified
2026-11-14) and Java 21 on a fleet host; nothing here runs in a
worktree checkout. Usage:
    python3 scripts/bench/pyserini_matched_baseline.py --pack-dir D \
        --slice held_out|search --out RUNFILE --work-dir W

Exit codes: 0 ok, 2 bad input, 1 failure.
"""

import argparse
import json
import os
import subprocess
import sys


def fail(message):
    """Print a failure message and return exit code 1."""
    print(f"pyserini_matched_baseline: failure: {message}", file=sys.stderr)
    return 1


def bad_input(message):
    """Print a bad-input message and return exit code 2."""
    print(f"pyserini_matched_baseline: bad input: {message}", file=sys.stderr)
    return 2


def corpus_language(corpus_id, queries):
    """The corpus language from its queries' categories, or None if mixed."""
    languages = set()
    for query in queries:
        category = query.get("category", "")
        if "-" not in category:
            return None
        languages.add(category.rsplit("-", 1)[1])
    if len(languages) != 1:
        return None
    return next(iter(languages))


def write_collection(directory, records):
    """Write one JsonCollection file; return its path."""
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "docs.jsonl")
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps({"id": record["record_id"], "contents": record["text"]}) + "\n")
    return path


def index_corpus(input_dir, index_dir, language):
    """Index one corpus with Lucene; return the subprocess exit code."""
    command = [
        sys.executable, "-m", "pyserini.index.lucene",
        "--collection", "JsonCollection",
        "--input", input_dir,
        "--index", index_dir,
        "--generator", "DefaultLuceneDocumentGenerator",
        "--threads", "4",
        "--storeRaw",
        "--language", language,
    ]
    return subprocess.run(command).returncode


def main(argv=None):
    """Index each corpus and search its queries, writing one TREC run file."""
    parser = argparse.ArgumentParser(description="matched Pyserini baseline over one pack slice")
    parser.add_argument("--pack-dir", required=True, help="directory holding the slice files")
    parser.add_argument("--slice", required=True, help="search or held_out (never sealed)")
    parser.add_argument("--out", required=True, help="TREC run file to write")
    parser.add_argument("--work-dir", required=True, help="scratch directory for collections and indexes")
    args = parser.parse_args(argv)
    if args.slice == "sealed":
        return bad_input("the sealed slice is opened only by its once-only run")
    if args.slice not in ("search", "held_out"):
        return bad_input(f"unknown slice: {args.slice}")
    slice_path = os.path.join(args.pack_dir, f"{args.slice}.json")
    try:
        with open(slice_path, encoding="utf-8") as handle:
            pack = json.load(handle)
    except (OSError, ValueError) as error:
        return bad_input(f"slice read failed: {error}")
    if pack.get("contract") != "oneiron.retrieval_pack.v1":
        return bad_input("slice file has the wrong contract")
    if pack.get("slice") != args.slice:
        return bad_input(f"slice file holds {pack.get('slice')}, want {args.slice}")
    try:
        from pyserini.search.lucene import LuceneSearcher
    except ImportError:
        return fail("pyserini is not installed; fleet hosts need pyserini==1.6.0 and Java 21")
    records_by_corpus = {}
    for corpus in pack.get("corpora", []):
        named = set()
        for session in corpus.get("sessions", []):
            named.update(session.get("record_ids", []))
        records_by_corpus[corpus["corpus_id"]] = named
    records = {record["record_id"]: record for record in pack.get("records", [])}
    queries_by_corpus = {}
    for query in pack.get("queries", []):
        queries_by_corpus.setdefault(query["corpus_id"], []).append(query)
    try:
        os.makedirs(args.work_dir, exist_ok=True)
        run_lines = []
        for corpus_id in sorted(queries_by_corpus):
            queries = queries_by_corpus[corpus_id]
            language = corpus_language(corpus_id, queries)
            if language is None:
                return bad_input(f"corpus {corpus_id} mixes categories")
            wanted = records_by_corpus.get(corpus_id, set())
            corpus_records = [records[record_id] for record_id in sorted(wanted) if record_id in records]
            corpus_dir = os.path.join(args.work_dir, corpus_id)
            input_dir = os.path.join(corpus_dir, "collection")
            index_dir = os.path.join(corpus_dir, "index")
            write_collection(input_dir, corpus_records)
            code = index_corpus(input_dir, index_dir, language)
            if code != 0:
                return fail(f"indexing {corpus_id} failed with exit {code}")
            searcher = LuceneSearcher(index_dir)
            searcher.set_language(language)
            searcher.set_bm25(0.9, 0.4)
            tag = f"pyserini-bm25-{language}"
            for query in sorted(queries, key=lambda row: row["query_id"]):
                hits = searcher.search(query["text"], 100)
                for rank, hit in enumerate(hits, start=1):
                    run_lines.append(f"{query['query_id']} Q0 {hit.docid} {rank} {hit.score!r} {tag}")
    except OSError as error:
        return fail(f"write failed: {error}")
    try:
        with open(args.out, "w", encoding="utf-8") as handle:
            for line in run_lines:
                handle.write(line + "\n")
    except OSError as error:
        return fail(f"run write failed: {error}")
    print(f"wrote {len(run_lines)} run lines to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
