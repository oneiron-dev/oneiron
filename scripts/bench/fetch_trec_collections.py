"""Fetch the pinned TREC collections for the retrieval matrix (ONE-318).

Downloads the pinned MIRACL (train, dev) and Mr.TyDi (test) files with
``huggingface_hub.hf_hub_download`` at the revisions pinned in
``sources.v1.json``, checks every LFS file's sha256, and writes per split
three files in the formats ``trec_collection::parse_topics``,
``parse_qrels`` and ``parse_passages`` accept:

- ``topics.tsv``: ``qid\ttext`` per line,
- ``qrels.txt``: ``qid Q0 docid grade`` per line,
- ``passages.jsonl``: ``{"docid", "title", "text"}`` per line: the judged
  pool, plus the ``M`` unjudged passages with the lowest sha256(docid) as
  fill candidates (default 0),

then one ``manifest.json`` in the ``scorecard convert-trec`` format with
every written file's sha256. Corpus shards are streamed (gzip line by
line), keeping only wanted docids; the full corpus is never stored.

Mr.TyDi notes: it has no Chinese, so ``zh`` gets no sealed split. Its
dev/test jsonl rows carry positive docids only (title and text are
empty), so passage text always comes from the corpus stream, and its
test split has positives only: fetch it with ``--fill-candidates`` of at
least 1 and convert it with ``--fill-seed``/``--fill-per-corpus``.
MIRACL topics and qrels are small plain files with no LFS sha256; they
are recorded as ``null`` in sources and downloaded unverified.

Usage:
    python3 scripts/bench/fetch_trec_collections.py --data-root DIR \
        --sources crates/oneiron-bench/fixtures/retrieval_matrix/sources.v1.json \
        --languages ja,ko,zh,th,id,en [--fill-candidates M]
        [--pack-id ID] [--revision R] [--time YYYY-MM-DDTHH:MM:SSZ]

``--time`` applies only where sources carry no dump time (Mr.TyDi); it is
required then. Exit codes: 0 ok, 2 bad input, 1 failure.
"""

import argparse
import gzip
import hashlib
import heapq
import json
import os
import re
import sys

TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$")


def fail(message):
    """Print a failure message and return exit code 1."""
    print(f"fetch_trec_collections: failure: {message}", file=sys.stderr)
    return 1


def bad_input(message):
    """Print a bad-input message and return exit code 2."""
    print(f"fetch_trec_collections: bad input: {message}", file=sys.stderr)
    return 2


def check_time(value):
    """True for exactly YYYY-MM-DDTHH:MM:SSZ with plausible ranges."""
    match = TIME_RE.match(value)
    if not match:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    return (
        year >= 1970
        and 1 <= month <= 12
        and 1 <= day <= 31
        and hour <= 23
        and minute <= 59
        and second <= 59
    )


def sha256_file(path):
    """The sha256 of a file's bytes, as lowercase hex."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified(repo_id, filename, revision, want):
    """Download a file and check its sha256, unless sources pins none."""
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        raise ValueError("huggingface_hub is not installed; fleet hosts need it")
    path = hf_hub_download(repo_id, filename, repo_type="dataset", revision=revision)
    if want is None:
        print(f"unverified (no sha256 in sources): {repo_id}/{filename}")
        return path
    found = sha256_file(path)
    if found != want:
        raise ValueError(f"sha256 mismatch for {repo_id}/{filename}")
    return path


def read_topics(path):
    """Map qid to text from a qid-TAB-text topics file."""
    topics = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            qid, _, text = line.partition("\t")
            topics[qid.strip()] = text.strip()
    return topics


def read_qrels(path):
    """List (qid, docid, grade) rows from a TREC qrels file."""
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            parts = line.split()
            rows.append((parts[0], parts[2], int(parts[3])))
    return rows


def stream_corpus(paths, wanted):
    """Map wanted docids to (title, text), scanning gzip shards line by line."""
    texts = {}
    missing = set(wanted)
    for path in paths:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            for line in handle:
                if not missing:
                    break
                if not line.strip():
                    continue
                row = json.loads(line)
                docid = row["docid"]
                if docid in missing:
                    texts[docid] = (row.get("title") or "", row.get("text") or "")
                    missing.discard(docid)
        if not missing:
            break
    return texts, sorted(missing)


def unjudged_rows(paths, wanted):
    """Yield (sha256(docid), docid, title, text) for every unjudged passage."""
    for path in paths:
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                docid = row["docid"]
                if docid in wanted:
                    continue
                digest = hashlib.sha256(docid.encode("utf-8")).hexdigest()
                yield (digest, docid, row.get("title") or "", row.get("text") or "")


def fill_candidates(paths, wanted, count):
    """The count unjudged passages with the lowest sha256(docid).

    A bounded heap keeps only count rows in memory, so a corpus of tens of
    millions of passages streams through without being held whole.
    """
    if count <= 0:
        return []
    lowest = heapq.nsmallest(count, unjudged_rows(paths, wanted))
    return [(docid, title, text) for _, docid, title, text in lowest]


def write_split(root, dirname, topics, qrels, passages):
    """Write topics.tsv, qrels.txt and passages.jsonl; return their sha256."""
    directory = os.path.join(root, dirname)
    os.makedirs(directory, exist_ok=True)
    outputs = {}
    topics_path = os.path.join(directory, "topics.tsv")
    with open(topics_path, "w", encoding="utf-8") as handle:
        for qid in sorted(topics):
            handle.write(f"{qid}\t{topics[qid]}\n")
    outputs["topics.tsv"] = sha256_file(topics_path)
    qrels_path = os.path.join(directory, "qrels.txt")
    with open(qrels_path, "w", encoding="utf-8") as handle:
        for qid, docid, grade in sorted(qrels):
            handle.write(f"{qid} Q0 {docid} {grade}\n")
    outputs["qrels.txt"] = sha256_file(qrels_path)
    passages_path = os.path.join(directory, "passages.jsonl")
    with open(passages_path, "w", encoding="utf-8") as handle:
        for docid, title, text in sorted(passages):
            handle.write(json.dumps({"docid": docid, "title": title, "text": text}) + "\n")
    outputs["passages.jsonl"] = sha256_file(passages_path)
    return outputs


def fetch_miracl(root, entry, corpus_repo, corpus_rev, language, split, fill_count):
    """Fetch one MIRACL split; return its manifest row."""
    lang = entry["languages"][language]
    topics_file = lang["topics"][split]
    qrels_file = lang["qrels"][split]
    topics_path = verified(entry["repo_id"], topics_file["file"], entry["revision"], topics_file["sha256"])
    qrels_path = verified(entry["repo_id"], qrels_file["file"], entry["revision"], qrels_file["sha256"])
    topics = read_topics(topics_path)
    qrels = read_qrels(qrels_path)
    kept = {qid for qid, _, grade in qrels if grade >= 1}
    wanted = {docid for qid, docid, _ in qrels if qid in kept}
    shard_paths = [verified(corpus_repo, shard["file"], corpus_rev, shard["sha256"]) for shard in lang["corpus"]]
    texts, missing = stream_corpus(shard_paths, wanted)
    if missing:
        sample = ", ".join(missing[:5])
        raise ValueError(f"{len(missing)} judged passages missing from the corpus: {sample}")
    passages = [(docid, texts[docid][0], texts[docid][1]) for docid in wanted]
    passages.extend(fill_candidates(shard_paths, wanted, fill_count))
    dirname = f"miracl-{language}-{split}"
    outputs = write_split(root, dirname, topics, qrels, passages)
    return {
        "collection": "miracl",
        "language": language,
        "split": split,
        "time": lang["time"],
        "topics": f"{dirname}/topics.tsv",
        "topics_sha256": outputs["topics.tsv"],
        "qrels": f"{dirname}/qrels.txt",
        "qrels_sha256": outputs["qrels.txt"],
        "passages": f"{dirname}/passages.jsonl",
        "passages_sha256": outputs["passages.jsonl"],
    }


def fetch_mr_tydi(root, entry, corpus_repo, corpus_rev, language, fill_count, fallback_time):
    """Fetch one Mr.TyDi test split; return its manifest row."""
    lang = entry["languages"][language]
    test_file = lang["test"]
    test_path = verified(entry["repo_id"], test_file["file"], entry["revision"], test_file["sha256"])
    topics = {}
    qrels = []
    with gzip.open(test_path, "rt", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            qid = str(row["query_id"])
            topics[qid] = row["query"]
            for passage in row.get("positive_passages", []):
                qrels.append((qid, passage["docid"], 1))
    wanted = {docid for _, docid, _ in qrels}
    shard_paths = [verified(corpus_repo, shard["file"], corpus_rev, shard["sha256"]) for shard in lang["corpus"]]
    texts, missing = stream_corpus(shard_paths, wanted)
    if missing:
        sample = ", ".join(missing[:5])
        raise ValueError(f"{len(missing)} judged passages missing from the corpus: {sample}")
    passages = [(docid, texts[docid][0], texts[docid][1]) for docid in wanted]
    passages.extend(fill_candidates(shard_paths, wanted, fill_count))
    if fill_count <= 0:
        print("note: mr-tydi test has positives only; convert it with --fill-seed/--fill-per-corpus")
    dirname = f"mr-tydi-{language}-test"
    outputs = write_split(root, dirname, topics, qrels, passages)
    return {
        "collection": "mr-tydi",
        "language": language,
        "split": "test",
        "time": lang["time"] or fallback_time,
        "topics": f"{dirname}/topics.tsv",
        "topics_sha256": outputs["topics.tsv"],
        "qrels": f"{dirname}/qrels.txt",
        "qrels_sha256": outputs["qrels.txt"],
        "passages": f"{dirname}/passages.jsonl",
        "passages_sha256": outputs["passages.jsonl"],
    }


def main(argv=None):
    """Fetch the pinned collections into a data root outside every worktree."""
    parser = argparse.ArgumentParser(description="fetch the pinned TREC collections")
    parser.add_argument("--data-root", required=True, help="output directory (outside every worktree)")
    parser.add_argument("--sources", required=True, help="sources.v1.json with pins and sha256")
    parser.add_argument("--languages", required=True, help="comma list, e.g. ja,ko,zh,th,id,en")
    parser.add_argument("--fill-candidates", type=int, default=0, help="unjudged fill passages per split (default 0)")
    parser.add_argument("--pack-id", default="retrieval-matrix", help="pack id for the manifest")
    parser.add_argument("--revision", default="r1", help="pack revision for the manifest")
    parser.add_argument("--time", default=None, help="split time where sources carry none (Mr.TyDi)")
    args = parser.parse_args(argv)
    if args.fill_candidates < 0:
        return bad_input("--fill-candidates must be 0 or more")
    if args.time is not None and not check_time(args.time):
        return bad_input("--time must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        with open(args.sources, encoding="utf-8") as handle:
            sources = json.load(handle)
    except (OSError, ValueError) as error:
        return bad_input(f"sources read failed: {error}")
    if sources.get("contract") != "oneiron.trec_sources.v1":
        return bad_input("sources file has the wrong contract")
    languages = [code.strip() for code in args.languages.split(",") if code.strip()]
    if not languages:
        return bad_input("--languages names no language")
    collections = sources.get("collections", {})
    miracl = collections.get("miracl", {})
    mr_tydi = collections.get("mr-tydi", {})
    for code in languages:
        if code not in miracl.get("languages", {}):
            return bad_input(f"unknown miracl language: {code}")
    try:
        os.makedirs(args.data_root, exist_ok=True)
    except OSError as error:
        return fail(f"data root create failed: {error}")
    try:
        rows = []
        for code in languages:
            for split in ("train", "dev"):
                rows.append(fetch_miracl(args.data_root, miracl, miracl["corpus_repo_id"], miracl["corpus_revision"], code, split, args.fill_candidates))
            if code == "zh":
                print("note: Mr.TyDi has no Chinese; zh gets no sealed split")
                continue
            if code not in mr_tydi.get("languages", {}):
                return bad_input(f"unknown mr-tydi language: {code}")
            if mr_tydi["languages"][code].get("time") is None and args.time is None:
                return bad_input(f"mr-tydi {code} has no dump time in sources; pass --time")
            rows.append(fetch_mr_tydi(args.data_root, mr_tydi, mr_tydi["corpus_repo_id"], mr_tydi["corpus_revision"], code, args.fill_candidates, args.time))
    except ValueError as error:
        return fail(str(error))
    except OSError as error:
        return fail(f"write failed: {error}")
    manifest = {
        "contract": "oneiron.trec_collection_manifest.v1",
        "pack_id": args.pack_id,
        "revision": args.revision,
        "dataset": "MIRACL + Mr.TyDi",
        "license": "Apache-2.0 (annotations); passage text: Wikipedia (CC BY-SA)",
        "splits": rows,
    }
    try:
        with open(os.path.join(args.data_root, "manifest.json"), "w", encoding="utf-8") as handle:
            json.dump(manifest, handle, indent=2)
            handle.write("\n")
    except OSError as error:
        return fail(f"manifest write failed: {error}")
    print(f"wrote {len(rows)} splits to {args.data_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
