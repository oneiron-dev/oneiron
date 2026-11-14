# The retrieval matrix: MIRACL, Mr.TyDi and the BM25F rank profile (ONE-318)

This page runs the retrieval-quality matrix end to end: fetch the pinned
collections, convert them to pack slices, grade a matched Lucene baseline,
tune the BM25F rank profile on the search slice, judge the candidate on
held_out against the incumbent with the Lucene gap as a report, run the
one sealed check, and stamp the proposal. The frozen profile lands in a
later PR after the owner's stamp.

## Languages and slices

Target, by canon: `ja`, `ko`, `zh`. SEA, from public sets: `th`, `id`
(ruling L8-38-SEA = A; `km`, `lo`, `my` and `vi` have no judgment set and
show as such in the report, with one FIX-LIST row for an internal set
built from real data later). Stem guard: `en` (the Stem channel only
fires on Latin text).

Slices: MIRACL `train` becomes `search` (tuning), MIRACL `dev` becomes
`held_out` (judgment, the split the published MIRACL baselines use), and
Mr.TyDi `test` becomes `sealed` (opened once). Mr.TyDi has no Chinese:
`zh` gets no sealed split.

## 1. Fetch

A booked `fleet run` (Python plus `huggingface_hub`), with the data root
outside every worktree (RESEARCH-0651 section 6: held_out and sealed stay
out of the repo and of any worktree):

```sh
python3 scripts/bench/fetch_trec_collections.py \
    --data-root <data-root> \
    --sources crates/oneiron-bench/fixtures/retrieval_matrix/sources.v1.json \
    --languages ja,ko,zh,th,id,en \
    --fill-candidates 2000 \
    --time 2021-08-01T00:00:00Z
```

The script downloads each pinned file at its pinned revision, checks LFS
sha256 (MIRACL topics and qrels are small plain files with no LFS hash;
they are recorded as `null` and downloaded unverified), streams the
corpus shards keeping only wanted docids, and writes per split
`topics.tsv`, `qrels.txt` and `passages.jsonl` plus one `manifest.json`.
`--time` applies only where sources carry no dump time (Mr.TyDi, whose
dump date is unstated upstream; the value above is the paper month and is
recorded in the manifest). Mr.TyDi test rows carry positive docids only,
so their text comes from the corpus stream, and the split has positives
only: keep `--fill-candidates` at 1 or more.

## 2. Convert

```sh
oneiron-bench scorecard convert-trec \
    --manifest <data-root>/manifest.json \
    --out-dir <data-root>/packs \
    --fill-seed 318 --fill-per-corpus 1000
```

`--fill-seed` and `--fill-per-corpus` come as a pair (both or neither)
and map to the converter's seeded fill; Mr.TyDi test needs them.

## 3. The Lucene baseline, graded by the same ruler

A booked `fleet run` (Python with `pyserini==1.6.0`, Java 21). The script
indexes the same pack slice's records per corpus and searches each
query at BM25 k1 0.9, b 0.4, top 100:

```sh
python3 scripts/bench/pyserini_matched_baseline.py \
    --pack-dir <data-root>/packs \
    --slice held_out --out <data-root>/lucene.held_out.run \
    --work-dir <data-root>/pyserini-work
oneiron-bench scorecard grade-run \
    --pack-dir <data-root>/packs \
    --slice held_out --run <data-root>/lucene.held_out.run \
    --retriever pyserini-bm25 --engine-commit <sha> \
    --out <data-root>/lucene.held_out.json \
    --budget-rows 100
```

`grade-run` refuses the sealed slice: a reference run file is graded on
`search` or `held_out` only.

## 4. Tune on search

The objective is the dictionary arm (ruling L8-38-DICTS = A); the
no-dictionary arm is a Floor (no regression beyond the paired
bootstrap's interval against the starting profile):

```sh
oneiron-bench scorecard tune-bm25f \
    --pack-dir <data-root>/packs \
    --slice search --start <profile-or-default> \
    --out <data-root>/tuned.profile.json \
    --steps-out <data-root>/tuned.steps.json \
    --engine-commit <sha> --dict-dir <dicts> \
    --budget-rows 100 --max-rounds 3
```

The tuner runs coordinate ascent over the Stem, NormalizedOverlay and
CjkNgram weights and the Surface, Stem and CjkNgram length norms; the
surface weight (the anchor), the overlay length norm (inert under
`NoNorm`), the formula and k1 stay fixed. It reads only the search
slice and refuses any other. Rerun without `--dict-dir` for the Floor
arm.

## 5. Judge on held_out

Run the incumbent (the starting profile) and the candidate (the tuned
profile) on held_out with `scorecard run --arm keyword`, then compare
with the Lucene scorecard as the reference report:

```sh
oneiron-bench scorecard run --arm keyword \
    --pack-dir <data-root>/packs --slice held_out \
    --rank-profile <incumbent-or-default> --dict-dir <dicts> \
    --budget-rows 100 --engine-commit <sha> \
    --out <data-root>/incumbent.held_out.json
oneiron-bench scorecard run --arm keyword \
    --pack-dir <data-root>/packs --slice held_out \
    --rank-profile <data-root>/tuned.profile.json \
    --dict-dir <dicts> --budget-rows 100 --engine-commit <sha> \
    --out <data-root>/candidate.held_out.json
oneiron-bench scorecard compare --campaign <campaign> \
    --reference <data-root>/lucene.held_out.json \
    --candidate-profile <data-root>/tuned.profile.json \
    --proposals <proposals> --at <unix-seconds> \
    <incumbent> <candidate>
```

Judgment follows the ruler: dominance, then the paired-bootstrap lower
bound above 0 on the Primary axes, then the ruler-path check; the
incumbent and the candidate must come from the same retriever. The
reference never changes the verdict: the 90 % of Lucene gap per
language and metric is a report (ruling L8-38-TARGET = A), and each
language under it gets a FIX-LIST row for analyser work.

## 6. The one sealed run, the proposal, the stamp

One sealed run per side (the claim is spent before the slice opens),
then the sealed check, then the owner's stamp:

```sh
oneiron-bench scorecard run --arm keyword \
    --pack-dir <data-root>/packs --slice sealed \
    --rank-profile <profile> --dict-dir <dicts> \
    --engine-commit <sha> --out <sealed.json> \
    --sealed-ledger <ledger> --campaign <campaign> \
    --proposal <id> --proposals <proposals>
oneiron-bench scorecard compare --sealed --campaign <campaign> \
    --proposals <proposals> --proposal <id> --at <unix-seconds> \
    <incumbent-sealed> <candidate-sealed>
oneiron-bench scorecard stamp --proposals <proposals> \
    --proposal <id> --at <unix-seconds> --note <text>
```

The stamp prints no pin call for a rank-profile proposal: BM25F weights
are compiled defaults, and the stamp's effect is the freeze PR's merge,
which applies the stamped profile. Open that PR only after the stamp
exists.
