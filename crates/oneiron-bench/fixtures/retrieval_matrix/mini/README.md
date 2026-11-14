# retrieval-matrix-mini: a synthetic three-slice pack for the bench tests

39 passages, 13 queries, 13 corpora (one query per corpus). All text is
synthetic, written for this fixture, and public-safe (CC0-1.0). Every
passage title is empty, so each record embeds exactly its passage text;
title joining is covered by the ruler's `trec_collection` tests instead.
Every query has one relevant passage (grade 1) and judged negatives
(grade 0), so `convert-trec` needs no fill. All splits share the time
`2022-10-01T00:00:00Z`.

Layout: `manifest.json` (the `convert-trec` format) plus one directory per
split with `topics.tsv`, `qrels.txt` and `passages.jsonl`. Query ids are
`<corpus>:q1`, record ids `<corpus>:<article>#<n>`, where `<corpus>` is
`<collection>-<language>-<split>` (for example `miracl-ja-train`).

## What each query is for

Search slice (`miracl`, `train`):

| corpus | query | relevant | negatives | purpose |
|---|---|---|---|---|
| miracl-ja-train | `桜祭` | `sakura#0` `桜祭京都` | `sakura#1` `桜 祭 桜 祭`, `sakura#2` `梅雨奈良` | the tuner flip: at `cjk_ngram.weight` 0 the distractor outranks the relevant (nDCG 1/log2(3)); any grid weight from 0.25 up flips it to rank 1 |
| miracl-ko-train | `한글` | `hangul#0` `한글공부` | `hangul#1` `바다`, `hangul#2` `산책로` | only-hit rank 1 at every profile |
| miracl-zh-train | `北京` | `beijing#0` `北京大学` | `beijing#1` `上海`, `beijing#2` `广州塔` | only-hit rank 1 at every profile |
| miracl-th-train | `แมว` | `cat#0` `แมว` | `cat#1` `น้ำ`, `cat#2` `ข้าว` | query and relevant are the same string, so they analyse identically whatever the Thai segmenter does; rank 1 at every profile |
| miracl-en-train | `harbour crossing` | `harbour#0` `harbour crossing at dawn` | `harbour#1` `grocery list market`, `harbour#2` `quiet meadow evening` | content words only; rank 1 at every profile |

Held-out slice (`miracl`, `dev`):

| corpus | query | relevant | negatives | purpose |
|---|---|---|---|---|
| miracl-ja-dev | `東京` | `tokyo#0` `東京大学` | `tokyo#1` `大阪城`, `tokyo#2` `富士山` | only-hit rank 1 |
| miracl-ko-dev | `독립` | `sejong#0` `세종대왕` | `sejong#1` `바다`, `sejong#2` `산` | no shared token with anything: nDCG 0, recall 0 |
| miracl-zh-dev | `上海` | `shanghai#0` `上海中心` | `shanghai#1` `北京`, `shanghai#2` `广州` | only-hit rank 1 |
| miracl-th-dev | `ข้าว` | `rice#0` `ข้าว` | `rice#1` `แมว`, `rice#2` `น้ำ` | identical-string rank 1 |
| miracl-en-dev | `lantern festival` | `lantern#0` `lantern festival evening`, `lantern#1` `mountain snowfall silence` | `lantern#2` `grocery market list` | two relevant passages, one sharing tokens and one not: recall 0.5, nDCG 1/(1+1/log2(3)) |

Sealed slice (`mr-tydi`, `test`): `ja` (`京都` / `京都御所`, negatives
`奈良`, `大阪`), `ko` (`바다` / `바다풍경`, negatives `한글`, `산책`),
`th` (`น้ำ` identical, negatives `แมว`, `ข้าว`). All only-hit rank 1.

## Why the numbers hold without dictionaries

With no `--dict-dir`, Japanese, Chinese and Korean all run the portable
`cjk_ngram` path: one Surface token per character plus one CjkNgram token
per adjacent character pair, never crossing a script run. Thai runs ICU
word segmentation (Surface only); English runs word segmentation with
Surface plus Snowball Stem overlays. Nothing drops stopwords, and the
query side analyses the same way as the index side.

- CJK only-hit corpora: the query's characters appear only in the
  relevant passage (padding and negatives use disjoint characters), so
  the relevant passage is the only document with a query term and the
  only hit: rank 1 at any profile.
- The ja-train flip: the query `桜祭` yields terms `桜`, `祭` (df 2,
  idf ln(1.6)) and `桜祭` (df 1, idf ln(8/3)). The relevant passage has
  each unigram once plus the bigram; the spaced distractor has each
  unigram twice and no bigrams (single-character runs emit none). At
  `cjk_ngram.weight` 0 the distractor's term-frequency advantage wins
  (score about 1.29 vs 0.94 with the start length norms); from grid
  weight 0.25 up the bigram contribution flips the relevant to rank 1
  (at the default 0.45 the gap is about 0.24). Computed from the exact
  BM25F in `crates/oneiron/src/bm25/scoring.rs`.
- A query found *only* through CjkNgram (no hit at weight 0) is
  impossible with the portable analyser: a shared bigram always implies
  shared unigrams, which always score. The flip above is the closest
  robust design: CjkNgram decides the ranking while Surface gives hits.
- Thai identical-string corpora: query and relevant are byte-identical,
  so they emit identical tokens under any segmentation; the negatives
  are different words.
- English corpora: every non-query word (and its Snowball stem) differs
  from every query word and stem, so the relevant passage is the only
  hit. The last query word always has a posting, so the final-token
  prefix expansion never fires. The ko-dev query shares no character
  with any passage, so it has no hit at any profile.
- The en-dev query finds only `lantern#0` at rank 1: recall is 1/2, and
  nDCG@10 is 1/(1+1/log2(3)) = 0.6131471927654584 (DCG 1, ideal
  1+1/log2(3), grade 1). One corpus holds one query, so no query ever
  sees another query's passages.

## Hand counts the tests assert

Search slice, keyword arm, compiled default (test 4): every category
`ndcg_at_10` 1.0 and `recall_at_budget` 1.0 (`miracl-ja`, `miracl-ko`,
`miracl-zh`, `miracl-th`, `miracl-en`).

Tuner (test 5) from `cjk-ngram-weight-0.profile.json`: the start macro
nDCG is (1/log2(3)+4)/5 = 0.9261859507142916 (the ja query ranks its
relevant second: 1/log2(3) = 0.6309297535714575); the best is 1.0, and
the best `cjk_ngram.weight` is above 0.

Held-out reference report (test 6), candidate `stem.weight` 0.5 vs the
`lucene.held_out.run` reference (the th query is absent from the run
file, so its reference run is empty):

| category | ours nDCG / recall | reference nDCG / recall | ratio | mean difference | lower bound |
|---|---|---|---|---|---|
| miracl-ja | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 / 1.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| miracl-ko | 0.0 / 0.0 | 1.0 / 1.0 | 0.0 / 0.0 | -1.0 / -1.0 | -1.0 / -1.0 |
| miracl-zh | 1.0 / 1.0 | 1.0 / 1.0 | 1.0 / 1.0 | 0.0 / 0.0 | 0.0 / 0.0 |
| miracl-th | 1.0 / 1.0 | 0.0 / 0.0 | null / null | 1.0 / 1.0 | 1.0 / 1.0 |
| miracl-en | 0.6131471927654584 / 0.5 | 1.0 / 1.0 | 0.6131471927654584 / 0.5 | -0.38685280723454163 / -0.5 | same as the difference (one pair) |
| overall | 0.7226294385530917 / 0.7 | 0.8 / 0.8 | 0.9032867981913646 / 0.8749999999999999 | -0.07737056144690832 / -0.1 | reported, not hand-counted |

Single-pair lower bounds equal their difference exactly: every
resample draws the one pair.
