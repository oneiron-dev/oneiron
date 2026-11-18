---
name: tune-oneiron-retrieval
description: Read a vault's retrieval receipts and propose one evidence-backed change to how the vault retrieves, scored on held-out past runs before it ships. The slow retrieval loop reads this skill at sleep. The bandit tunes inside the effort envelope, and this skill never fights it.
version: 0.1.0
license: Apache-2.0
role: knowledge
metadata:
  author: oneiron-dev
  contact: contact@oneiron.dev
  requires: the engine's retrieval telemetry (ONEIRON-ARCH-0037), the one bandit and the skill-improvement loop (ONEIRON-ARCH-0053 §5 and §10a)
  checked-against: oneiron origin/main 0fdfe222c, 2026-10-08
  seeded-from: ONEIRON-ARCH-0004, ARCH-0031, ARCH-0037, ARCH-0042, ARCH-0053, RESEARCH-0651, and the outside sources in references/sources.md
  data: references/knobs.md, references/records.md, references/sources.md
  engine-gaps: NOTES.md
---

# Tune Oneiron retrieval

You are the slow loop for retrieval. You wake at sleep with one vault's retrieval receipts. You find one repeated failure, trace it to one knob, and propose one change. Replay on held-out past runs scores the change before it ships. You write a proposal. You never write a live value.

## Two loops, one skill

Retrieval is a skill (ARCH-0037). Its numbers are that skill's parameters. Two things move them, and only two.

| | the bandit (fast) | you (slow) |
|---|---|---|
| owner | ARCH-0053 §5 | the skill-improvement loop, ARCH-0037 and ARCH-0053 §10a |
| when | picks per run; learns at sleep | at sleep, once enough new receipts exist |
| moves | which arm runs, inside the effort envelope | the script, the arm set, the envelope's edges, the seeds and ranges of parameters |
| evidence | the shaped reward of each run | replay on held-out past runs |
| never | leaves the envelope | sets a value the bandit is learning |

You shape the space. The bandit searches it. When a parameter is learned, you may change its seed, its range or its learner's settings, with evidence. You never write its live value.

### What runs today

This page was checked against engine commit `0fdfe222c`. [NOTES.md](NOTES.md) lists each gap as engine work.

- One part learns today: the blend-weight table. At birth it holds recency 0.35, salience 0.30, confidence 0.20 and gravity 0.15. A reward-weighted tuner moves it one step per explicit call. Nothing calls it on a schedule yet.
- The Thompson bandit, its arms, the effort-envelope check, the seeded script and a retrieval replay executor are canon, not code yet.
- Gated outcomes, the only reward the learner trusts, come from the bench's outcome ingest today. No Dreamer job writes them yet.
- Most other numbers are compiled constants or host settings. The skill-improvement loop today edits a skill's description text only.
- So most proposals today are recommendations to the owner, a re-seed of the learner's settings, or a named piece of engine work. Say which one in the receipt.

## First lesson: the ruler before the knob

- No trusted score, no change. A proposal without held-out evidence is a note, not a change.
- The defaults are priors. Once the vault holds enough receipts, they outrank this page.
- Enough, as a seed: about 200 published runs with gated outcomes over at least 7 days, and at least 30 of them in the slice you change. Below that, propose what collects more evidence, never a number. The loop revises this seed from its own receipts.
- Telemetry capture is off by default, and the default retention keeps 7 days or 1024 runs. A vault that needs tuning needs capture on and a longer window first. Both are host settings. Recommend them.
- Most failures are not knob failures. Check the host inputs first: no query embedding, pending vectors, a missing Japanese dictionary, an index frontier that has not caught up.

## Read the record before this page

1. Pins and seeds the owner set. Never override a pin. Propose a change to it instead.
2. The vault's receipts: runs, gated outcomes, traces, and the blend table with its data window. [references/records.md](references/records.md) says how to read them.
3. The shipped defaults in [references/knobs.md](references/knobs.md).
4. This page.

## The knobs

[references/knobs.md](references/knobs.md) lists every knob with its code location, default, range in code, a safe range, and who may change it. In short:

| area | knobs and defaults | who changes it |
|---|---|---|
| Effort | graph depth light 0, medium 1, high 2, xhigh 4, max 10; rerank top 30, or 50 at xhigh and max; a budget lease from high up | the caller picks the level; the bandit picks inside it; you propose the envelope's edges |
| Lexical | BM25F weight and b per channel: Surface 1.00 and 0.75, Stem 0.35 and 0.65, NormalizedOverlay 0.55 and 0, CjkNgram 0.45 and 0.30; k1 1.2, pinned | skill parameter by design; today a per-query rank profile the host passes |
| Analyzer | Japanese, Chinese and Korean dictionaries; without one, character n-grams (portable mode) | host setting: recommend |
| Vectors | ef_search 128; m_max_0 64 and ef_construction 200 at build; fast_dims unset | host setting: recommend; build settings need a rebuild |
| Fusion and blend | each channel z-scored, then summed as relevance; relevance log weight 1.0; the four blend weights; a recency half-life per entity type | weights: the learner; half-lives: skill parameter by design, compiled today |
| Graph | PPR damping 0.15; recall seeds 8; a λ budget per edge kind, with the five world-model budgets pinned; part_of capped at 2 hops; VAD alpha 0, at most 0.4; community beta 0 | λ and damping: skill parameter by design, compiled today; VAD and community: host setting behind a BEAM gate |
| Temporal | sigma 1 day; minimum window 7 days; 3 widening rounds; score floor 0.05 | skill parameter by design, compiled today |
| Budgets | 20 results; 4000 tokens; split 0.45 claims, 0.10 turns, 0.25 summaries, 0.20 other | the caller sets the size; the split is a skill parameter by design |
| Abstention | dual-weak rule: no keyword hit and every cosine under 0.3; gap rule: top cosine under 0.5 and gap ratio under 0.1; anomalous query text | a floor; change only by proposal with the owner's stamp |

Three interactions matter most:

- Cosine floors belong to one embedder. A model swap moves every cosine score. Re-derive the abstention floors after a swap. Never carry them over.
- Depth costs twice. Hops add latency, and the reward subtracts hops directly. A deeper walk must win more gated hits than it loses in cost.
- The blend sees only what the channels found. A missing channel cannot be fixed by reweighting the blend.

[references/knobs.md](references/knobs.md) has the rest.

## Symptoms, causes, changes

Read the symptom from the records. Check the causes in order. Make the smallest change.

| symptom, and how you see it | likely causes, in order | change |
|---|---|---|
| Many empty packs: `empty_reason` set or no `result_ids` | 1. The vector channel never ran: `Vector` is missing from `signals`. The host passed no query embedding, or the vectors are still pending. 2. A Japanese query ran on character n-grams only. 3. The abstention floors came from another embedder. 4. The vault truly lacks the fact. | 1 and 2: recommend the host fix. 3: re-derive the floors on replay from this embedder's scores. 4: change nothing; abstaining is right. A gated hit in another run of the same turn only flags a possible false abstention. Confirm it with a label for that query and scope. |
| Slow p95: `elapsed_us` by effort, `retrieval_latency_baseline` | 1. Deep walks at xhigh and max. 2. Rerank of the top 50. 3. A HyDE retry ran the stores a second time, with wider limits. 4. PPR cache misses after many edge writes. 5. Many callers at once. | 1 and 2: propose a narrower envelope edge for the slice where deep walks add no gated hits. 3: count retries first. 4 and 5: recommend. Never tune retrieval for host load. |
| Stale hits: an old claim ranks above the newer one that replaced it | 1. Nothing marked the old claim superseded. A superseded, retracted or expired claim already scores 0 at read time. 2. The half-life is too long for that entity type or claim class. 3. The recency weight is low; check the blend table's data window. 4. The index frontier is behind. | 1: recommend the write-path fix; it is not a retrieval knob. 2: propose a half-life for that one type or class. 3: never set the weight; if the learner's data is thin, propose collecting more outcomes. 4: recommend the idle-delay row. |
| Japanese misses: Japanese turns whose runs have no `Text` signal or no gated hits | 1. No Sudachi dictionary, so character n-grams only. 2. Kana and kanji spellings, or honorifics, of one name. 3. Mixed-script queries. | 1: recommend installing the dictionary. A mode flip fails closed; the host clears the text index with `clear_text_index` and re-indexes. 2 and 3: propose the CjkNgram or NormalizedOverlay weight for the Japanese slice, judged on oneiron-ja-memory. |
| Names missed: people, handles, misheard words | 1. No phonetic codes were passed. 2. The stemmer split a name. 3. The Surface weight is low against Stem. | 1: recommend the host pass codes. 2 and 3: propose the Stem weight down or the Surface weight up, judged on name queries. |
| One event's many records fill the pack | No event-level diversity step exists. The default-off community selection does not de-duplicate events. | Engine work (NOTES.md). Do not fake it with a smaller limit, and do not switch on the community prior yourself. |
| Time questions miss: "last March" finds nothing | 1. The host parsed no window, or rejected the phrase. 2. The window is too tight: sigma 1 day, 3 rounds. | 1: recommend. 2: propose sigma or rounds for time-bearing queries. |
| Rewards look random | Few gated outcomes; one evaluator; several runs per turn sharing one outcome. | Do not tune. Propose collecting outcomes. |

## Judge a change before it ships

1. **One change per proposal.** One knob, one slice, one direction.
2. **Split before you look.** Split by a hash of the turn id, so a turn's runs stay together. Draft and iterate on the dev slice. Hold out about one turn in five for admission. Never read held-out outcomes while you draft, and never iterate on them. Keep the split fixed across proposals. RESEARCH-0651 also keeps a sealed slice for one final measurement of the chosen candidate per promotion.
3. **Replay.** Run the incumbent and the candidate on the same held-out runs, with the same clock and corpus snapshot (`replay_inputs`). The engine has no retrieval replay yet. Until it does, use the weaker rulers and name the one you used:
   - Re-rank stored candidates. A blend-weight change can be re-scored from each run's stored blend components with the effective, normalized weights. This only reorders what the run surfaced. It cannot find what the run missed. It cannot test a half-life change either: the records keep z-scores, not ages.
   - The bench. Run oneiron-bench on the public packs and on oneiron-ja-memory, on a fresh vault, at one engine commit.
4. **Score.**
   - The shaped reward: gate × hit − cost_weight × (latency_norm + hops). Only gated end outcomes count. A raw outcome reward is telemetry, not a label.
   - Recall at the token budget, and nDCG@10, where labels exist.
   - Abstention errors on labelled answerable and unanswerable queries.
   - p50 and p95 latency, on the same machine under the same load.
   - Run the incumbent twice first. The gap between those two runs is the noise floor.
5. **Admit by dominance with floors** (ARCH-0053 §10a). The owner's goal record names the axes. The candidate must beat the incumbent on at least one axis, cost included, by more than the noise floor, and lose on none. A cheaper or faster candidate of equal quality is admitted. A tie rejects. A tradeoff escalates. On held-out runs, a paired bootstrap's 95% interval for the improved axis must sit above zero.
   - Floors: abstention false positives under 5%; zero scope leaks; zero control rows in recall; the same pack for the same inputs.
   - Kill lines from ARCH-0037, each over two eval batches: pass rate down more than 1.0 point; recall@15 down more than 1.0 point; p50 or p95 up more than 30%; Expand firing outside 10 to 30% of runs. The last one cannot be measured until policy verbs are logged (NOTES.md).
6. **Keep the bandit's prior.** An arm you did not change keeps its posterior. A changed arm starts from its old posterior as a weak prior, origin `carried`, with a weight in runs. Never reset the whole posterior. Never write it yourself.
7. **Land a Proposed revision with its receipt.** The incumbent stays until admission passes. A host setting or a floor needs the owner's stamp.

## Never

- Fight the bandit inside its envelope. Never set the live value of a learned parameter, pin an arm per query, or narrow the envelope to force an arm. Narrow an edge only when replay shows the arm never pays in that slice.
- Change the records: the run row, the outcome row, the trace, the fields of `RetrievalState`, the keys or the schema version. They are the replay corpus. A new field is engine work.
- Write query text anywhere. The run record is query-free by design.
- Keep a copy of the parameters as a config row. There is no `retrieval_policies` table.
- Widen a Grant, a budget lease, a scope or a floor. Control rows never reach recall.
- Tune on held-out runs. Special-case words from the vault. Use the count-only BEAM scorer as a quality signal.
- Change a host setting yourself: the HNSW build, the embedder, the dictionaries, capture, retention, the map size. Recommend it with evidence.
- Ship two changes in one proposal.

## The vault's other knobs

None of these is a retrieval skill parameter the loop may tune by itself today. Recommend changes with evidence.

| knob | default | kind |
|---|---|---|
| HNSW build: m_max_0, ef_construction, fast_dims | 64, 200, unset | host setting; a change needs `rebuild_hnsw` or a new vault |
| HNSW ef_search | 128 | host setting; search time only, so a skill parameter by design |
| Text-index dictionaries (`dict_search_paths`) | none, so character n-grams | host setting; a mode flip needs `clear_text_index` |
| Embedding model and transform | unset until the first vector | host setting; a swap re-embeds the vault |
| Embedding queue | priorities 0 to 3, no tuning knob | engine; nothing to tune |
| PPR cache TTL | 24 h, 72 h or 168 h by seed age | engine constant |
| PPR community prior | beta 0 | host setting behind a BEAM gate |
| Telemetry capture | off | host setting; turn it on before tuning |
| Telemetry retention | 7 days or 1024 runs | gate manifest rows; widen before tuning |
| Index maintenance: `rebuild_hnsw`, `compact_postings`, `cleanup_ppr_cache` | the host schedules them | host verbs |
| Context compaction (`MemoryProfile`) | 4000-token window | the agent's record, not retrieval |
| Dreamer wake policy | wake every turn; nightly every 86400 s; quiet weave after 3600 s | the Dreamer's own recipes |
| Fold thresholds | none exist in the engine | nothing to tune |

## The receipt

Every proposal carries:

- the knob, the slice, the change from and to, and one line on why;
- the symptom, with the run counts and the time window that show it;
- the ruler you used (replay, re-rank of stored candidates, or the bench), the engine commit, the held-out count and its digest;
- the scores before and after, the noise floor and the interval;
- what happens to the bandit's prior;
- anything that is a host setting or engine work, by name;
- the rollback: the incumbent stays until admission passes.

## You slip here

- Lowering the abstention floors because packs are empty, when the vector channel never ran.
- Tuning the four blend weights by hand. The learner owns them.
- Calling a latency win from one run.
- Carrying cosine floors across an embedder swap.
- Raising depth for recall and ignoring the hops cost.
- Treating a raw outcome reward as a label.
- Tuning retrieval for host load.
- Following this page over a slice with real runs.
