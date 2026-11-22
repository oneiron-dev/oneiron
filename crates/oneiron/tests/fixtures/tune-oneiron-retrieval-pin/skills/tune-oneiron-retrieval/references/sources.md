# Outside practice, with sources

What the field has found about the knobs this skill tunes. Each line names a source a reader can open. All links returned HTTP 200 on 2026-10-08. Use these as priors and as plausible ranges. The vault's own held-out runs decide.

## Hybrid fusion

- Reciprocal rank fusion sums 1/(k + rank) over lists; the original paper fixed k = 60. Cormack, Clarke and Buettcher, SIGIR 2009. https://cormack.uwaterloo.ca/cormacksigir09-rrf.pdf
- A convex mix of normalized lexical and dense scores beat RRF in and out of domain, and tuning its one weight needed few labelled queries. Bruch, Gai and Ingber, 2023. https://arxiv.org/abs/2210.11934
- Z-score normalization misbehaves with few results or outliers; OpenSearch defaults to min-max. https://docs.opensearch.org/latest/search-plugins/search-pipelines/normalization-processor/
- Qdrant advises RRF when no evaluation set exists, and weighted fusion once one does. https://qdrant.tech/documentation/search/hybrid-queries/

For Oneiron: the engine fuses by summing per-channel z-scores, then blends in log space; ARCH-0004 retired RRF as the source of truth. Z-scores on a channel with one or two hits are noise, and the engine zeroes a list with no variance. Watch fusion on short candidate lists.

## BM25 and BM25F

- Experiments suggest 0.5 < b < 0.8 and 1.2 < k1 < 2 work in many collections. Robertson and Zaragoza, 2009. https://www.staff.city.ac.uk/~sbrp622/papers/foundations_bm25_review.pdf
- Lucene's defaults are k1 = 1.2 and b = 0.75. https://lucene.apache.org/core/10_3_2/core/org/apache/lucene/search/similarities/BM25Similarity.html
- Most experiments find the best b in 0.3 to 0.9 and the best k1 in 0.5 to 2.0. Short, focused documents favour a lower k1, and lower b helps where length means detail rather than drift. Elastic, 2018. https://www.elastic.co/blog/practical-bm25-part-3-considerations-for-picking-b-and-k1-in-elasticsearch
- BM25 variants showed no significant effectiveness differences across eight variants and three collections. Kamphuis et al., ECIR 2020. https://link.springer.com/content/pdf/10.1007/978-3-030-45442-5_4.pdf
- BM25F weights term frequencies per field before saturation; summing per-field BM25 scores breaks saturation. Robertson, Zaragoza and Taylor, CIKM 2004. https://ir.webis.de/anthology/publications/rec+conf+cikm+RobertsonZT04

For Oneiron: k1 is pinned at 1.2. Memories are short and similar in length, so b matters less than for web pages. Test b on the Surface channel in 0.3 to 0.9, one step of about 0.1 at a time. Leave NormalizedOverlay at b = 0; it carries no length norm by design.

## Vector index (HNSW)

- M sets graph links, efConstruction build quality, and ef search-time recall; there is a trade-off, not an optimum. Malkov and Yashunin, 2018. https://arxiv.org/abs/1603.09320
- hnswlib calls M = 12 to 48 fine for most uses, and 48 to 64 for high recall on high-dimensional data. https://github.com/nmslib/hnswlib/blob/master/ALGO_PARAMS.md
- pgvector defaults to m = 16, ef_construction = 64 and ef_search = 40; a higher ef_search raises recall and costs speed. https://github.com/pgvector/pgvector
- In one Lucene throughput study on BEIR, flat (exact) and HNSW indexes differed negligibly below 100K documents, under that study's settings and hardware. Exact search is also the recall oracle for ANN. Lin, ACL 2025 Industry. https://aclanthology.org/2025.acl-industry.61/
- Filters can cut ANN recall; measure filtered and unfiltered recall apart. Qdrant, 2023. https://qdrant.tech/benchmarks/filtered-search-intro/

For Oneiron: the engine's defaults (m_max_0 64, ef_construction 200, ef_search 128) already sit at the high-recall end. Tune ef_search first, because it is search-time only. Compare incumbent and candidate settings against brute force on the same corpus and queries; the stock `oneiron-bench vector` run pins its own settings. Several scope filters run after the blend, so filtered recall is the number that matters.

## Japanese and other CJK text

- Kuromoji is dictionary-based morphology; its search mode also emits compound parts. https://www.elastic.co/docs/reference/elasticsearch/plugins/analysis-kuromoji-tokenizer
- The CJK bigram filter matches by character pairs, with unigrams off by default. https://www.elastic.co/docs/reference/text-analysis/analysis-cjk-bigram-tokenfilter
- Sudachi offers three split sizes (A, B, C); short splits help partial matches, long ones keep compounds. https://github.com/WorksApplications/Sudachi

For Oneiron: with a dictionary, the engine indexes Sudachi mode A, a mode C overlay, kana folding and bigrams together (ARCH-0031). Without one, it falls back to n-grams. Morphology and n-grams complement each other, so judge the CjkNgram weight on the Japanese set, not on English.

## Abstention

- Selective answering abstains below a confidence threshold; pick the threshold for coverage at a target accuracy on held-out data. Cole et al., EMNLP 2023. https://aclanthology.org/2023.emnlp-main.35.pdf
- Retrieving on every turn can add unhelpful passages; SELF-RAG retrieves on demand. Asai et al., ICLR 2024. https://proceedings.iclr.cc/paper_files/paper/2024/file/25f7be9694d7b32d5cc670927b8091e1-Paper-Conference.pdf
- Adaptive-RAG routes questions by complexity to no retrieval, one step or several steps. Jeong et al., NAACL 2024. https://aclanthology.org/2024.naacl-long.389/

For Oneiron: set a floor from labelled answerable and unanswerable queries, at a target false-abstention rate. Never set it from eyeballed scores. Cosine floors belong to one embedder.

## Judging a change from logs

- Replay evaluation keeps the logged events where the new policy picks the logged arm. The simple match-only replay is unbiased when the logger picked arms uniformly at random. A known non-uniform random logger needs a rejection-sampling or propensity correction, and the evaluated actions must have been possible. Li, Chu, Langford and Wang, WSDM 2011. https://arxiv.org/abs/1003.5956
- Inverse propensity and doubly robust estimators need the logged probability of each action; doubly robust usually has lower variance. Wang, Agarwal and Dudík, ICML 2017. https://proceedings.mlr.press/v70/wang17a/wang17a.pdf
- Thompson sampling is competitive with UCB and a sound default. Chapelle and Li, NeurIPS 2011. https://proceedings.neurips.cc/paper/2011/file/e53a0a2978c28872a4505bdb51db06dc-Paper.pdf
- Linear Thompson sampling has a near-optimal regret bound. Agrawal and Goyal, ICML 2013. https://proceedings.mlr.press/v28/agrawal13.pdf
- Interleaving and multileaving compare rankers with less data than A/B tests. Schuth et al., CIKM 2014. https://anneschuth.nl/assets/schuthcikm14.pdf

For Oneiron: once the bandit runs, it should log each run's action probability. Without it, replay of a new arm set cannot be corrected for the bandit's own choices. When arms change, carry a prior only where the arm's meaning and the reward's scale did not change. The prior-carry rule is engineering judgment, not a theorem.

## Machines tuning databases

- GPTuner reads manuals to pick knobs and ranges, then runs Bayesian search. It reports 16 times less tuning time and up to 30% better results than the best baseline on PostgreSQL and MySQL. VLDB 2024. https://arxiv.org/html/2311.03157v2
- λ-Tune has a model write whole configurations from the workload and tests a few. 2025. https://arxiv.org/abs/2411.03500
- DB-BERT reads manuals for hints and tries them with reinforcement learning; it found the best settings among the methods compared on TPC-C and TPC-H. Trummer, 2022. https://arxiv.org/abs/2112.10925
- PostgreSQL's shipped config aims at compatibility, not speed. https://wiki.postgresql.org/wiki/Tuning_Your_PostgreSQL_Server

For Oneiron: borrow the workflow, not the percentages. Start from documented ranges, pick the knob the receipts implicate, search coarse then fine, and let measurement decide. These papers compare against other tuners, so they give no general share of an expert's gain.
