# Scorer conformance result

This is a deterministic scorer fixture, not measured model accuracy and not a
native-scale BEAM run. Four 0.5 judgments exercise all four wedge buckets.
The official int-cast result is 0.0. The fixed float-clamped side result is 0.5.

Generated from clean source commit `273d7cdde9b09a4dc89667dcb12a01d59ffe83b9`
using the project's previously built native `target/debug/oneiron-bench` binary:

```
target/debug/oneiron-bench beam score-nuggets .w7/nugget-proof.json
```

`replay.json` preserves that input. `.w7/nugget-proof.log` is the local command
receipt. The scored code is the same `nuggets.rs` covered by the green scoped
BEAM scorer test. No model call or provider cost is claimed by this artifact.
