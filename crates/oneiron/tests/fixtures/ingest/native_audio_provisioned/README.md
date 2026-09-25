# Provisioned native smoke evidence (not E1/E3 qualification)

These receipts record completed local model execution, not just imported SDKs.

- `english-asr-aligner-*`: retained public synthetic Fred MP4 → Qwen ASR in the
  unchanged MLX runtime → Qwen forced alignment in its isolated interpreter.
  21 word intervals. Original ASR text/case/punctuation survives; the ASR said
  “a blue notebook” where the synthesis reference says “the blue notebook”.
  This is not a zero-WER claim or a default-selection act.
- `uk-ctc-*`: installed Lesya `uk_UA` TTS → actual Ukrainian Wav2Vec2 emissions
  → CTC traceback in the isolated UK interpreter. 9 word intervals, no Russian
  substitution. The Ukrainian ASR lane of Qwen remains explicitly unsupported.
- `moss-*`: the same complete Fred file → one registered-SDK-only MOSS decode.
  These are speaker-cluster segment times, not word times or named identities.

All inputs are synthetic, with no private human speech. No labelled word-time
truth, consented meeting cohort or speaker enrollment was supplied. Therefore
these receipts cannot qualify model accuracy, community1, cleanup, E1/E3, the
full meeting artifact pipeline, bulk import, or an authenticated default choice.
`summary.json` and `jev.jsonl` explicitly record that boundary. Failed setup and
native attempts remain in `target/w7-validation`, not silently relabelled passes.

English/MOSS source: `../native_audio/public-speech.mp4`, SHA256
`0401d5626fa0a5e6401da721f62479033358d9b3dc2db6a19c889913d4c0d089`.
UK reference text is in its summary and the generated recording is `ukrainian.aiff`.
Exact immutable snapshots and per-file hashes come from the owner's provisioning
manifest; no model files or environments are copied into the engine repository.

Each output has actual code/profile/audio hashes. UK was executed before the
later English-punctuation and MOSS-only changes to the shared runtime helper;
its unchanged CTC implementation hash is in the receipt. Do not claim that older
trace executes the later shared-helper bytes. The retained native-audio directory
is likewise historical and is not overwritten by these newer runs.

## Japanese refusal, not a hidden pass

`japanese-refused-*` is an additional installed Kyoko synthetic Japanese run.
Qwen forced alignment returns `を` with start=end=4.0 seconds. The production
adapter rejects this as `InvalidAlignmentOutput`; it does not stretch, interpolate,
merge away or drop the token to fabricate a positive interval. A direct native
**diagnostic** captured the raw intervals in `japanese-raw-diagnostic.json`; it
bypasses output validation only for inspection and is not an accepted alignment.
The input is `japanese.aiff`. A deterministic regression pins the zero-time refusal.
This is further evidence that supported-language metadata and the successful
English smoke are not Japanese timing qualification. A qualified timed route
still needs actual reference evaluation; these failed timings cannot select it.
