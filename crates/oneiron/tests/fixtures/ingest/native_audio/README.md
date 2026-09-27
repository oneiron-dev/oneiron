# Native meeting-audio proof

This is public synthetic speech, not a speaker-identity or multilingual benchmark.
`manifest.json` binds the shipped files and records hashes for intermediate files
that were intentionally omitted. The exact native environment/model and script
revision are recorded there. The producer did **not** produce a transcript artifact:
forced word alignment and community-1 were unavailable. Do not treat text-only ASR
or chunk timestamps as labelled words.

Reproduce manually with an already installed native interpreter, ffmpeg and the
cached Qwen snapshot, using `scripts/proofs/meeting_audio_native.py --help`.
Never invoke the UV script launcher or download/install models during this proof.
The harness uses macOS Fred speech synthesis and writes only inside its supplied
workspace. The recorded proof predates bounded process-timeout hardening; its
script hash remains the exact revision that generated these results.

## Packaged adapter fixture decode (ONE-2090)

`public-speech.pcm16.zlib` is retained 16 kHz mono s16le PCM (190,218 samples,
SHA-256 `5e0f5f5721d8b79cfc91fe0fa0cc67dc37b495eec93c2706d02940dc9527cb8d`)
from ffmpeg 8.1.1 decoding this exact public mp4 on Linux. The earlier Mac
proof's PCM hash differs, so the adapter acceptance test binds this retained
PCM and exact source MP4 hash rather than claiming cross-host PCM identity.
The test-only `scripts/meeting-audio-adapter/fixture-host.py` checks source
hash and decompressed PCM hash and returns **fixture** provenance for *every*
model port. It exercises the encoded-file → command bridge → producer → saved
artifact → consumer normalization → bulk-consent handoff path without needing
models or ffmpeg installed on each remote Cargo worker. It is not a live
ffmpeg/model-quality run; real qualification remains separate.
