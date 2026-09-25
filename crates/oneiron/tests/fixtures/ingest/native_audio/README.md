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
