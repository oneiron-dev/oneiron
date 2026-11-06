# oneiron-macos — menu-bar recorder

A macOS menu-bar app that records the microphone and the audio other apps are
playing, cuts it into one-minute segments, and lands each segment in a local
Oneiron vault as ASSET bytes plus one `voice.segment` claim.

The engine is embedded **in-process** (path dependency on `crates/oneiron`):
this Mac is a vault device node, not a client of one. The recorder declares no
home-node candidacy and starts no home workers. It leaves any declaration from
another serving lifecycle unchanged. Replication rides the existing device-sync
path and puts nothing new on the wire.

The app shares its already-open device vault with the server's ordinary
paired-device sync connection. It reads the same resolved `[device_sync]`
configuration and enrollment files as `oneiron serve`, and dials the home at
its configured URL (`wss`, or loopback `ws`). It starts no HTTP server, mesh
listener, model worker or Dreamer. The section's `always_on` and `primary`
flags remain serving-host settings; this recorder never declares its own
home candidacy. With no configured or enrolled home it keeps recording locally;
a sync configuration or connection failure is logged without blocking capture. The device vault's preset, platform keystore and
host-root profile selection are unchanged.

On every final app exit, capture stops and flushes its last local segment
before the sync connection, credential renewal and removal-archive receiver
are stopped and joined. This guarantees local landing, not remote delivery
before exit: the normal durable sync path carries pending writes on reconnect.

## Shape

- `src-tauri/src/disclosure.rs` — the gate. A capture exists only downstream of
  a `CapturePermit`, which only an affirm can produce and which starting a
  capture consumes.
- `src-tauri/src/capture/` — the microphone leg (`cpal`), the far-end leg
  (Core Audio process tap, macOS 14.2+), output-route detection, and the
  segment cutter that latches route at each boundary.
- `src-tauri/src/vault_sink.rs` — ASSET bytes plus the `voice.segment` claim.
- `src-tauri/src/session.rs` — the state both surfaces render from.
- `src-tauri/ui/` — the window, as plain HTML/CSS/JS. There is no node build
  chain and there should not be one.

## Features

- default (MIN-SPEC, runs on Intel): capture plus vault landing. No
  transcription surface at all.
- `asr-mlx`: compiles in the `SegmentTranscriber` seam and its external-tool
  adapter. Transcripts land at the Imported trust tier.

Echo cancellation ships as *awareness*, not cancellation: v1 links no canceller,
so a speaker-route segment with real far-end audio records `unavailable` rather
than claiming a cancellation nobody ran. Capture is never blocked by it.

## What a shipping build still needs

This tree builds the app; it does not produce a signed bundle. A hardware pass
must add, at minimum:

- `NSMicrophoneUsageDescription` and `NSAudioCaptureUsageDescription` in the
  bundle's `Info.plist` — without them macOS refuses both legs;
- a signing identity and bundle icons, and `bundle.active` turned on in
  `tauri.conf.json`.
