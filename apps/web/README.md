# oneiron-web

The Oneiron web surface: the product app (console/workbench) and, later, whatever
else of the website wants to live in code rather than mocks.

- **Framework:** TanStack Start (Vite, TanStack Router, server functions opt-in).
  Chosen 2026-08-14 for interactivity-first defaults; research record in
  `oneiron-mocks` FLOWS.md and the session notes.
- **Design truth:** graduates from `oneiron-mocks` (Safelight system, FLOWS.md
  ruling ledger). The mocks repo stays the annotation bench until parity.
- **Engine frontend:** this app now lives at `apps/web` in the `oneiron` engine
  repo, imported with its full Git history under U1 = A (2026-11-03). The move
  does not change the UI or connect its fixtures to a running engine.

## Run

```bash
bun install
bun run dev
```

## Layout

- `src/styles/safelight.css` — the Safelight token sheet (carried from the mocks).
- `public/fonts/` — bundled Source Serif 4, Barlow, Server Mono and Departure Mono.
- `src/routes/` — TanStack file routes.

## Desktop foundation (macOS)

The desktop app packages the **same routes, art, fonts, sounds, tuner and fixture
interactions** in Tauri 2. It opens at `/app/inbox`. It is not connected to an
engine. Sign-in, vault creation, task activity and receipts shown by the current
UI are still fixtures, not real operations.

Requirements: Bun, Rust 1.96.0 (pinned in `src-tauri/rust-toolchain.toml`), and the
macOS Xcode command-line tools. Install project dependencies with `bun install`.
The project-local Tauri CLI is included; no global CLI install is needed.

```bash
# Existing browser workflow (unchanged)
bun run dev
bun run build

# Desktop development: Tauri starts its own Vite server on 127.0.0.1:1420.
# Check that this port is free first; do not stop someone else's server.
bun run desktop:dev

# Static desktop frontend and typecheck only
bun run build:desktop:frontend

# Focused tests for the app-side runtime boundary
bun test

# Native macOS .app, including a fresh static frontend build
CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR="$PWD/src-tauri/target" bun run desktop:build
```

With the target directory above, the bundle is
`src-tauri/target/release/bundle/macos/Oneiron.app`. It is development/ad-hoc
signed, not notarized. On a host whose selected Xcode beta causes a Rust
proc-macro `E0463` loading error, use the installed stable Xcode for this command
only (do not change the system-wide selection):

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR="$PWD/src-tauri/target" bun run desktop:build
```

Use a fresh project-local target directory if it already contains artifacts
linked by the failing beta toolchain. Do not clean shared build caches.
The current `dev.oneiron.workbench` bundle identifier is for this foundation. Release identity, signing, updates, installers and public
distribution are not configured. Windows/Linux builds have not been validated.

### App-only navigation and previews

- Settings uses the same search/ask Palette as the app (`Cmd/Ctrl+K` or `/`
  outside text fields). Back and Escape return to the last valid app screen in
  this session, including its supported URL state. Escape closes the Palette
  or current Settings layer before leaving.
- Appearance offers an optional Recall scene: **None** (default), **Tidal
  margin**, or **High weather**. The scene follows the app theme and appears
  only before a question. Answers have no scene. The choice is device-local;
  blocked storage keeps it for the current renderer session only.
- Inbox actions settle in place with explicit local outcomes and fixed fixture
  times. Reply fields keep one replaceable, not-sent preview on plain Enter.
  Nothing is sent, granted, resumed, or changed in an engine. These local
  decisions and replies reset when you leave Inbox or reload.
- Inbox title buttons support Enter/Space. Record columns restore focus when
  closed. The existing tuner still offers all three open laws; this pass does
  not resolve that product choice. Edited draft text is not synchronized
  between separate inline and column draft mounts.

### Build and runtime boundaries

- `vite.config.ts` remains the web/Nitro build. `vite.desktop.config.ts` uses
  TanStack Start's SPA mode and emits an `index.html` shell with the same route
  tree. Tauri embeds **only `dist-desktop/client`**. The temporary build-time
  `dist-desktop/server` output is not bundled; no Node server runs in the app.
- Tauri's static host falls back to `index.html` for app routes. This permits
  in-app navigation and reloads on nested paths without a server. OS URL-scheme
  deep links are not registered.
- Each router gets a small immutable `AppRuntime` context. `surface` describes
  the build target, not engine reachability. Both hosts explicitly use
  `dataSource: 'fixtures'` and `engine.status: 'not-configured'`. Future engine
  integration can enter at this context boundary using the existing engine
  client contract. No transport, endpoint registry, credentials or duplicate
  engine SDK is defined here; route fixtures have not been mass-refactored.
- The Rust process owns only the window. It starts no engine, sidecar, daemon,
  service or background task. Closing/quitting the app therefore cannot stop
  an independent engine. No autostart, filesystem or shell permissions are
  granted. The macOS main window can invoke only the built-in drag/titlebar
  double-click operations and the two bounded app-icon preference commands. Keep-awake is intentionally absent: real local task
  lifecycle must own it later, not fixture activity or UI lifetime.
- Existing localStorage keys are preserved. The native origin has its own UI
  preferences; it does not import a browser profile or migrate vault data.
- Native icons use the canonical Oneiron aperture SVG, with the approved light
  and dark ink treatments. Source SVGs and generation notes are in
  `src-tauri/icons/`. No route fixture content or design tokens are changed.
  Desktop adds the Mac-only chrome inset and app-icon setting described below.

### Native chrome

On macOS, the titlebar is a native transparent overlay with its title hidden.
The traffic lights remain real OS controls. A 40px row in the existing desk
material reserves their space, and the whole app moves down together, including
the folded rail and working sheet. The empty row to the right of the controls
handles dragging and the system titlebar double-click behavior. A 6px outer
gutter stays clear for native edge/corner resizing. The fixed tuner, vault menu,
sign-in and error surfaces use the same top clearance. No toolbar actions,
horizontal offsets or imitation window buttons are added.

The native shell injects a document-start CSS marker **only on macOS**. Browser
pages and Windows/Linux receive neither the marker nor its layout insets; those
platforms retain standard native decorations. The Mac capability grants exactly
`core:window:allow-start-dragging` and
`core:window:allow-internal-toggle-maximize` to `main`, with a `macOS` platform
restriction. Real native drag, edge resize, double-click zoom, minimize/restore
and fullscreen were checked on the development Mac. The 40px inset remains in
native fullscreen; this clean top clearance is retained for the foundation.
Other macOS versions and custom OS double-click preferences are not certified.
The drag region uses Tauri's built-in handling. Restored, rendered and dragged
tuner positions are clamped below the Mac inset; browser positioning is unchanged.

Source Serif 4 (normal/italic, weight400–600, optical size8–60) and Barlow
(normal400/500) now load from bundled `/fonts/` files rather than Google Fonts.
The font families, weights/styles, Unicode coverage and design tokens are
unchanged. Upstream SIL OFL licenses and provenance are in `public/fonts/`.
This preserves the app's typography offline without weakening the native CSP.
Unrelated reference/mock HTML pages retain their existing font references.

### App icon appearance (macOS)

Appearance settings has a native-Mac-only **app icon** row:

- **Light** uses the native-rendered ink-on-paper PNG override (A).
- **Dark** uses the native-rendered white-on-neutral-dark PNG override (B).
  The neutral Dark colors are owner-accepted.
- **System** is the default. In a packaged app with the layered catalog on
  macOS 26+, it clears the runtime override and lets macOS render the bundle's
  icon. This follows the OS **icon/widget style**, independently of general
  light/dark appearance and the desk's CSS theme.

The modern bundle/Finder icon is layered and system-controlled, not fixed B.
B remains the PNG/ICNS/ICO legacy fallback. On older macOS or an unbundled dev
executable without the catalog, System keeps the light/dark PNG mapping based on
OS application appearance rather than falling back to a generic executable icon.
Explicit overrides affect the running Dock/app-switcher icon, not Finder.

The choice is reapplied at startup from
`~/Library/Application Support/dev.oneiron.workbench/app-icon-appearance.json`.
No macOS appearance setting or icon cache is changed. The public AppKit
`NSApplication.setApplicationIconImage` API runs on the main thread; nil is used
only when macOS 26+, an actual .app bundle, the expected CFBundleIconName and
Assets.car are present. Exactly two enum-only commands are authorized for the
main Mac window. There are no arbitrary paths/bytes or general native powers.
The setting is hidden in browsers and on Windows/Linux.

`src-tauri/icons/Oneiron.icon` is the canonical layered source. The installed
Tauri CLI's direct .icon invocation hit the actool NSPlaceholderArray bug, so
`tauri.macos.conf.json` uses the validated precompiled primary `Assets.car`.
The app minimum stays macOS 12.0. Source/provenance and regeneration notes are in
`src-tauri/icons/README.md`. The PNG overrides are flat native-rendered fallbacks
with native framing and rim/shadow, not live glass or FX-off renders. They are
used as-is without a second mask or inset. No icon gallery/framework is added.

The CSP allows bundled assets, existing inline styles and Tauri's internal IPC
transport. Renderer permissions are limited to the Mac chrome and icon operations
above. The development policy additionally allows the local Vite HMR connection. A future engine connection needs an explicit
security/auth review; localhost alone is not authority.
