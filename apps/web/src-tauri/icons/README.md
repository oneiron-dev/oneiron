# Native app icons

## Source and provenance

`Oneiron.icon/` is the layered source. The neutral Dark colors are owner-accepted. `logo.svg` preserves the original
Oneiron aperture mark byte-for-byte (SHA-256 in `source.json`). The layered
`Assets/Aperture.svg` uses an exact equivalent even-odd path instead of an SVG
mask for native edge quality. Its geometry is unchanged; Composer centers and
uniformly scales the foreground to 0.7938 in every appearance. The Light/default
background is pure white `#FFFFFF`; Light ink stays `#1A1A1A`. The Dark appearance uses
`#1A1A1A` with `#FFFFFF` ink; only its two appearance-specific fills changed.
Default/tinted fills, scale 0.7938, centering, native tile and material settings
are unchanged. The scale is an approved optical choice, not an Apple requirement.
There are no separately authored mono/Clear values; those treatments are OS-owned.

Stable Xcode 26.5 compiled `Assets.car`: Oneiron.iconstack, 1024 square, two layers,
Aqua/DarkAqua/Tintable appearances. Apple Icon Composer 1.5 (98) also rendered it.
Default/dark/tinted fill specializations must not gain sibling base-fill fields.

`app-icon-light.png` / `app-icon-dark.png` are the 1024px native .icns
fallback exports, used verbatim. They already contain the native mask, outer
padding and rim/shadow. They are flat native-rendered fallbacks, not live Liquid
Glass or FX-off renders. Do not add another mask/inset or substitute full-frame
composer-*.png references. No image generation or logo redesign was used.

## Packaging

- `tauri.macos.conf.json` uses the precompiled **primary** `Assets.car` because the
  installed Tauri CLI 2.11.3 direct .icon actool invocation throws
  `__NSPlaceholderArray ... attempt to insert nil object`. Do not substitute the
  separate dark export-staging catalog.
- `Info.plist` names the modern icon `Oneiron`. The fallback key names
  `OneironLegacy.icns`, copied from `icon.icns`; this keeps B as the legacy icon
  without changing the layered source's default appearance.
- `Oneiron.icns` is the primary compiler fallback retained for provenance.
  `icon.png`, `icon.icns`, `icon.ico` are B format fallbacks generated from the
  owner-accepted native-framed 1024px dark PNG. The converter emits a 512px PNG
  downsample and multi-size ICNS/ICO; no extra mask or inset is applied.
  Windows/Linux keep ordinary fallback formats and native decorations.
- App minimum remains macOS 12.0. A macOS 26 resource compile target does not
  raise the application deployment target.

To regenerate the primary catalog using the installed Apple tools, from repo
root (output directory must exist):

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcrun actool \
  src-tauri/icons/Oneiron.icon --compile /tmp/oneiron-catalog \
  --platform macosx --minimum-deployment-target 26.0 --app-icon Oneiron \
  --standalone-icon-behavior all --output-partial-info-plist /tmp/oneiron-catalog/Info.plist
```

Use `assetutil --info` to verify Oneiron.iconstack and its appearances before
replacing the checked-in catalog. The runtime PNGs must be native .icns exports,
not recomposed previews. Extract with `iconutil --convert iconset`, and use the
native `icon_512x512@2x.png` for each 1024px runtime image. For Dark export only,
copy the source to a separate `OneironDark.icon`, promote its exact dark fills
to defaults, compile separately, and extract its ICNS. Never bundle that staging
catalog. Generate `icon.png` / `icon.icns` / `icon.ico` with project-local
`bunx --no-install tauri icon <native-dark-1024.png> --output <staging-dir>`, then
copy only those fallback files. No second mask, inset or upscaling is needed.

The current owner-accepted receipt is `modern-macos-icon/neutral-dark-preview`. Source and
artifact hashes are in `source.json`. The previous accepted scale receipt remains
at `modern-macos-icon/logo-scale-07938`. Native 1024px plate bounds remain
`[100,100,924,924]`; shadow bounds `[66,74,958,966]`; glyph bounds
`[207,207,816,816]` (609px). Both alpha channels are pixel-identical to the
previous exports. Light/default PNG and primary ICNS are byte-identical. No pixel
inversion, CSS filter, extra mask, inset or custom lighting was applied.
No web favicon or other app art is changed.

## Runtime behavior

On macOS 26+ with the validated catalog available in the actual app bundle,
System passes nil to NSApplication.applicationIconImage. macOS then owns layered
icon rendering and independent icon/widget style choices. Finder is modern and
system-controlled, not fixed B. Light/Dark explicitly override only the running
Dock tile with the two compiled-in PNGs. On older OS/unbundled dev, System keeps
OS-application-light/dark fallback mapping. No icon-cache or OS-setting mutation.
