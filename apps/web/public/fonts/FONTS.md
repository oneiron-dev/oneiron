# Bundled app fonts

These are unmodified WOFF2 bytes fetched on2026-09-19 from the exact Google Fonts
CSS request that the app previously imported:

`https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,opsz,wght@0,8..60,400..600;1,8..60,400..600&family=Barlow:wght@400;500&display=swap`

- Source Serif4: Google Fonts v14; variable optical size8–60 and weight400–600,
  normal and italic. All6 supplied Unicode subsets retained for each style.
- Barlow: Google Fonts v13; normal400 and500. All3 supplied Unicode subsets
  retained for each weight.
- `src/styles/fonts.css` preserves Google's family, style, weight range,
  display:swap and unicode-range declarations, changing only URLs to local files.
- Original URLs, file sizes and SHA-256 hashes: `google-fonts-manifest.json`.
- Licenses: `source-serif-4/OFL.txt`, `barlow/OFL.txt`. These are the upstream
  SIL Open Font License1.1 notices, copied unmodified from google/fonts.

No font glyphs, metadata, weight/style choices, family names or app design tokens
were edited. Local loading lets the packaged app work offline with the existing
restrictive CSP. Existing Departure Mono and Server Mono files are unchanged.
