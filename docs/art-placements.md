# The art in the app — kit and placements (08-15 eve)

Owner: "small little soulful stuff here and there; sometimes a full background."
Rule: an image sits where a picture belongs — empty states, the lost page,
first-run, the agents' faces — never as fill on a working surface. Red stays
scarce: the vermilion sun is for non-working surfaces only.

## The kit (`public/art/`, keyed out of the ratified riso plates)

| file | from | rooms | use |
|---|---|---|---|
| `spot-flock.png` 490×406 α | riso-dayflock | both | the house spot: dreams rising / the queue flown off |
| `spot-sun.png` 286×277 α | riso-dayflock | paper | non-working surfaces only (red scarce) |
| `spot-moon.png` 206×215 α | riso-oneiroi | film | non-working surfaces only; fringes on paper |
| `plate-dayflock.webp` 1400w | riso-dayflock | paper | full-page plate |
| `plate-oneiroi.webp` 1400w | riso-oneiroi (owner's favourite) | film | full-page plate |
| `field-day.png` / `field-night.png` | fleet Bayer fields | per room | the desk plate |

Source plates: `oneiron-ui-exploration/design-explorations/3-safelight/imagegen/`
(also `riso-lighthouse`, `riso-paperbirds`, `riso-daysea`, `_archive/*`).
House dither: `…/imagegen/ditherize.py` (8×8 Bayer, 3px cells). Recipes:
`content/ai-creatives/imagegen-cli.md`. Keying script that made the spots:
`~/.claude/jobs/cb57b445/tmp/spots.py` (paper/night colour → alpha ramp).

The room picks the art: `.art-day` / `.art-night` (display vars), `--plate-img`,
`--field-img` in `safelight.css`.

## Placed (d18e985)

1. **Chat, new chat** — opens EMPTY: the flock, one line, three doors that
   fill the composer. The Hokuei fixture thread is a past chat now (history
   popover → opens it; head shows its title).
2. **Lost page** (not-found · error) — the plate IS the page (dayflock by day,
   oneiroi by night); a small card with `back` · `inbox` / `try again`.
3. **Empty inbox** — the flock + one line above the quiet-line (`?empty`
   previews it; fixtures always fill the inbox).
4. **Desk plate** — the Bayer field behind the desk, opacity `--plate`
   (tuner slider), off by default.

## Proposed, not built (owner picks)

5. **Sign-in / first run** — full plate (like the lost page) + the card.
   The one place a full background is clearly right.
6. **Agents page** — each agent's face: the pixel creatures
   (`oneiron-mocks/mocks/assets/creatures/`, transparent sprites) or riso
   portraits to generate; the same face optional beside the name on the
   agent line (canon: creatures are a setting, marks-only default).
7. **Empty vault** ("no claims yet") — the flock; **empty history**
   ("no chats yet") — a micro moon/sun.
8. **`?` explainer panels** — a small spot per surface (the sorting desk for
   the inbox, the drawer for the vault). Risk: clutter; only if it earns it.
9. **Onboarding / vault mint** — the lighthouse + beam (riso-lighthouse):
   "your vault, lit".
10. **Receipts / night-shift** — a micro moon glyph on night-run rows.
    Risk: the bullet grammar (hollow = proposed) is semantic; a glyph must
    not read as a state.

## To generate (Codex imagegen, only after the owner picks from above)

Spots with alpha, 2–3 flat inks + grain, same plates as the flock:
a lone bird · the lighthouse with its beam · a cloud puff · a card-catalog
drawer (the vault) · an envelope on the wire (channels) · the aperture mark
as a riso stamp. Day + night pair each. Prompt register: imagegen-cli.md
Register B; then `ditherize.py --mode dark|light`.
