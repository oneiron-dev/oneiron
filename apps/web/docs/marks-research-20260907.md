# Attribute marks · where they come from (research, 2026-09-07)

Owner asked whether an open-source Greek / classical symbol library exists (an enthusiast's
repo), or whether we generate our own marks. Two grok legs, X first then the web.

## Verdict

- **No cohesive open-source Greek or mythology icon family exists.** GitHub topics (greek,
  mythology, classics, icons, svg) surface brand-logo sets, a deity knowledge graph and a
  meander generator, nothing drawn as a set.
- **X designers recommend no pack.** The classical work they praised in 2024–2026 is custom:
  the Hades Olympian attribute marks inside meander rings, and M35's Olympus identity that
  turns artefacts into cut-out graphics. Marketplace god packs and hand-painted RPG icons read
  as clip-art to them.
- **Route: draw our own.** One attribute per agent, one stroke weight, solid silhouette, one
  drawing per size. Reference pool only: Wikimedia and OpenClipart singletons (caduceus,
  laurel, vase silhouettes) and the Hades marks for the register.

## Closest things found

| what | where | licence | why it does not ship |
|---|---|---|---|
| Game Icons, Greek & Roman tag (69 of 4,180) | game-icons.net/tags/greek-roman.html · github.com/game-icons/icons | CC BY 3.0 | solid and legible at 16, but a game HUD look; owner passed |
| Woodcutter "Greek Mythology" dingbat (236 slots) | dafont.com/greek-mythology.font | "100% free", TTF only | linocut heads, the right register for portraits, unusable at 16 |
| Wikimedia Commons singletons | Caduceus.svg (PD) · laurel wreath (CC0) | per file | authentic drawings to trace, not a set |
| OpenClipart / FreeSVG / publicdomainvectors | freesvg.org · publicdomainvectors.org | CC0 | only free source with vase-painting silhouettes; quality uneven |
| Noto Sans Symbols / Symbols 2 | github.com/notofonts/symbols | OFL | a few Unicode deity glyphs (☿ ☤ ⚴ ⚶), thin, read as astrology; Apple fonts lack ⚴ ⚶ |
| bingqiao/meander | github.com/bingqiao/meander | MIT | generates the key pattern as a border; a meander is trim, never a 16 px icon |

Paid or account-walled and not praised anywhere: IconScout, Noun Project, Envato Mycogen,
Icons8, Streamline, Creative Fabrica, Font Awesome Pro caduceus. Figma Community has no
dedicated free set.

## What "cool" means to designers on X

Abstracted artefacts, attribute marks, inscriptional type, meander as a border. Filled Zeus,
Parthenon and Corinthian-column packs are dated. Getty's own note: the meander is a border
element.

---

## Raw leg 1 · open-source sets (grok, web + GitHub)

I'll search GitHub, npm, Figma, Wikimedia, and the web in parallel for free Greek/mythology icon sets, then rank what actually exists.Promising leads: Woodcutter’s dingbat font, Wikimedia SVGs, and IconScout’s 45-icon pack. Next I’ll check Game-icons, OpenClipart, and GitHub more tightly.**There is no cohesive open-source Greek/mythology icon family.** Marketplace line packs exist; GitHub has almost nothing on-topic. What exists is a game-HUD silhouette library, a woodcut dingbat, scattered public-domain clipart, and Unicode/Noto symbols.

---

## Sets found

### 1. Game Icons — Greek & Roman tag
- **URL:** [game-icons.net/tags/greek-roman.html](https://game-icons.net/tags/greek-roman.html) · GitHub [game-icons/icons](https://github.com/game-icons/icons)
- **License:** CC BY 3.0 (a few contributors CC0). Attribution required.
- **Style:** Solid white-on-black silhouettes (TF2 / Dungeon Keeper HUD), not vase-painting or linocut.
- **Count:** **69** tagged Greek/Roman of **4,180+** in the library.
- **Motifs:** caduceus, trident, crested/Spartan helmets, temple, lyre, owl, thunderbolt, laurel, amphora, labyrinth, torch, plus creatures (minotaur, hydra, pegasus, medusa, cerberus). No meander, no red-figure, no stamp heads, no aegis as a named mark.
- **16 px:** **Yes** — drawn for inventory grids.
- **npm/Figma:** not an npm icon package; SVGs on GitHub. No official Figma community file.

This is the only real *icon set* that is free, vector, and motif-complete.

### 2. Woodcutter — “Greek Mythology” dingbat
- **URL:** [dafont.com/greek-mythology.font](https://www.dafont.com/greek-mythology.font)
- **License:** Author note “100% Free” (DaFont label, **not** OSI). Other Woodcutter fonts are personal-use-only — this one is the free-tagged one. No GitHub, no SVG sources.
- **Style:** Linocut / woodcut / stamp-style classical figures and heads. Closest match to “classics enthusiast publishes a dingbat.”
- **Count:** **236** font slots (typical dingbat padding; unique motifs likely ~50–90).
- **16 px:** **No** — too much hatch and portrait detail.
- **Use:** TTF only. Trace to SVG if you need paths.

### 3. Wikimedia Commons — per-file SVGs (not a pack)
- **URLs:**
  - [Caduceus.svg](https://commons.wikimedia.org/wiki/File:Caduceus.svg) — public domain
  - [Caduceus simple.svg](https://commons.wikimedia.org/wiki/File:Caduceus_simple.svg) — CC BY-SA 3.0
  - [Laurel wreath (CC0)](https://commons.wikimedia.org/wiki/File:Greek_Roman_Laurel_wreath_with_branches_vector.svg)
  - [Category:Greek mythology](https://commons.wikimedia.org/wiki/Category:Greek_mythology) — mixed art/photos, not glyphs
  - [Noto alchemical caduceus U+1F750](https://commons.wikimedia.org/wiki/File:NotoSans_-_Alchemical_Symbol_For_Caduceus_-_1F750_-_gGByzW.svg)
- **License:** per file (PD / CC0 / CC BY-SA).
- **Style:** Heraldic engraving, not a unified stroke weight.
- **Count:** dozens of useful marks, not a designed set.
- **16 px:** simple caduceus **yes**; wreaths and statues **no**.

Best source for *authentic* attribute drawings to trace, not a kit.

### 4. OpenClipart / FreeSVG / Public Domain Vectors
- **URLs:** [freesvg.org](https://freesvg.org) (e.g. [Greek vase](https://freesvg.org/greek-vase), caduceus) · [publicdomainvectors.org greek myth](https://publicdomainvectors.org/en/free-greek-myth-clipart) (~456 hits)
- **License:** CC0 / public domain.
- **Style:** Dump: black-figure-ish vase silhouettes, statue drawings, stained-glass, cartoons. Quality wildly uneven.
- **Count:** hundreds of *files*, zero design system.
- **16 px:** vase and Pegasus/Sisyphus silhouettes **yes**; everything else **no**.
- **Motifs present:** amphora/vase silhouettes, lyre, column, caduceus, Rod of Asclepius, Pegasus, some deity line drawings. Not a family.

This is the only free source that actually has **vase-painting silhouettes**.

### 5. Noto Sans Symbols / Symbols 2
- **URL:** [github.com/notofonts/symbols](https://github.com/notofonts/symbols)
- **License:** SIL OFL 1.1
- **Style:** Typographic Unicode glyphs (alchemical caduceus, thunderbolt-adjacent, miscellaneous symbols). Not mythology illustration.
- **Count:** ~1,100 + ~2,900 glyphs; **a handful** are classically relevant (☤ U+2624, ⚕ U+2695, ⚡, 🔱 live in other Unicode blocks).
- **16 px:** **Yes** as font glyphs.

A symbol font, not a motif set.

### 6. greek-meander (pattern generator, not icons)
- **URL:** [github.com/bingqiao/meander](https://github.com/bingqiao/meander) (Rust, `cargo install greek-meander`) · older Python `greek_meander` on PyPI
- **License:** MIT
- **Style:** Stroke Greek-key / meander borders as SVG/PNG.
- **Count:** generator, not a glyph inventory.
- **16 px:** as a **border**, yes if you thicken the stroke; as a 16 px *icon*, a meander needs several units and usually fails.

Only OSS answer for **meander/key patterns**.

---

## Found but not usable as open icon sets

| Name | URL | Why it fails |
|---|---|---|
| IconScout “Greek Mythology” packs | [45 line icons](https://iconscout.com/icon-pack/greek-mythology-icon-pack_86470), [50 line](https://iconscout.com/icon-pack/greek-mythology-1) | Marketplace “free” with account/attribution; thin **line** (16 px **no**); not OSS |
| Noun Project Maxicons | [45-icon set](https://thenounproject.com/browse/collection-icon/greek-mythology-167325/) | Paid / Creator Pro |
| Envato Mycogen pack | [Ancient Greece and Mythology Icons](https://elements.envato.com/ancient-greece-and-mythology-icons-TW59XLQ) | Paid. Motif list is actually good (caduceus, lyre, trident, helmet, olive, laurel, fire, maze) |
| Icons8 search | [ancient-greek-mythology](https://icons8.com/icons/set/ancient-greek-mythology) | Generic UI; free = attribution + link, not a redistributable pack |
| SVG Repo “Greek” | [svgrepo.com/vectors/greek](https://www.svgrepo.com/vectors/greek/) | ~50 mixed tourist-Greece cliparts (columns, Parthenon, helmets); per-file licenses |
| Streamline “ancient greek” | [streamlinehq.com](https://www.streamlinehq.com/icons/tag/ancient-greek) | Commercial library, 984 tagged across styles |
| Creative Fabrica SVG art | [ancient-greek-mythology-svg-art](https://www.creativefabrica.com/product/ancient-greek-mythology-svg-art/) | $0 marketplace, not OSS; small line-art pack |
| Font Awesome | caduceus is **Pro** (`fa-caduceus`) | Not free; not a classical set |
| npm `project-greek-mythology-icons` | ecosyste.ms listing | Tutorial *starter* for an SVG library, not mythology artwork |
| Figma Community | search: greek mythology / ancient greek | **No dedicated free icon pack found.** Closest: “Orpheus” portfolio UI kit ([CC BY 4.0](https://ui4free.com/uikit/orpheus---designer-portfolio-greek-avatars-figma-ui-kit.htm)) — avatars, not attributes |

GitHub topics (`greek`, `mythology`, `classics`, `icons`, `svg`) did not surface a classics icon repo. Hits were brand-logo sets, a deity knowledge-graph, and the meander generator.

---

## Ranked shortlist (at most 5)

1. **Game Icons (Greek/Roman tag)** — only shippable 16 px solid set; CC BY 3.0; game-y, not classical.
2. **Wikimedia + OpenClipart/CC0** — authentic caduceus, wreath, vase silhouettes to **trace**; not a set.
3. **Woodcutter Greek Mythology dingbat** — linocut heads, informal “100% free”; TTF, unusable at 16 px.
4. **Noto Symbols (OFL)** — a few Unicode marks, not motifs.
5. **bingqiao/meander (MIT)** — generate the key pattern; not icons.

---

**Verdict:** Nothing good enough to adopt as a family. Cherry-pick Game Icons for 16 px solids (helmet, trident, caduceus, lyre, owl, bolt) and trace Wikimedia/OpenClipart for vase silhouettes; **draw your own marks** for a classics-enthusiast language (attributes + meander + black-figure + stamp heads as one weight).

---

## Raw leg 2 · X recommendations (grok)

I'll search X first for designer recommendations of Greek/classical icon sets, then confirm any promising URLs on the web.X results were noisy; I’ll tighten queries around Figma/Noun Project sets and the Olympus identity case, then confirm URLs on the web.**Short answer:** On X, product designers almost never recommend an off-the-shelf “Greek gods” icon pack for UI. The conversation is thin, noisy (Orthodox religious icons, slot assets, jewelry), and the only work that actually got design-community praise in 2024–2026 is **custom identity**, not a downloadable glyph library.

---

### What showed up on X (and what it actually was)

**1. M35 identity for Olympus (Sydney restaurant) — the one designers actually liked**  
- **What:** Custom brand system that turns classical Greek artefacts/sculptural forms into playful cut-out graphics, anchored by a circle (tholos), inscriptional type (Mercure), and a Greek-coastline blue. Not a UI icon set.  
- **URLs:** [The Brand Identity case](https://the-brandidentity.com/project/m35-recontextualises-greek-artefacts-as-playful-graphics-for-olympus) · [M35 project](https://www.m35.com.au/projects/olympus)  
- **Who:** [@TweetsByTBI](https://x.com/TweetsByTBI) (The Brand Identity), Dec 2025, ~491 likes / 217 bookmarks; also [@logodesawards](https://x.com/logodesawards) (Jan 2026).  
- **Why they liked it:** “Recontextualises Greek artefacts as playful graphics” — classical without being reverential, museum-gift-shop, or clip-art.  
- **Free/open:** No. Commissioned identity (Apollo Group / M35).

**2. LudicArts “Ancient Greek Icon Set” — praised only by the seller; game-y**  
- **What:** Hand-painted RPG-style icons (helmets, gods, artefacts).  
- **Who:** [@ludicarts](https://x.com/ludicarts) (Jul 2023), self-promo to `#gamedev`.  
- **Why they liked it:** “High quality, hand-painted.” That is exactly the look product-UI people usually reject.  
- **Free/open:** Paid game-asset pack.

**3. Map Effects Greek map-icon pack (in progress, not a product-UI library)**  
- **What:** Compass, ship, jar frames for historical/mythology maps.  
- **Who:** [@MapEffects](https://x.com/MapEffects) (Nov 2025).  
- **Why:** Useful for cartography/worldbuilding, not app chrome.  
- **Free/open:** Unclear / forthcoming commercial tool assets.

**4. Meander (Greek key) as ornament — designers treat it as a border, not an icon**  
- **What:** Canonical Greek fret. [@GettyMuseum](https://x.com/GettyMuseum) (Jul 2026) noted it is “normally a border element,” and called a huge white meander on a vase “odd.”  
- **Why that matters:** The tasteful use is trim/pattern (Hades merch, jewelry, architecture), not a 24px nav glyph.  
- **Free/open:** The motif is public-domain; specific SVGs vary.

**5. SuperGiant *Hades* Olympian marks + meander (product example, not a pack)**  
- **What:** God symbols set in meander circles (2026 merch lining).  
- **Who:** [@SuperGroupiesUS](https://x.com/SuperGroupiesUS).  
- **URL:** [Zagreus wallet](https://us.super-groupies.com/products/zagreus-model-long-wallet-hades)  
- **Why it lands:** Attribute-based marks (not cartoon Zeus), consistent line, meander as frame. This is the closest “it actually looks good” Greek-god iconography in a shipped product — and it is **custom game art**, not a Figma kit.  
- **Free/open:** No.

**What did *not* appear:** No designer thread recommending a Figma Community “Greek gods” kit, Noun Project collection, Streamline mythology set, or meander SVG library as a product-UI system. When UI people on X list icon sets they actually use ([@AdhamDannaway](https://x.com/AdhamDannaway): Lucide, Iconoir, Remix, Tabler, Phosphor; [@hemeon](https://x.com/hemeon): Phosphor), they are **general UI sets**, not classical ones.

---

### Web confirmation of packs (sold everywhere; **not** praised on X)

These exist and match the search queries. None of them were recommended by named product designers on X in this pass:

| Pack | URL | License | Notes |
|---|---|---|---|
| SVG Repo “Greek” dump | https://www.svgrepo.com/vectors/greek/ | mostly free (per-file) | Temples, columns, helmets, letters. Uneven, clip-art-heavy. Raw material only. |
| IconScout Greek Mythology (45 glyphs) | https://iconscout.com/icon-pack/greek-mythology-icon-pack_86469 | marketplace / “free download” w/ account | Glyph style; typical stock. |
| 84 Mythology Monsters & Creatures | https://designtemplateplace.com/product/84-ancient-greek-mythology-monsters-and-336202 | paid | SVG/AI/IconJar; gods + monsters + Greek alphabet. Edu/game. |
| 50 Ancient Greece Icons (Dighital) | https://dighital.com/icon-pack/icons/flat-icons/50-ancient-greece-icons/ | $10 | “UI/UX” marketing copy; Parthenon/column/laurel set. |
| Design Bundles Ancient Greece | https://designbundles.net/mahesagraphic/5530927-ancient-greece-icon-pack | $7 | Same stock vocabulary. |
| Wikimedia Greek-letter SVGs | e.g. https://commons.wikimedia.org/wiki/File:Greek_uc_phi_icon.svg | open | Actual usable **glyphs** (α–ω / Α–Ω), not gods. |

---

### Praised product / brand uses of classical iconography (2024–2026)

1. **Olympus restaurant × M35 (2025)** — the clear design-press winner: artefacts as graphics, not god clip-art. [@TweetsByTBI](https://x.com/TweetsByTBI).  
2. **Hades visual language (still circulating 2026)** — Olympian attributes + meander, not portraits.  
3. **Arknights Endfield / Alleikhreos (Gamescom 2026)** — [@SoloChronicle](https://x.com/SoloChronicle): Foundite look drawn from **ancient Greek sculpture**, not icon packs. Tasteful because it is form/material, not a Zeus sticker.

No 2024–2026 SaaS/app UI on X was held up as “they nailed Greek-god icons in the product chrome.”

---

### Ranked shortlist (≤5) if you actually need marks for a product UI

1. **Don’t buy a god-portrait pack.** Do what M35 did: 6–12 custom attributes (owl, thunderbolt, trident, lyre, aegis, meander frame) drawn in *your* stroke. That is what designers treat as cool.  
2. **Wikimedia / Unicode Greek letters** — the only open, non-clip-art glyph set that consistently looks like design rather than a game HUD.  
3. **Meander as pattern, never as a 24px icon** — Getty’s own note; Hades uses it as lining/frame.  
4. **Hades-style attribute marks** as a reference (custom; not licensable as a UI kit).  
5. **SVG Repo / IconScout only as scrap** — steal a column silhouette, then redraw. Shipping those files as a system reads stock.

**Verdict:** Designers treat **abstracted artefacts, attributes, inscriptional type, and meander-as-border** as cool; **filled Zeus / Parthenon / Corinthian-column marketplace packs and hand-painted RPG icons** as dated clip-art.
