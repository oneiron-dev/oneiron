# Oneiron D2 Diagram Style Guide

Style tokens derived from [oneiron.dev](https://oneiron.dev) landing page.

## Palette

| Token   | Light     | Dark      | Role                          |
|---------|-----------|-----------|-------------------------------|
| accent  | `#E63E2A` | `#E63E2A` | Hero elements, primary action |
| ink     | `#1a1a1a` | `#ffffff` | Text, markers, titles         |
| surface | transparent | transparent | Background (N7) — blends with host page |
| raised  | `#ffffff` | `#1E1E1E` | Elevated surfaces, headers    |
| success | `#4A7C59` | `#6BA87D` | Completion, positive output   |
| muted   | `#6B7280` | `#9CA3AF` | Secondary connections         |
| brown   | `#8B5A2B` | `#C4824D` | Warm secondary accent         |

## Shadows

All non-class nodes use `style.shadow: true` for a consistent "cards on a surface" look.
This applies to architecture, deployment, and any future flow diagrams.

**Storage diagrams** also get shadows, but require manual SVG post-processing because D2
silently ignores `style.shadow` on `shape: class`. See the post-processing section for
the injection steps (filter definition + filter attributes on shape groups).

## Node Styles

**Hero node** (e.g. Vault — the central/important element):
```d2
node: Label {
  style.fill: "#E63E2A"
  style.font-color: "#ffffff"
  style.stroke: "#c4321f"
  style.border-radius: 8
  style.bold: true
  style.shadow: true
}
```

**Standard node** (e.g. search lanes, secondary elements):
```d2
node: Label {
  style.fill: "#F4F0E6"
  style.font-color: "#1a1a1a"
  style.stroke: "#1a1a1a"
  style.border-radius: 8
  style.shadow: true
}
```

**Heavy/convergence node** (e.g. Fusion — endpoint before results):
```d2
node: Label {
  style.fill: "#1a1a1a"
  style.font-color: "#F4F0E6"
  style.stroke: "#1a1a1a"
  style.border-radius: 8
  style.bold: true
  style.shadow: true
}
```

**Text labels** (input/output):
```d2
label: Label {
  shape: text
  style.font-color: "#1a1a1a"   # ink for input
  style.bold: true
}
# or "#4A7C59" (success) for output/results
```

## Storage Diagram Conventions

Storage diagrams use `shape: class` for database category boxes inside a vault container.

### Vault container

```d2
vault: LMDB Environment (18 databases) {
  style.fill: transparent    # no fill — avoids double hatching with sketch overlay
  style.stroke: "#E63E2A"   # accent border defines the container
  style.font-color: "#E63E2A"
  style.bold: true
  grid-columns: 3
  grid-gap: 16
}
```

### Class boxes (light mode)

All headers use cream (`#F4F0E6`) for contrast against the transparent page background.
All titles use `ink` (`#1a1a1a`). Category identity is carried by the body fill (= `style.stroke`).

```d2
core: "Core" {
  shape: class
  style.fill: "#F4F0E6"      # cream — visible header on transparent bg
  style.stroke: "#1a1a1a"   # ink — body fill color
  style.font-color: "#1a1a1a"  # ink — uniform title text
  style.border-radius: 8
  style.font-size: 13
}
```

### Class boxes (dark mode)

All headers use `raised` (`#1E1E1E`), all titles use white (`#ffffff`).
Category identity is carried by the body fill (= `style.stroke`).

```d2
core: "Core" {
  shape: class
  style.fill: "#1E1E1E"     # raised — uniform dark header
  style.stroke: "#ffffff"    # white — body fill color
  style.font-color: "#ffffff"  # white — uniform title text
  style.border-radius: 8
  style.font-size: 13
}
```

### Category stroke colors

| Category | Light stroke | Dark stroke | Notes         |
|----------|-------------|-------------|---------------|
| Core     | `#1a1a1a`   | `#ffffff`   | ink           |
| Vector   | `#E63E2A`   | `#E63E2A`   | accent        |
| Text     | `#8B5A2B`   | `#C4824D`   | brown         |
| Graph    | `#4A7C59`   | `#6BA87D`   | success       |
| Temporal | `#6B7280`   | `#9CA3AF`   | muted         |
| Phonetic | `#1a1a1a`   | `#ffffff`   | ink           |

### Design rationale

- **Uniform header fills**: category identity lives in the body color only — one encoding channel, not two
- **Transparent vault fill**: sketch mode adds a hachure overlay to every filled shape; transparent vault + filled class boxes = max 1 hatching layer instead of 2-3
- **Vault overlay removal**: even with transparent fill, D2 renders a sketch overlay rect on the vault — remove it in post-processing (see below)

## Edge Colors

| From → To              | Color     | Token   |
|------------------------|-----------|---------|
| Input → Hero           | `#E63E2A` | accent  |
| Hero → Standard nodes  | `#6B7280` | muted   |
| Standard → Convergence | `#8B5A2B` | brown   |
| Convergence → Output   | `#4A7C59` | success |

All edges: `style.stroke-width: 2`

## Rendering

All diagrams use `--sketch` for hand-drawn aesthetics.

```bash
# Light mode (theme 0 = default)
d2 --sketch --theme=0 <name>.d2 <name>-light.svg

# Dark mode (theme 200 = Catppuccin Mocha)
d2 --sketch --theme=200 <name>-dark.d2 <name>-dark.svg
```

**Theme 200** gives us dark backgrounds but uses Catppuccin's purple-tinted neutrals.
We post-process to replace them with Oneiron brand colors.

## Post-Processing

### All SVGs — transparent N7 background

D2 renders N7 as a solid fill (white for light, `#1E1E2E` for dark). Replace with
transparent so diagrams blend seamlessly with the host page (GitHub README, docs site, etc.):

```bash
# Light mode — only change the N7 CSS class, NOT inline fill attributes (those belong to nodes)
sed -i '' 's/\.fill-N7{fill:#FFFFFF;}/.fill-N7{fill:transparent;}/g' <name>-light.svg

# Dark mode — same: CSS class only
sed -i '' 's/\.fill-N7{fill:#1E1E2E;}/.fill-N7{fill:transparent;}/g' <name>-dark.svg
```

### Storage diagrams — fix B2 markers and vault overlay

B2 controls the `+` visibility markers on class shapes.

```bash
# Light mode: cream markers (visible on all colored body fills)
sed -i '' 's/\.fill-B2{fill:#0D32B2;}/.fill-B2{fill:#F4F0E6;}/g' storage-light.svg

# Dark mode: dark markers (visible on all colored body fills)
sed -i '' 's/\.fill-B2{fill:#CBA6f7;}/.fill-B2{fill:#111111;}/g' storage-dark.svg

# Both modes: remove vault container overlay to eliminate double hatching
# The vault overlay is the largest sketch-overlay rect (covers entire diagram)
sed -i '' 's|<rect width="784.000000" height="470.000000" transform="translate(0.000000 0.000000)" class=" sketch-overlay-darker" />||' storage-*.svg
```

**Note**: The vault overlay dimensions may change if the diagram layout changes. Match the largest `sketch-overlay-*` rect.

### Storage diagrams — shadow injection

D2 ignores `style.shadow` on `shape: class`, so shadows must be injected manually.
Two parts: (a) add the filter definition to `<defs>`, (b) add `filter` attributes to each
class shape group (skip the vault, which is the first `<g class="shape">` in the SVG).

```bash
# 1. Add filter definition to <defs>
FILTER='<filter id="shadow-filter" width="200%" height="200%" x="-50%" y="-50%"><feGaussianBlur stdDeviation="1.7" in="SourceGraphic" /><feFlood flood-color="#3d4574" flood-opacity="0.4" result="ShadowFeFlood" in="SourceGraphic" /><feComposite in="ShadowFeFlood" in2="SourceAlpha" operator="in" result="ShadowFeComposite" /><feOffset dx="3" dy="5" result="ShadowFeOffset" in="ShadowFeComposite" /><feBlend in="SourceGraphic" in2="ShadowFeOffset" mode="normal" result="ShadowFeBlend" /></filter>'
sed -i '' "s|</defs>|${FILTER}</defs>|" storage-*.svg

# 2. Add filter attributes to class shape groups (skip first = vault)
python3 -c "
import re
for fname in ['storage-light', 'storage-dark']:
    path = f'docs/{fname}.svg'
    with open(path, 'r') as f:
        content = f.read()
    count = [0]
    def replacer(match):
        count[0] += 1
        if count[0] == 1:  # skip vault
            return match.group(0)
        return '<g class=\"shape\" filter=\"url(#shadow-filter)\" >'
    content = re.sub(r'<g class=\"shape\" >', replacer, content)
    with open(path, 'w') as f:
        f.write(content)
"
```

### GitHub cache busting

The README uses `?v=N` query params on SVG references. Bump after every re-render:

```markdown
<source srcset="./docs/storage-dark.svg?v=10">
```

## Files

| File                      | Purpose                     |
|---------------------------|-----------------------------|
| `architecture.d2`         | Architecture — light source |
| `architecture-dark.d2`    | Architecture — dark source  |
| `architecture-light.svg`  | Architecture — light SVG    |
| `architecture-dark.svg`   | Architecture — dark SVG     |
| `storage-light.d2`        | Storage layout — light      |
| `storage-dark.d2`         | Storage layout — dark       |
| `storage-light.svg`       | Storage layout — light SVG  |
| `storage-dark.svg`        | Storage layout — dark SVG   |
| `deployment-light.d2`     | Deployment — light          |
| `deployment-dark.d2`      | Deployment — dark           |
| `deployment-light.svg`    | Deployment — light SVG      |
| `deployment-dark.svg`     | Deployment — dark SVG       |

The README uses `<picture>` elements to auto-switch between light and dark SVGs based on the viewer's color scheme preference.
