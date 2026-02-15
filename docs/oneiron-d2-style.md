# Oneiron D2 Diagram Style Guide

Style tokens derived from [oneiron.dev](https://oneiron.dev) landing page.

## Palette

| Token   | Light     | Dark      | Role                          |
|---------|-----------|-----------|-------------------------------|
| accent  | `#E63E2A` | `#E63E2A` | Hero elements, primary action |
| ink     | `#1a1a1a` | `#C8C4BA` | Text, heavy/convergence nodes |
| surface | `#F4F0E6` | `#111111` | Background                    |
| raised  | `#ffffff` | `#1A1A1A` | Elevated surfaces             |
| success | `#4A7C59` | `#6BA87D` | Completion, positive output   |
| muted   | `#6B7280` | `#9CA3AF` | Secondary connections         |
| brown   | `#8B5A2B` | `#C4824D` | Warm secondary accent         |

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

## Edge Colors

| From → To              | Color     | Token   |
|------------------------|-----------|---------|
| Input → Hero           | `#E63E2A` | accent  |
| Hero → Standard nodes  | `#6B7280` | muted   |
| Standard → Convergence | `#8B5A2B` | brown   |
| Convergence → Output   | `#4A7C59` | success |

All edges: `style.stroke-width: 2`

## Rendering

```bash
# Light mode
d2 --sketch <name>.d2 <name>-light.svg

# Dark mode — render WITHOUT --dark-theme, then post-process
d2 --sketch <name>-dark.d2 <name>-dark.svg
```

The `--sketch` flag adds analog warmth matching Oneiron's noise-texture aesthetic.

**Important: Do NOT use `--dark-theme`.**  D2's built-in dark themes (200 = Catppuccin Mocha, 201 = Flagship) inject blue-violet tinted neutrals (`#1E1E2E`, `#0D32B2`, `#4A6FF3`, etc.) that clash with Oneiron's warm neutral palette. Instead, render dark SVGs with the default theme and post-process to replace D2's light-theme neutrals with Oneiron-brand dark grays:

```bash
# Post-process: replace D2's blue-tinted neutrals with brand neutrals
sed -i '' \
  -e 's/#FFFFFF/#111111/g' \
  -e 's/#EEF1F8/#1A1A1A/g' \
  -e 's/#DEE1EB/#222222/g' \
  -e 's/#CFD2DD/#2A2A2A/g' \
  -e 's/#9499AB/#444444/g' \
  -e 's/#676C7E/#666666/g' \
  -e 's/#0A0F25/#888888/g' \
  -e 's/#0D32B2/#333333/g' \
  -e 's/#4A6FF3/#555555/g' \
  -e 's/#3d4574/#333333/g' \
  -e 's/#E3E9FD/#1C1C1C/g' \
  -e 's/#EDF0FD/#181818/g' \
  -e 's/#F7F8FE/#141414/g' \
  <name>-dark.svg
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
