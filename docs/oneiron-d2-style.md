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
d2 --sketch architecture.d2 architecture-light.svg

# Dark mode (--dark-theme only works with SVG)
d2 --sketch --dark-theme 200 architecture-dark.d2 architecture-dark.svg
```

The `--sketch` flag adds analog warmth matching Oneiron's noise-texture aesthetic.

## Files

| File                    | Purpose                     |
|-------------------------|-----------------------------|
| `architecture.d2`       | Light mode source           |
| `architecture-dark.d2`  | Dark mode source            |
| `architecture-light.svg`| Light SVG (README)          |
| `architecture-dark.svg` | Dark SVG (README)           |

The README uses a `<picture>` element to auto-switch between light and dark SVGs based on the viewer's color scheme preference.
