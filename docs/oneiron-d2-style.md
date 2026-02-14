# Oneiron D2 Diagram Style Guide

Style tokens derived from [oneiron.dev](https://oneiron.dev) landing page.

## Palette

| Token   | Hex       | Role                          |
|---------|-----------|-------------------------------|
| accent  | `#E63E2A` | Hero elements, primary action |
| ink     | `#1a1a1a` | Text, heavy/convergence nodes |
| surface | `#F4F0E6` | Warm parchment backgrounds    |
| success | `#4A7C59` | Completion, positive output   |
| muted   | `#6B7280` | Secondary connections         |
| brown   | `#8B5A2B` | Warm secondary accent         |
| raised  | `#ffffff` | Elevated surfaces             |

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
d2 --sketch input.d2 output.svg   # hand-drawn look (recommended)
d2 --sketch input.d2 output.png   # raster version
```

The `--sketch` flag adds analog warmth matching Oneiron's noise-texture aesthetic.
