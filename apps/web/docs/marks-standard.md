# Attribute marks · the house standard (draft, 2026-09-07)

One mark per agent. It sits in the roster row at 16 to 24 px, filled with the agent's ink, and
it is what tells the agents apart. This is the standard every mark is drawn and judged against.
It borrows the mechanism icon designers use, the keyline grid, and adds our register rules.

## How icon designers keep shapes from fighting

A set looks uneven when every icon fills its box the same way. A disc and a spear both scaled
to the same square read as a boulder and a hair. The fix is not taste, it is a grid with
keyline shapes: a few fixed boxes, one per silhouette class, sized so that different shapes
carry the same optical weight.

```
24-unit grid, 2-unit safe margin, live area 20

  circle Ø20        square 18        wide 20×16        tall 16×20
 ┌────────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
 │  ╭──────╮  │   │  ┌──────┐  │   │            │   │    ┌──┐    │
 │ ╱        ╲ │   │  │      │  │   │ ┌────────┐ │   │    │  │    │
 │ │  disc  │ │   │  │ box  │  │   │ │ wide   │ │   │    │  │    │
 │ ╲        ╱ │   │  │      │  │   │ └────────┘ │   │    │  │    │
 │  ╰──────╯  │   │  └──────┘  │   │            │   │    └──┘    │
 └────────────┘   └────────────┘   └────────────┘   └────────────┘
   shield, wreath   tablet, letter   trumpet, sandal   feather, staff
```

The circle is larger than the square on purpose: a round shape looks smaller than a square of
the same width, so it overshoots. A wide object gets the wide box, a tall one the tall box.
Every mark fills its box edge to edge. That single rule makes a disc and a spear sit as equals.
These numbers are Material's 24 dp keylines; Apple's SF Symbols and IBM's Carbon do the same
thing with their own boxes. We adopt Material's numbers because our marks live at 16 to 24.

## The rules

1. **Grid.** Draw on 24 units with a 2-unit margin. Classify the silhouette (round, square,
   wide, tall) and fill that keyline box exactly. Nothing floats inside a smaller box.
2. **One object.** An attribute the god holds, wears or tends. Never a scene, never a pair
   unless the pair is the object (wings).
3. **One view.** Side profile for things that have a side (helmet, sandal, scroll, lamp).
   Front for symmetric things (wings, wreath, temple). No three-quarter views, no
   perspective, no shadows.
4. **Solid, one hand.** A filled silhouette. The hand (geometric or calligraphic) is chosen once
   for the whole family. Where a stroke exists (staff, spear, ripple) it is 3 units at 24.
5. **Minimum feature.** Interior cuts and counters are at least 2 units at 24. Anything thinner
   is dropped, not thinned.
6. **One drawing per size.** 24 and 20 share a drawing. 16 is its own cut with the interior
   cuts removed (the creature-lane law: never downscale a bigger drawing).
7. **Ink mass.** Between 20 and 40 percent of the keyline box. Under 20 reads spindly, over 40
   reads as a blob.
8. **Register.** An ancient object, never a modern one. The test: could it be painted on a
   vase. An envelope with a wax seal fails, a folded tablet passes.
9. **Contrast.** A mark in ink clears 3:1 on its sheet (WCAG 1.4.11). A name in ink clears
   4.5:1. Shape tells the agents apart, never hue alone (WCAG 1.4.1).
10. **Format.** A traced SVG, filled paths, viewBox 0 0 24 24, used as a CSS mask or inline with
    currentColor. PNG masks are scaffolding until the SVG is proven on the bench.

## How it applies to batch 2

Batch 2 (gpt-image-2 on Flora, 3 by 3 grids) already holds rules 2, 4 and 8 for most cells. It
breaks rule 1: every cell was drawn to fill about the same square, so the trumpet is a wide
sliver and the shield a full disc. The normalizer (`keyline.py`) classifies each mark's
silhouette and refits it to its keyline box. The bench shows raw beside normalized at 16 · 20 ·
24. Rule 6 (a native 16 cut) and rule 3 (one view per family) are generation-time rules and
go into the prompt of the next batch, once the attributes are picked.

## References

- Material Design icon system: 24 dp grid, 2 dp padding, keylines circle 20 · square 18 ·
  wide 20×16 · tall 16×20, minimum stroke 2 dp.
- Apple SF Symbols and the Human Interface Guidelines: three scales and nine weights per
  symbol, optical alignment over geometric.
- IBM Carbon icon guidelines: one visual language, consistent stroke, no perspective.
- Our own creature lane (2026-07-13): three cuts per animal, each drawn natively at its scale.
