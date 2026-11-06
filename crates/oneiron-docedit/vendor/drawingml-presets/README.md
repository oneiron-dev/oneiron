# DrawingML preset connection-site data

Source: Ecma International, ECMA-376 Part 1, fifth edition (2016), Annex H,
`OfficeOpenXML-DrawingMLGeometries.zip`, `presetShapeDefinitions.xml`.

Official transport:
https://ecma-international.org/wp-content/uploads/ECMA-376-1_5th_edition_december_2016.zip

The XML here is the original inner file, unchanged. SHA-256:
`2f7c868d857c1e3c4b5a6068759fe0e07d77ad58377a6618d1b02ba3507b6939`.
It has a duplicated `upDownArrow` and no `upArrow`; no third-party correction
has been inserted. `LICENSE.txt` carries the complete Ecma default copyright
notice and disclaimer; its clause (iv) permits standard functionality
implementations. `LICENSE-SOURCE.txt` records the official policy source.

## Derived data

From the repository root, regenerate the Rust data with:

```sh
python3 scripts/docedit/generate_preset_sites.py
python3 scripts/docedit/generate_preset_sites.py --check
```

The generated file is
`src/live/points/preset_sites/data.rs`, relative to `crates/oneiron-docedit`.
It contains adjustment defaults, ordered calculated guides and ordered
connection sites. Guide order and repeated guide definitions are retained.
Paths, adjustment handles and preset text rectangles are not imported:
Edit Points supplies the paths, keeps empty handles and keeps the existing
full-bounds text rectangle.

The generator retains only definitions whose guide references resolve in
order using the 36 built-ins and 17 formula operators in ECMA-376 Part 1
20.1.10.56 and 20.1.9.11. It produces 180 definitions. These six use
unresolved references and are not promoted: `curvedLeftArrow` (`cd3`),
`flowChartManualInput` and `flowChartPunchedTape` (`hd10`), `leftRightRibbon`,
`ribbon` and `ribbon2` (`wd32`). The missing `upArrow`, unknown presets and
presets without connection sites also keep the existing vertex-only
conversion. No input is newly refused.

## Use and limits

Only preset-to-freeform edits with actual live or slide connector glue use
the retained sites. Their original site list remains the prefix of the new
list, so existing connector indices still name the same source-defined sites.
New vertex sites append after it. Instance adjustment formulas override the
same-named defaults; new site-guide names avoid all held guide names. Shape
transforms are left unchanged. Existing custom-geometry redraw is unchanged.

Annex H supplies informative example geometries. This implementation uses
those published constructions; it does not claim a runtime comparison with
PowerPoint's built-in preset renderer. The six unresolved definitions and
missing `upArrow` remain FIX 5726 follow-ups. No formula evaluator, runtime
Word comparison, tests, migration or new policy limit is introduced.
