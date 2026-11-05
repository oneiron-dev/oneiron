# Preset connection sites during Edit Points

When Edit Points turns a glued preset shape into a freeform, docedit keeps the
preset's published connection-site prefix before appending vertex sites.
Connection indices therefore retain the same source-defined positions.

The source-pinned generator currently emits 183 preset definitions. This
includes `leftRightRibbon`, `ribbon` and `ribbon2`: their guides use `wd32`,
a built-in that the runtime already supports. The original 180 definitions,
the vendor XML digest and its Ecma license are unchanged by this extension.

Four names still use the existing fallback:

- `upArrow` is absent from the pinned source XML.
- `curvedLeftArrow` contains an unresolved `cd3` reference.
- `flowChartManualInput` and `flowChartPunchedTape` contain unresolved `hd10`
  references.

No coordinates or formulas are guessed for these cases. Renderer equivalence
of the retained preset guide graph remains unproved. Custom-geometry redraw,
unconnected shapes and the existing fallback are unchanged.

Regenerate this data with `python3 scripts/docedit/generate_preset_sites.py`.
Its `--check` mode reports stale generated data without changing files.
No API, dependency, setting or deployment configuration changes are required.
