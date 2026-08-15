/* the tuner · a DEV instrument, not product (owner 08-15 eve: "make me a
   bunch of sliders so that I can tune the page"). one place derives the
   layout vars and the whole LIGHT room from a few knobs; the dark room
   stays byte-identical (values are written as light-dark(light, dark)).
   loads before first paint and restores the last tuning from
   localStorage — the React panel (src/components/dev/Tuner.tsx) only
   drives this. */
(function () {
  var KEY = 'oneiron-tune';
  var DARK = {
    bg: '#131110', el: '#1B1815', well: '#211D18',
    s1: '#DDD6C9', s2: '#C0B9AC', s3: '#8F887A', s4: '#565048',
    rule: '#322D27', ruleStrong: '#443E35',
  };
  /* the light room as shipped in f1ce5a5, in oklch, so a fresh panel
     starts exactly where the page is */
  var DEFAULTS = {
    railW: 186, sheetTop: 12, sheetRight: 18, sheetBottom: 46, sheetLeft: 26, sheetLeftFolded: 4, grain: 0.05, plate: 0,
    sheetRadius: 8, panePadX: 22, panePadY: 18, ctxW: 320, ctxTint: 1,
    paperL: 0.929, paperC: 0.0116, paperH: 85,
    sheetLift: 0.027, wellDrop: 0.036, inkShift: 0,
  };
  var PRESETS = {
    current: {},
    paper:   { paperC: 0.006, paperH: 72, wellDrop: 0.02 },
    stock:   { paperC: 0.003, paperH: 72, wellDrop: 0.02 },   /* near-neutral, a whisper of warmth */
    neutral: { paperC: 0.002, paperH: 260, wellDrop: 0.02 },
  };
  /* the ink ladder's base L/C (light room); its hue follows the paper and
     its chroma scales with the paper's, so a neutral paper gets neutral
     ink instead of warm ink on grey */
  var INK = [[0.255, 0.0095], [0.345, 0.0146], [0.489, 0.0193], [0.645, 0.022]];

  function ok(L, C, H) {
    L = Math.max(0, Math.min(1, L));
    return 'oklch(' + (L * 100).toFixed(2) + '% ' + Math.max(0, C).toFixed(4) + ' ' + H.toFixed(1) + ')';
  }
  function ld(light, dark) { return 'light-dark(' + light + ', ' + dark + ')'; }

  function derive(v) {
    var L = v.paperL, C = v.paperC, H = v.paperH;
    var desk = ok(L, C, H);
    var sheet = ok(L + v.sheetLift, C * 0.85, H);
    var well = ok(L - v.wellDrop, C * 1.5, H);
    var k = C / 0.0116;                     /* ink chroma scale */
    var s = INK.map(function (p) { return ok(p[0] + v.inkShift, p[1] * k, H); });
    return {
      '--bg': ld(desk, DARK.bg),
      '--bg-elevated': ld(sheet, DARK.el),
      '--bg-well': ld(well, DARK.well),
      '--ctx-bg': ld('color-mix(in oklch, ' + sheet + ', ' + well + ' ' + Math.round(v.ctxTint * 100) + '%)', DARK.well),
      '--rule': ld(ok(L - 0.064, C * 1.5, H), DARK.rule),
      '--rule-strong': ld(ok(L - 0.134, C * 1.9, H), DARK.ruleStrong),
      '--silver-1': ld(s[0], DARK.s1),
      '--silver-2': ld(s[1], DARK.s2),
      '--silver-3': ld(s[2], DARK.s3),
      '--silver-4': ld(s[3], DARK.s4),
      '--rail-w': v.railW + 'px',
      '--sheet-top': v.sheetTop + 'px',
      '--sheet-right': v.sheetRight + 'px',
      '--sheet-bottom': v.sheetBottom + 'px',
      '--sheet-left': v.sheetLeft + 'px',
      '--sheet-left-folded': v.sheetLeftFolded + 'px',
      '--grain': String(v.grain),
      '--plate': String(v.plate),
      '--sheet-radius': v.sheetRadius + 'px',
      '--pane-pad-x': v.panePadX + 'px',
      '--pane-pad-y': v.panePadY + 'px',
      '--ctx-w': v.ctxW + 'px',
    };
  }

  function apply(values) {
    var v = Object.assign({}, DEFAULTS, values || {});
    var out = derive(v);
    var st = document.documentElement.style;
    for (var k in out) st.setProperty(k, out[k]);
    return v;
  }
  function clear() {
    var st = document.documentElement.style;
    for (var k in derive(DEFAULTS)) st.removeProperty(k);
  }
  function save(values) {
    try { localStorage.setItem(KEY, JSON.stringify(values)); } catch (e) { /* private mode */ }
  }
  function load() {
    try { return JSON.parse(localStorage.getItem(KEY) || 'null'); } catch (e) { return null; }
  }
  function reset() { clear(); try { localStorage.removeItem(KEY); } catch (e) { /* */ } }

  window.oneironTune = { DEFAULTS: DEFAULTS, PRESETS: PRESETS, apply: apply, clear: clear, save: save, load: load, reset: reset, derive: derive };

  /* restore before first paint */
  var saved = load();
  if (saved) apply(saved);
})();
