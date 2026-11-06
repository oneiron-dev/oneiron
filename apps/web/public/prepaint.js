/* restore the fold before first paint · no flash */
if (localStorage.getItem('oneiron-mock-rail') === 'folded')
  document.documentElement.classList.add('rail-folded');
/* restore pack-group folds before first paint · default expanded */
try {
  const rg = JSON.parse(localStorage.getItem('oneiron-rail-groups') || '{}');
  for (const p of ['rooms', 'crm', 'office', 'channels', 'lenses'])
    if (rg[p] === 'folded') document.documentElement.classList.add('rg-' + p);
} catch (e) { /* bad JSON → default expanded */ }
/* the room, same pass — the theme cannot flash either. three states:
   'light' / 'dark' force a room; anything else follows the system. */
{
  const t = localStorage.getItem('oneiron-theme');
  if (t === 'light' || t === 'dark') document.documentElement.classList.add(t);
}
/* the roster face + portrait style (owner 09-07, A): rows wear the name in ink;
   a tuner override is restored before paint so the roster never flashes */
{
  const rf = localStorage.getItem('oneiron-roster-face');
  document.documentElement.setAttribute('data-roster-face', rf === 'portrait' || rf === 'mark' ? rf : 'none');
  const fs = localStorage.getItem('oneiron-face-style');
  if (fs === 'base' || fs === 'trink' || fs === 'dream') document.documentElement.setAttribute('data-face-style', fs);
  /* the selected row's chrome (owner 09-07): rounded is the default, the tuner's pick restores here */
  const vo = localStorage.getItem('oneiron-voice');
  if (vo === 'indent' || vo === 'mono' || vo === 'glyph') document.documentElement.setAttribute('data-voice', vo);
  const vg = localStorage.getItem('oneiron-voice-ground');
  if (vg === 'none' || vg === 'hairline') document.documentElement.setAttribute('data-voice-ground', vg);
  /* the picker + the work (owner 09-08): well/thread are the defaults, the tuner's pick restores here */
  const pk = localStorage.getItem('oneiron-picker');
  if (pk === 'well' || pk === 'sidebar' || pk === 'ground') document.documentElement.setAttribute('data-picker', pk);
  const rc = localStorage.getItem('oneiron-room-column');
  if (rc === 'center' || rc === 'dock') document.documentElement.setAttribute('data-room-column', rc);
  if (localStorage.getItem('oneiron-my-turn') === 'stack') document.documentElement.setAttribute('data-my-turn', 'stack');
  const wk = localStorage.getItem('oneiron-work');
  if (wk === 'pane') document.documentElement.setAttribute('data-work-axis', wk);
  const sc = localStorage.getItem('oneiron-select-chrome');
  if (sc === 'square' || sc === 'gutter' || sc === 'box') document.documentElement.setAttribute('data-select-chrome', sc);
}
