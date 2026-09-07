/* restore the fold before first paint · no flash */
if (localStorage.getItem('oneiron-mock-rail') === 'folded')
  document.documentElement.classList.add('rail-folded');
/* restore pack-group folds before first paint · default expanded */
try {
  const rg = JSON.parse(localStorage.getItem('oneiron-rail-groups') || '{}');
  for (const p of ['crm', 'office', 'channels', 'lenses'])
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
  if (vo === 'right' || vo === 'mono' || vo === 'glyph') document.documentElement.setAttribute('data-voice', vo);
  const sc = localStorage.getItem('oneiron-select-chrome');
  if (sc === 'square' || sc === 'gutter' || sc === 'box') document.documentElement.setAttribute('data-select-chrome', sc);
}
