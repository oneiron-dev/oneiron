/* restore the fold before first paint · no flash */
if (localStorage.getItem('oneiron-mock-rail') === 'folded')
  document.documentElement.classList.add('rail-folded');
/* restore pack-group folds before first paint · default expanded */
try {
  const rg = JSON.parse(localStorage.getItem('oneiron-rail-groups') || '{}');
  for (const p of ['crm', 'office', 'channels', 'lenses'])
    if (rg[p] === 'folded') document.documentElement.classList.add('rg-' + p);
} catch (e) { /* bad JSON → default expanded */ }
/* the reading room, same pass — the theme cannot flash either */
if (localStorage.getItem('oneiron-mock-theme') === 'light')
  document.documentElement.classList.add('light');
