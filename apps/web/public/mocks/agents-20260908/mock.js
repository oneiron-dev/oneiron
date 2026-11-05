/* agents room mocks · shared chrome: the app rail, the ground line, the
   corner switches, the keys (t theme · r rail). the page's defaults live on
   <html data-voice data-head data-rail>, set by the page's prepaint script;
   picks are remembered per page under mock-agents:<page>:<switch>. */
(function () {
  var html = document.documentElement;
  var body = document.body;
  var page = body.dataset.page || 'm';
  var active = body.dataset.active || 'agents';
  var supports = (body.dataset.switches || '').split(/\s+/).filter(Boolean);

  var I = {
    logo: '<svg width="18" height="18" viewBox="0 0 120 120" fill="none" aria-hidden="true"><mask id="ocut"><rect width="120" height="120" fill="white"/><circle cx="60" cy="60" r="22" fill="black"/></mask><rect x="17.5" y="17.5" width="85" height="85" rx="10" fill="currentColor" transform="rotate(45 60 60)" mask="url(#ocut)"/></svg>',
    chev: '<svg width="8" height="8" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><path d="M2 3.5 L5 6.5 L8 3.5"/></svg>',
    chev10: '<svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor" stroke-width="1.4" aria-hidden="true"><path d="M2 3.5 L5 6.5 L8 3.5"/></svg>',
    search: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>',
    inbox: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/></svg>',
    vault: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect width="8" height="18" x="3" y="3" rx="1"/><path d="M7 3v18"/><path d="M20.4 18.9c.2.5-.1 1.1-.6 1.3l-1.9.7c-.5.2-1.1-.1-1.3-.6L11.1 5.1c-.2-.5.1-1.1.6-1.3l1.9-.7c.5-.2 1.1.1 1.3.6Z"/></svg>',
    agents: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 5h12a2 2 0 0 1 2 2v12a2 2 0 0 1 -2 2h-12a2 2 0 0 1 -2 -2v-12a2 2 0 0 1 2 -2z"/><path d="M9 16c1 .667 2 1 3 1s2 -.333 3 -1"/><path d="M9 7l-1 -4"/><path d="M15 7l1 -4"/><path d="M9 12v-1"/><path d="M15 12v-1"/></svg>',
    pipeline: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="18" x="3" y="3" rx="2"/><path d="M8 7v7"/><path d="M12 7v4"/><path d="M16 7v9"/></svg>',
    today: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2v4"/><path d="M16 2v4"/><rect width="18" height="18" x="3" y="4" rx="2"/><path d="M3 10h18"/></svg>',
    orgs: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z"/><path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2"/><path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2"/><path d="M10 6h4"/><path d="M10 10h4"/><path d="M10 14h4"/><path d="M10 18h4"/></svg>',
    notes: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M10 9H8"/><path d="M16 13H8"/><path d="M16 17H8"/></svg>',
    briefs: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6h4"/><path d="M2 10h4"/><path d="M2 14h4"/><path d="M2 18h4"/><rect width="16" height="20" x="4" y="2" rx="2"/><path d="M9.5 8h5"/><path d="M9.5 12H16"/><path d="M9.5 16H14"/></svg>',
    tasks: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10.656V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h12.344"/><path d="m9 11 3 3L22 4"/></svg>',
    threads: '<svg width="16" height="16" viewBox="0 0 256 256" fill="currentColor"><path d="M229.93,186.58A78,78,0,0,0,168.16,74.42,78,78,0,1,0,26.07,138.58L18.58,164A14,14,0,0,0,36,181.42l25.46-7.49a78,78,0,0,0,26.39,7.63,78,78,0,0,0,106.77,40.37L220,229.42A14,14,0,0,0,237.42,212ZM62,161.5a6.05,6.05,0,0,0-1.69.24l-27.77,8.17a2,2,0,0,1-2.48-2.48l8.17-27.77a6.05,6.05,0,0,0-.47-4.53,66,66,0,1,1,27.08,27.08A6,6,0,0,0,62,161.5Zm155.71,26.16,8.17,27.77a2,2,0,0,1-2.48,2.48l-27.77-8.17a6.06,6.06,0,0,0-4.53.47,66,66,0,0,1-90-28.4,77.92,77.92,0,0,0,71-94.68,66,66,0,0,1,46.07,96A6.05,6.05,0,0,0,217.74,187.66Z"/></svg>',
    eye: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2.062 12.348a1 1 0 0 1 0-.696 10.75 10.75 0 0 1 19.876 0 1 1 0 0 1 0 .696 10.75 10.75 0 0 1-19.876 0"/><circle cx="12" cy="12" r="3"/></svg>',
    history: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/></svg>'
  };

  function row(key, label, count) {
    return '<a href="#" class="' + (key === active ? 'active' : '') + '"><span class="ico">' + I[key] + '</span><span class="txt">' + label + '</span>' + (count ? '<span class="count">' + count + '</span>' : '') + '</a>';
  }
  function group(label, rows) {
    return '<div class="group"><span class="label">' + label + ' ' + I.chev10 + '</span>' + rows + '</div>';
  }

  /* the app rail, as built */
  var rail = document.querySelector('nav.rail');
  if (rail && !rail.children.length) {
    rail.innerHTML =
      '<div class="head-row"><span class="mark">' + I.logo + '</span><span class="vault-chip"><span class="name">antevon</span>' + I.chev + '</span><span class="search-btn">' + I.search + '</span></div>' +
      '<div class="group">' + row('inbox', 'inbox', '5') + row('vault', 'vault') + row('agents', 'agents') + '</div>' +
      group('crm', row('pipeline', 'pipeline') + row('today', 'today') + row('orgs', 'orgs')) +
      group('office', row('notes', 'notes') + row('briefs', 'briefs') + row('tasks', 'tasks')) +
      group('channels', row('threads', 'threads')) +
      group('lenses', row('eye', 'supplier watch'));
  }

  /* the ground line: the corner switches left, the live runs right */
  var sw = {
    voice: ['indent', 'right', 'mono', 'glyph'],
    head: ['portrait', 'line', 'none'],
    rail: ['open', 'edge']
  };
  function remember(k, v) { try { localStorage.setItem('mock-agents:' + page + ':' + k, v); } catch (e) {} }
  function paint() {
    document.querySelectorAll('.switches button[data-sw]').forEach(function (b) {
      b.classList.toggle('on', html.dataset[b.dataset.sw] === b.dataset.v);
    });
    var tb = document.querySelector('.switches button[data-theme]');
    if (tb) tb.textContent = html.dataset.theme === 'dark' ? 'night' : 'day';
  }
  function set(k, v) { html.dataset[k] = v; remember(k, v); paint(); }
  function setTheme(t) { html.dataset.theme = t; try { localStorage.setItem('oneiron-theme', t); } catch (e) {} paint(); }

  var switchesHtml = supports.map(function (k) {
    if (!sw[k]) return '';
    return '<span class="swg"><span class="swk">' + k + '</span>' + sw[k].map(function (v, i) {
      return (i ? '<span class="sep">·</span>' : '') + '<button type="button" data-sw="' + k + '" data-v="' + v + '">' + v + '</button>';
    }).join('') + '</span>';
  }).join('') + '<span class="swg"><span class="swk">t</span><button type="button" data-theme="1">night</button></span>';

  var ground = document.createElement('div');
  ground.className = 'ground';
  ground.innerHTML = '<div class="gline"><div class="switches">' + switchesHtml + '</div><span class="gspacer"></span>' +
    '<span class="grun" data-agent="eiri"><span class="gname">eiri</span><span>·</span><span class="shimmer">drafting the COO intro</span></span>' +
    '<span class="grun" data-agent="tory"><span class="gname">tory</span><span>·</span><span class="shimmer">checking filings</span></span>' +
    '<span class="grun"><span class="gplus">+</span><span>new chat</span></span>' +
    '<span class="grun">' + I.history + '</span></div>';
  body.appendChild(ground);
  var grain = document.createElement('div'); grain.className = 'grain'; body.appendChild(grain);

  ground.addEventListener('click', function (e) {
    var b = e.target.closest('button'); if (!b) return;
    if (b.dataset.sw) set(b.dataset.sw, b.dataset.v);
    else if (b.dataset.theme) setTheme(html.dataset.theme === 'dark' ? 'light' : 'dark');
  });
  paint();

  /* the pocket door: the edge opens, the glyph folds, r toggles */
  document.querySelectorAll('.edge').forEach(function (el) { el.addEventListener('click', function () { set('rail', 'open'); }); });
  document.querySelectorAll('.foldg').forEach(function (el) { el.addEventListener('click', function () { set('rail', 'edge'); }); });

  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    var t = e.target; if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
    if (e.key === 't') setTheme(html.dataset.theme === 'dark' ? 'light' : 'dark');
    if (e.key === 'r' && supports.indexOf('rail') >= 0) set('rail', html.dataset.rail === 'edge' ? 'open' : 'edge');
  });

  /* every thread keeps its foot in view */
  function foot() { document.querySelectorAll('.thread, .chat-thread').forEach(function (el) { el.scrollTop = el.scrollHeight; }); }
  foot(); window.addEventListener('load', foot); setTimeout(foot, 400);
  document.querySelectorAll('a[href="#"]').forEach(function (a) { a.addEventListener('click', function (e) { e.preventDefault(); }); });
})();
