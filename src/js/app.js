/* Infosphera Security Toolbox — App-Shell: Navigation, Routing, Suche, Design */
(() => {
  'use strict';
  const { tools, CATEGORIES, icon, util } = window.TB;
  const { esc, store, copy } = util;
  const VERSION = '1.0.0';

  const $ = (s) => document.querySelector(s);
  const view = $('#view');
  const byId = Object.fromEntries(tools.map((t) => [t.id, t]));
  const catName = Object.fromEntries(CATEGORIES.map((c) => [c.id, c.name]));
  const catLine = Object.fromEntries(CATEGORIES.map((c) => [c.id, c.line]));
  let cleanup = null;

  /* ---------- Design (Auto / Hell / Dunkel) ---------- */
  const themes = ['auto', 'light', 'dark'];
  const themeLabel = { auto: 'System', light: 'Hell', dark: 'Dunkel' };
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const applyTheme = () => {
    const pref = store.get('theme', 'auto');
    const eff = pref === 'auto' ? (mq.matches ? 'dark' : 'light') : pref;
    document.documentElement.dataset.theme = eff;
    $('#themeBtn').innerHTML = icon(pref === 'auto' ? 'auto' : pref === 'dark' ? 'moon' : 'sun') + themeLabel[pref];
  };
  $('#themeBtn').addEventListener('click', () => {
    const cur = store.get('theme', 'auto');
    store.set('theme', themes[(themes.indexOf(cur) + 1) % themes.length]);
    applyTheme();
  });
  mq.addEventListener('change', applyTheme);
  applyTheme();
  $('#version').textContent = 'v' + VERSION;

  /* ---------- Favoriten & Verlauf ---------- */
  const favs = () => store.get('favs', []);
  const isFav = (id) => favs().includes(id);
  const toggleFav = (id) => {
    const f = favs();
    store.set('favs', f.includes(id) ? f.filter((x) => x !== id) : [...f, id]);
  };
  const pushRecent = (id) => store.set('recent', [id, ...store.get('recent', []).filter((x) => x !== id)].slice(0, 8));

  const glyph = (t) => t.glyph ? esc(t.glyph) : icon(t.cat);

  /* ---------- Sidebar ---------- */
  const renderNav = () => {
    const collapsed = store.get('collapsed', []);
    const active = location.hash.replace(/^#\/?/, '').replace(/^tool\//, '');
    let html = `<a class="nav-item nav-home ${!active ? 'active' : ''}" href="#/">${icon('home')}Übersicht</a>`;
    const f = favs().filter((id) => byId[id]);
    if (f.length) {
      html += `<div class="nav-group" data-cat="fav"><button class="nav-title">${icon('star')}Favoriten<span class="count">${f.length}</span></button><div class="nav-items">` +
        f.map((id) => `<a class="nav-item ${active === id ? 'active' : ''}" href="#/tool/${id}">${esc(byId[id].name)}</a>`).join('') + '</div></div>';
    }
    for (const c of CATEGORIES) {
      const list = tools.filter((t) => t.cat === c.id);
      if (!list.length) continue;
      html += `<div class="nav-group ${collapsed.includes(c.id) ? 'collapsed' : ''}" data-cat="${c.id}">
        <button class="nav-title" data-toggle="${c.id}">${icon(c.id)}<span>${esc(c.name)}</span><span class="line">${esc(c.line)}</span><span class="count">${list.length}</span>${icon('chev', 'class="chev"')}</button>
        <div class="nav-items">${list.map((t) => `<a class="nav-item ${active === t.id ? 'active' : ''}" href="#/tool/${t.id}">${esc(t.name)}</a>`).join('')}</div></div>`;
    }
    $('#nav').innerHTML = html;
  };
  $('#nav').addEventListener('click', (e) => {
    const b = e.target.closest('[data-toggle]');
    if (!b) return;
    const id = b.dataset.toggle;
    const c = store.get('collapsed', []);
    store.set('collapsed', c.includes(id) ? c.filter((x) => x !== id) : [...c, id]);
    b.parentElement.classList.toggle('collapsed');
  });

  /* ---------- Startseite ---------- */
  const card = (t) => `<a class="card ${t.appOnly ? 'app-only' : ''}" href="#/tool/${t.id}">
      <div class="card-icon">${glyph(t)}</div>
      <div><h3>${esc(t.name)}</h3><p>${esc(t.desc)}</p></div>
      ${isFav(t.id) ? `<span class="fav-star">${icon('star')}</span>` : ''}
    </a>`;

  const renderHome = () => {
    document.title = 'Infosphera Security Toolbox';
    const recent = store.get('recent', []).filter((id) => byId[id]).slice(0, 4);
    const f = favs().filter((id) => byId[id]);
    const sphere = `<svg class="hero-sphere" viewBox="0 0 200 200" fill="none">${[90, 72, 52, 30, 10].map((rx) => `<ellipse cx="100" cy="100" rx="${rx}" ry="90"/>`).join('')}${[-60, -30, 0, 30, 60].map((y) => `<ellipse cx="100" cy="${100 + y}" rx="${Math.round(Math.sqrt(8100 - y * y))}" ry="${Math.round(Math.sqrt(8100 - y * y) * 0.18)}"/>`).join('')}<circle cx="100" cy="100" r="90" stroke-width="1.2"/><ellipse class="orbit" cx="100" cy="100" rx="122" ry="40" transform="rotate(-18 100 100)"/><circle class="sat" cx="214" cy="68" r="4"/></svg>`;
    let html = `<section class="hero">
        ${sphere}
        <div class="hero-kicker"><i></i>Infosphera · Defensive Security</div>
        <h1>Security Toolbox</h1>
        <p>${tools.length} Werkzeuge, um Domains, Geräte und Abläufe zu prüfen, zu härten und auf den Ernstfall vorzubereiten. Verständlich erklärt, auf Deutsch, nach Schweizer Standards.</p>
        <div class="hero-stats">
          <div><b>${tools.length}</b><span>Tools</span></div>
          <div><b>4</b><span>Sphera-Linien</span></div>
          <div><b>0</b><span>Tracking</span></div>
          <div><b>⌘K</b><span>Schnellsuche</span></div>
        </div>
      </section>
      <div class="principles">
        <div><b>Nur defensiv</b>Keine Exploits, keine Angriffe auf fremde Systeme.</div>
        <div><b>Lokal zuerst</b>Dateien, Logs und Passwörter verlassen dein Gerät nicht.</div>
        <div><b>Passiv nach aussen</b>Nur öffentliche Angaben wie DNS, TLS und Header.</div>
        <div><b>Ehrlich</b>Jeder Befund mit Erklärung und konkreter Massnahme.</div>
      </div>`;
    if (f.length) html += `<div class="section-head">${icon('star')}<h2>Favoriten</h2></div><div class="grid">${f.map((id) => card(byId[id])).join('')}</div>`;
    if (recent.length) html += `<div class="section-head">${icon('time')}<h2>Zuletzt verwendet</h2></div><div class="grid">${recent.map((id) => card(byId[id])).join('')}</div>`;
    for (const c of CATEGORIES) {
      const list = tools.filter((t) => t.cat === c.id);
      if (!list.length) continue;
      html += `<div class="section-head">${icon(c.id)}<h2>${esc(c.name)}</h2><span class="line-tag">${esc(c.line)}</span><span class="q">${esc(c.q)}</span><span class="spacer"></span><span class="count">${list.length}</span></div><div class="grid">${list.map(card).join('')}</div>`;
    }
    view.innerHTML = html;
  };

  /* ---------- Tool-Ansicht ---------- */
  const renderTool = (t) => {
    document.title = t.name + ' · Infosphera Security Toolbox';
    view.innerHTML = `<div class="tool-head">
        <div class="card-icon">${glyph(t)}</div>
        <div><div class="crumb">${esc(catName[t.cat])} · ${esc(catLine[t.cat])}</div><h1>${esc(t.name)}</h1><p>${esc(t.desc)}</p></div>
        <div class="tool-actions"><button class="icon-btn ${isFav(t.id) ? 'on' : ''}" id="favBtn" title="Favorit">${icon('star')}</button></div>
      </div><div id="toolRoot"></div>`;
    $('#favBtn').addEventListener('click', (e) => {
      toggleFav(t.id);
      e.currentTarget.classList.toggle('on', isFav(t.id));
      renderNav();
    });
    const root = $('#toolRoot');
    const ctx = Object.assign({}, util, {
      q: (s) => root.querySelector(s),
      qa: (s) => Array.from(root.querySelectorAll(s)),
      icon,
    });
    try {
      const res = t.render(root, ctx);
      cleanup = typeof res === 'function' ? res : null;
    } catch (err) {
      root.innerHTML = `<div class="msg err">Fehler beim Laden: ${esc(err.message)}</div>`;
      console.error(err);
    }
    pushRecent(t.id);
  };

  const route = () => {
    if (cleanup) { try { cleanup(); } catch { /* ignore */ } cleanup = null; }
    const h = location.hash.replace(/^#\/?/, '');
    const m = h.match(/^tool\/(.+)$/);
    const t = m && byId[m[1]];
    if (t) renderTool(t); else renderHome();
    renderNav();
    $('#main').scrollTop = 0;
  };
  window.addEventListener('hashchange', route);

  /* ---------- Kopieren (global) ---------- */
  document.addEventListener('click', (e) => {
    const a = e.target.closest('[data-copy],[data-copy-text]');
    if (!a) return;
    if (a.dataset.copyText !== undefined) return copy(a.dataset.copyText);
    const el = view.querySelector(a.dataset.copy);
    if (el) copy('value' in el && el.tagName !== 'BUTTON' ? el.value : el.textContent);
  });

  /* ---------- Befehlspalette ---------- */
  const pal = $('#palette'), pin = $('#paletteInput'), plist = $('#paletteList');
  let sel = 0, results = [];
  const score = (t, q) => {
    const hay = (t.name + ' ' + t.desc + ' ' + (t.keywords || '') + ' ' + catName[t.cat]).toLowerCase();
    const n = t.name.toLowerCase();
    if (n.startsWith(q)) return 100;
    if (n.includes(q)) return 80;
    if (q.split(/\s+/).every((w) => hay.includes(w))) return 50;
    let i = 0;
    for (const ch of n) if (ch === q[i]) i++;
    return i === q.length ? 20 : 0;
  };
  const renderPal = () => {
    const q = pin.value.trim().toLowerCase();
    results = q ? tools.map((t) => [t, score(t, q)]).filter((x) => x[1] > 0).sort((a, b) => b[1] - a[1]).map((x) => x[0]) : tools.slice();
    sel = Math.min(sel, Math.max(results.length - 1, 0));
    plist.innerHTML = results.length ? results.slice(0, 60).map((t, i) =>
      `<li class="${i === sel ? 'sel' : ''}" data-id="${t.id}"><div class="card-icon">${glyph(t)}</div><div><b>${esc(t.name)}</b><small>${esc(t.desc)}</small></div><span class="cat">${esc(catName[t.cat])}</span></li>`
    ).join('') : '<div class="palette-empty">Kein Tool gefunden</div>';
    const s = plist.querySelector('.sel');
    if (s) s.scrollIntoView({ block: 'nearest' });
  };
  const openPal = () => { pal.hidden = false; pin.value = ''; sel = 0; renderPal(); setTimeout(() => pin.focus(), 10); };
  const closePal = () => { pal.hidden = true; };
  const go = (id) => { closePal(); location.hash = '#/tool/' + id; };
  $('#searchTrigger').addEventListener('click', openPal);
  pin.addEventListener('input', () => { sel = 0; renderPal(); });
  pin.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { sel = Math.min(sel + 1, results.length - 1); renderPal(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { sel = Math.max(sel - 1, 0); renderPal(); e.preventDefault(); }
    else if (e.key === 'Enter' && results[sel]) go(results[sel].id);
    else if (e.key === 'Escape') closePal();
  });
  plist.addEventListener('click', (e) => { const li = e.target.closest('li[data-id]'); if (li) go(li.dataset.id); });
  pal.addEventListener('click', (e) => { if (e.target === pal) closePal(); });
  document.addEventListener('keydown', (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); pal.hidden ? openPal() : closePal(); }
    else if (e.key === 'Escape' && !pal.hidden) closePal();
  });

  // Electron-Menü kann die Suche öffnen
  window.addEventListener('is:search', openPal);

  route();
})();
