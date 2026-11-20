/* Sphera Orbit · Erkennen — Ist etwas faul? Bin ich betroffen? */
(() => {
  'use strict';
  const { register, util } = window.TB;
  const { esc, net, findings, normDomain, isDomain } = util;

  const refang = (s) => s.replace(/hxxp/gi, 'http').replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.').replace(/\[:\]/g, ':').replace(/\[@\]|\[at\]|\(at\)/gi, '@').replace(/\[\/\]/g, '/');
  const defang = (s) => s.replace(/^http/i, 'hxxp').replace(/\./g, '[.]').replace(/@/g, '[@]');
  const MULTI = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'co.at', 'or.at', 'gv.at', 'co.nz', 'com.br', 'co.jp', 'co.za', 'com.tr', 'com.cn', 'github.io', 'vercel.app', 'netlify.app', 'pages.dev', 'web.app', 'firebaseapp.com', 'herokuapp.com', 'azurewebsites.net', 'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com', 'square.site', 'godaddysites.com', 'ngrok.io', 'ngrok-free.app', 'r2.dev', 'workers.dev', 'glitch.me', 'repl.co'];
  const regDomain = (h) => {
    const p = h.split('.');
    if (p.length <= 2) return h;
    const last2 = p.slice(-2).join('.'), last3 = p.slice(-3).join('.');
    if (MULTI.includes(last2)) return last3;
    if (MULTI.includes(last3) && p.length > 3) return p.slice(-4).join('.');
    return last2;
  };
  // Punycode-Decoder (RFC 3492) für IDN-Anzeige
  const punyDecode = (input) => {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const adapt = (delta, num, first) => { delta = first ? Math.floor(delta / damp) : delta >> 1; delta += Math.floor(delta / num); let k = 0; while (delta > 455) { delta = Math.floor(delta / 35); k += base; } return k + Math.floor(36 * delta / (delta + skew)); };
    const out = []; let i = 0, n = 128, bias = 72;
    const b = input.lastIndexOf('-'); for (let j = 0; j < (b < 0 ? 0 : b); j++) out.push(input.charCodeAt(j));
    for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
      const oldi = i; let w = 1;
      for (let k = base; ; k += base) {
        const c = input.charCodeAt(idx++); const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        i += digit * w; const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias; if (digit < t) break; w *= base - t;
      }
      bias = adapt(i - oldi, out.length + 1, oldi === 0); n += Math.floor(i / (out.length + 1)); i %= out.length + 1; out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  };
  const unicodeHost = (h) => h.split('.').map((l) => l.startsWith('xn--') ? (() => { try { return punyDecode(l.slice(4)); } catch { return l; } })() : l).join('.');

  /* ================= Passwort-Leak-Check ================= */
  register({
    id: 'pwned', name: 'Passwort-Leak-Check', glyph: 'HIBP', cat: 'orbit',
    desc: 'Prüft, ob ein Passwort in bekannten Datenlecks vorkommt – anonym über k-Anonymity, das Passwort verlässt das Gerät nie.',
    keywords: 'have i been pwned hibp passwort leak breach datenleck k-anonymity kompromittiert',
    render(root, U) {
      root.innerHTML = `<div class="panel"><div class="row"><input id="pw" type="password" class="grow" placeholder="Passwort eingeben" autocomplete="off" style="font-size:16px"/><button class="btn btn-sm btn-ghost" id="eye">anzeigen</button><button class="btn btn-primary" id="go">Prüfen</button></div><div id="res" style="margin-top:14px"></div></div>
        <div class="panel"><h3>So funktioniert es</h3>${findings([
          { s: 'info', t: '1. Das Passwort wird lokal mit SHA-1 gehasht', d: 'Beispiel: «Sommer2024!» → <code>A1B2C…</code> (40 Zeichen). Das Passwort selbst wird nie übertragen.' },
          { s: 'info', t: '2. Nur die ersten 5 Zeichen des Hashs gehen an Have I Been Pwned', d: 'Die Antwort enthält Hunderte Hash-Enden, die mit diesem Präfix beginnen (inkl. Fülldaten).' },
          { s: 'info', t: '3. Der Vergleich passiert auf deinem Gerät', d: 'Niemand ausser dir erfährt, welches Passwort geprüft wurde.' },
        ])}</div>`;
      U.q('#eye').onclick = () => { const i = U.q('#pw'); i.type = i.type === 'password' ? 'text' : 'password'; U.q('#eye').textContent = i.type === 'password' ? 'anzeigen' : 'verbergen'; };
      const go = async () => {
        const pw = U.q('#pw').value; if (!pw) return;
        U.q('#res').innerHTML = '<span class="muted">Prüfe …</span>';
        try {
          const h = U.bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(pw)))).toUpperCase();
          const r = await fetch('https://api.pwnedpasswords.com/range/' + h.slice(0, 5), { headers: { 'Add-Padding': 'true' } });
          if (!r.ok) throw new Error('Dienst nicht erreichbar (' + r.status + ')');
          const line = (await r.text()).split('\n').find((l) => l.startsWith(h.slice(5)));
          const n = line ? +line.split(':')[1] : 0;
          U.q('#res').innerHTML = n > 0
            ? `<div class="finding err"><div class="ic">✕</div><div><b>${U.fmtNum(n, 0)}-mal in Datenlecks gefunden</b><p>Dieses Passwort steht in Listen, mit denen Angreifer automatisiert Konten durchprobieren.</p><div class="fix">Überall ändern, wo es verwendet wird. Neues, einzigartiges Passwort aus dem Passwort-Manager und 2FA aktivieren.</div></div><div></div></div>`
            : `<div class="finding ok"><div class="ic">✓</div><div><b>Nicht in bekannten Lecks gefunden</b><p>Das heisst nicht automatisch, dass es stark ist. Länge (ab 14 Zeichen) und Einzigartigkeit zählen.</p></div><div></div></div>`;
        } catch (e) { U.q('#res').innerHTML = `<div class="msg err">${esc(e.message)}</div>`; }
      };
      U.q('#go').onclick = go;
      U.q('#pw').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    },
  });

  /* ================= Lookalike-Domains ================= */
  const KEYS = { q: 'wa', w: 'qase', e: 'wsdr', r: 'edft', t: 'rfgz', z: 'tghu', u: 'zhji', i: 'ujko', o: 'iklp', p: 'ol', a: 'qwsy', s: 'awedxy', d: 'serfcx', f: 'drtgvc', g: 'ftzhbv', h: 'gzujnb', j: 'huikmn', k: 'jiolm', l: 'kop', y: 'asx', x: 'ysdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk' };
  const GLYPH = { o: ['0'], l: ['1', 'i'], i: ['1', 'l'], e: ['3'], a: ['4'], s: ['5'], b: ['8'], g: ['9', 'q'], m: ['rn', 'nn'], w: ['vv'], d: ['cl'], u: ['v'], n: ['m'] };
  const TLDS = ['ch', 'com', 'net', 'org', 'info', 'swiss', 'li', 'de', 'at', 'co', 'io', 'app', 'online', 'shop', 'site', 'biz', 'eu'];
  const WORDS = ['login', 'secure', 'support', 'portal', 'online', 'konto', 'rechnung', 'invoice', 'service', 'kundendienst', 'ag', 'gmbh', 'mail', 'pay'];
  const lookalikes = (dom) => {
    const parts = dom.split('.'); const tld = parts.length > 2 && MULTI.includes(parts.slice(-2).join('.')) ? parts.slice(-2).join('.') : parts[parts.length - 1];
    const name = dom.slice(0, -(tld.length + 1)).split('.').pop();
    const out = new Map();
    const add = (n, t, kind) => {
      if (!n || (n === name && t === tld)) return;
      const d = `${n}.${t}`;
      if (/^[a-z0-9-]+$/.test(n) && !n.startsWith('-') && !n.endsWith('-') && !out.has(d)) out.set(d, kind);
    };
    for (let i = 0; i < name.length; i++) {
      add(name.slice(0, i) + name.slice(i + 1), tld, 'Buchstabe fehlt');
      add(name.slice(0, i) + name[i] + name.slice(i), tld, 'Buchstabe doppelt');
      if (i < name.length - 1) add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2), tld, 'Vertauscht');
      (KEYS[name[i]] || '').split('').forEach((k) => { add(name.slice(0, i) + k + name.slice(i + 1), tld, 'Tippfehler (Nachbartaste)'); add(name.slice(0, i) + k + name.slice(i), tld, 'Zusatztaste'); });
      (GLYPH[name[i]] || []).forEach((g) => add(name.slice(0, i) + g + name.slice(i + 1), tld, 'Ähnliches Zeichen'));
      if (name.slice(i, i + 2) === 'rn') add(name.slice(0, i) + 'm' + name.slice(i + 2), tld, 'Ähnliches Zeichen');
      if (i > 0) add(name.slice(0, i) + '-' + name.slice(i), tld, 'Bindestrich');
    }
    TLDS.forEach((t) => add(name, t, 'Andere Endung'));
    add(name + tld.replace('.', ''), 'com', 'Endung angehängt');
    WORDS.forEach((w) => { add(`${name}-${w}`, tld, 'Zusatzwort'); add(`${w}-${name}`, tld, 'Zusatzwort'); });
    return [...out.entries()].map(([d, kind]) => ({ d, kind }));
  };
  register({
    id: 'lookalike', name: 'Lookalike-Domains', glyph: 'TYPO', cat: 'orbit',
    desc: 'Tippfehler- und Doppelgänger-Domains erzeugen und prüfen, welche bereits registriert sind und Mail empfangen.',
    keywords: 'typosquatting lookalike domain phishing doppelgänger homoglyph brand protection tippfehler',
    render(root, U) {
      root.innerHTML = `<div class="panel"><div class="row"><input id="dom" class="mono grow" placeholder="firma.ch" style="font-size:16px"/><button class="btn" id="gen">Varianten erzeugen</button><button class="btn btn-primary" id="chk">Registrierte finden</button></div>
        <div class="small muted" style="margin-top:8px">Die Prüfung fragt nur öffentliches DNS ab (Nameserver, Adresse, Mailserver). Registrierte Varianten mit Mailserver sind sofort für Phishing nutzbar.</div></div><div id="res"></div>`;
      U.q('#dom').value = U.store.get('look-dom', '');
      let list = [];
      const draw = (checked) => {
        const reg = list.filter((x) => x.reg);
        U.q('#res').innerHTML = `<div class="panel"><div class="stat-grid"><div class="stat"><b>${list.length}</b><span>Varianten</span></div>${checked ? `<div class="stat"><b style="color:var(--warn)">${reg.length}</b><span>registriert</span></div><div class="stat"><b style="color:var(--err)">${reg.filter((x) => x.mx).length}</b><span>mit Mailserver</span></div>` : ''}</div>
          <div class="row end" style="margin-top:10px"><button class="btn btn-sm" id="csv">${U.icon('download')}CSV</button></div>
          <div class="tbl-wrap" style="margin-top:10px"><table class="tbl"><tr><th>Domain</th><th>Art</th>${checked ? '<th>Status</th><th>IP</th><th>Mail</th>' : ''}</tr>
          ${(checked ? [...reg, ...list.filter((x) => !x.reg)] : list).map((x) => `<tr><td class="mono">${esc(x.d)}</td><td class="small">${esc(x.kind)}</td>${checked ? `<td>${x.reg ? '<span class="badge warn">registriert</span>' : x.err ? '<span class="badge">?</span>' : '<span class="small muted">frei</span>'}</td><td class="mono small">${esc(x.ip || '')}</td><td>${x.mx ? '<span class="badge err">MX</span>' : ''}</td>` : ''}</tr>`).join('')}</table></div>
          ${checked && reg.length ? '<div class="callout" style="margin-top:12px"><b>Nächste Schritte:</b> Wichtige freie Varianten (z. B. andere Endungen) selbst registrieren. Verdächtige registrierte Domains beobachten; bei Missbrauch beim Registrar und bei antiphishing.ch melden.</div>' : ''}</div>`;
        U.q('#csv').onclick = () => U.download('lookalikes.csv', 'domain;art;registriert;ip;mx\n' + list.map((x) => [x.d, x.kind, x.reg ? 'ja' : 'nein', x.ip || '', x.mx ? 'ja' : ''].join(';')).join('\n'), 'text/csv');
      };
      const gen = () => {
        const d = normDomain(U.q('#dom').value);
        if (!isDomain(d)) { U.q('#res').innerHTML = '<div class="msg err">Bitte eine Domain eingeben</div>'; return false; }
        U.store.set('look-dom', d); list = lookalikes(d); draw(false); return true;
      };
      U.q('#gen').onclick = gen;
      U.q('#chk').onclick = async () => {
        if (!gen()) return;
        let i = 0, done = 0;
        const worker = async () => {
          while (i < list.length) {
            const x = list[i++];
            try {
              const ns = await net.doh(x.d, 'NS');
              x.reg = ns.status === 0 && (ns.all.length > 0);
              if (x.reg) {
                const [a, mx] = await Promise.all([net.doh(x.d, 'A'), net.doh(x.d, 'MX')]);
                x.ip = (a.answers[0] || {}).data || ''; x.mx = mx.answers.some((m) => !/^0 \.$/.test(m.data));
              }
            } catch { x.err = true; }
            done++;
            if (done % 20 === 0) U.q('#res .stat-grid').innerHTML = `<div class="stat"><b>${done}/${list.length}</b><span>geprüft …</span></div>`;
          }
        };
        await Promise.all(Array.from({ length: 8 }, worker));
        draw(true);
      };
    },
  });

  /* ================= Link-Prüfer ================= */
  const BRANDS = ['postfinance', 'post', 'ubs', 'raiffeisen', 'zkb', 'credit-suisse', 'swisscom', 'sunrise', 'salt', 'sbb', 'admin', 'estv', 'migros', 'coop', 'twint', 'swissquote', 'bcge', 'bkb', 'lukb', 'valiant', 'galaxus', 'digitec', 'ricardo', 'tutti', 'swisspass', 'paypal', 'microsoft', 'office365', 'outlook', 'apple', 'icloud', 'google', 'amazon', 'netflix', 'dhl', 'dpd', 'fedex', 'ups', 'visa', 'mastercard', 'viseca', 'cembra', 'cornercard', 'whatsapp', 'facebook', 'instagram', 'linkedin', 'docusign', 'dropbox', 'adobe', 'booking', 'airbnb'];
  const SUS_TLD = ['zip', 'mov', 'top', 'xyz', 'click', 'link', 'cyou', 'rest', 'icu', 'buzz', 'sbs', 'cfd', 'quest', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'live', 'monster', 'bond', 'lol', 'support', 'help', 'country', 'kim', 'xin', 'fit', 'loan', 'win', 'bid', 'date'];
  const SHORT = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 's.id', 'rb.gy', 't.ly', 'qrco.de', 'lnkd.in', 'shorturl.gg'];
  const deleet = (s) => s.replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e').replace(/5/g, 's').replace(/4/g, 'a').replace(/rn/g, 'm').replace(/vv/g, 'w');
  register({
    id: 'link-check', name: 'Link-Prüfer', glyph: 'URL', cat: 'orbit',
    desc: 'Verdächtigen Link analysieren, ohne ihn zu öffnen: Täuschungstricks, falsche Marken, IDN-Doppelgänger, Weiterleitungen.',
    keywords: 'phishing link url check verdächtig prüfen idn punycode homograph sms smishing',
    render(root, U) {
      root.innerHTML = `<div class="panel"><div class="field"><div class="label">Link aus Mail, SMS oder Chat<span class="hint">wird nicht aufgerufen</span></div><input id="u" class="mono" placeholder="https://…" style="font-size:15px" spellcheck="false"/></div></div><div id="res"></div>`;
      const run = () => {
        let raw = refang(U.q('#u').value.trim()); if (!raw) { U.q('#res').innerHTML = ''; return; }
        const F = [];
        if (/^(javascript|data|vbscript):/i.test(raw)) { U.q('#res').innerHTML = `<div class="panel">${findings([{ s: 'err', t: 'Kein Weblink, sondern ausführbarer Code (' + esc(raw.split(':')[0]) + ':)', d: 'Nicht öffnen.' }])}</div>`; return; }
        if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = 'http://' + raw;
        let u; try { u = new URL(raw); } catch { U.q('#res').innerHTML = '<div class="msg err">Kein gültiger Link</div>'; return; }
        const host = u.hostname.toLowerCase(); const uni = unicodeHost(host); const reg = regDomain(host); const tld = host.split('.').pop();
        const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[');
        if (u.protocol === 'http:') F.push({ s: 'warn', t: 'Unverschlüsselt (http)', d: 'Seriöse Login- und Zahlungsseiten nutzen immer https. Aber: https allein heisst nicht, dass eine Seite echt ist.' });
        if (u.username || /@/.test(raw.split('/').slice(0, 3).join('/'))) F.push({ s: 'err', t: 'Täuschung mit «@» im Link', d: `Alles vor dem @ wird ignoriert. Der Link führt tatsächlich zu <code>${esc(host)}</code>.` });
        if (isIp) F.push({ s: 'err', t: 'IP-Adresse statt Domain', d: 'Seriöse Dienste verlinken fast nie direkt auf IP-Adressen.' });
        if (host.includes('xn--')) {
          const mixed = /[a-z]/i.test(uni) && /[Ѐ-ӿͰ-Ͽ]/.test(uni);
          F.push({ s: mixed ? 'err' : 'warn', t: mixed ? 'Gemischte Schriften (IDN-Homograph)' : 'Internationalisierte Domain (Punycode)', d: `Angezeigt als <code>${esc(uni)}</code>, technisch <code>${esc(host)}</code>. ${mixed ? 'Kyrillische/griechische Buchstaben imitieren lateinische. Klassischer Phishing-Trick.' : 'Prüfen, ob die Sonderzeichen gewollt sind.'}` });
        }
        const sub = host.slice(0, Math.max(0, host.length - reg.length - 1));
        const regName = reg.split('.')[0];
        const brandHits = BRANDS.filter((b) => (sub.includes(b) || u.pathname.toLowerCase().includes('/' + b) || deleet(regName).includes(b) || deleet(regName.replace(/-/g, '')).includes(b)) && regName !== b && !reg.startsWith(b + '.'));
        const exactBrand = BRANDS.find((b) => regName === b);
        if (brandHits.length && !exactBrand) F.push({ s: 'err', t: `Marke «${brandHits[0]}» im Link, aber fremde Domain`, d: `Die eigentliche Domain ist <code>${esc(reg)}</code>. «${esc(brandHits[0])}» steht nur als Tarnung in ${sub.includes(brandHits[0]) ? 'der Subdomain' : deleet(regName).includes(brandHits[0]) && !regName.includes(brandHits[0]) ? 'leicht veränderter Schreibweise' : 'Domain oder Pfad'}.` });
        if (sub.split('.').filter(Boolean).length >= 3) F.push({ s: 'warn', t: 'Viele Subdomain-Ebenen', d: 'Lange Ketten wie <code>login.konto.bank.example.xyz</code> sollen die echte Domain am Ende verstecken.' });
        if (SUS_TLD.includes(tld)) F.push({ s: 'warn', t: `Häufig missbrauchte Endung .${esc(tld)}`, d: 'Günstige Endungen werden überdurchschnittlich oft für Phishing genutzt.' });
        if (MULTI.includes(reg.split('.').slice(1).join('.')) || /\.(github\.io|vercel\.app|netlify\.app|pages\.dev|web\.app|workers\.dev|r2\.dev|ngrok)/.test(host)) F.push({ s: 'warn', t: 'Gratis-Hosting / Baukasten-Domain', d: `<code>${esc(reg)}</code> kann jede Person in Minuten erstellen.` });
        if (SHORT.includes(host)) F.push({ s: 'warn', t: 'Link-Verkürzer', d: 'Das eigentliche Ziel ist versteckt. Viele Verkürzer zeigen mit «+» am Ende eine Vorschau (z. B. bit.ly/abc+).' });
        if (u.port && !['80', '443'].includes(u.port)) F.push({ s: 'warn', t: `Ungewöhnlicher Port ${esc(u.port)}` });
        const kw = (u.hostname + u.pathname + u.search).toLowerCase().match(/login|log-in|signin|verify|verif|secure|update|konto|account|bestaetig|bestätig|sperr|unlock|passwort|password|rechnung|invoice|paket|zustellung|refund|rückerstattung|bonus|gewinn|wallet|2fa|mfa/g);
        if (kw) F.push({ s: 'warn', t: 'Typische Lockwörter', d: [...new Set(kw)].map((k) => `<code>${esc(k)}</code>`).join(' ') + ' – Druck und Dringlichkeit sind Kernmerkmale von Phishing.' });
        const redir = [...u.searchParams.entries()].find(([k, v]) => /^(url|u|redirect|redir|next|target|dest|destination|continue|return|goto|r)$/i.test(k) && /^https?:|^\/\//i.test(v));
        if (redir) F.push({ s: 'warn', t: 'Weiterleitung auf anderes Ziel', d: `Parameter <code>${esc(redir[0])}</code> leitet weiter nach <code>${esc(redir[1])}</code>.` });
        if (/\.(exe|scr|msi|bat|cmd|js|vbs|iso|img|zip|rar|7z|html?|svg|one|lnk|apk|dmg|pkg)$/i.test(u.pathname)) F.push({ s: 'warn', t: 'Direkter Datei-Download', d: `Endung <code>${esc(u.pathname.split('.').pop())}</code>. Dateien aus unerwarteten Links nicht öffnen.` });
        if (raw.length > 150) F.push({ s: 'info', t: `Sehr langer Link (${raw.length} Zeichen)` });
        if ((u.pathname.match(/%[0-9a-f]{2}/gi) || []).length > 5) F.push({ s: 'info', t: 'Viele kodierte Zeichen', d: 'Kann den eigentlichen Inhalt verschleiern.' });
        const errs = F.filter((f) => f.s === 'err').length, warns = F.filter((f) => f.s === 'warn').length;
        const v = errs ? ['err', 'Wahrscheinlich gefährlich', 'Nicht öffnen, keine Daten eingeben.'] : warns >= 2 ? ['warn', 'Verdächtig', 'Nur öffnen, wenn du den Absender direkt kontaktiert und bestätigt hast.'] : warns ? ['warn', 'Vorsicht', 'Ein Warnzeichen. Absender und Kontext prüfen.'] : ['ok', 'Keine typischen Täuschungsmerkmale', 'Das ist keine Garantie. Neue Phishing-Seiten können unauffällige Links haben.'];
        if (!F.length) F.push({ s: 'ok', t: 'Keine Auffälligkeiten in Aufbau und Domain' });
        U.q('#res').innerHTML = `<div class="panel"><div class="grade-wrap"><div class="grade g-${v[0] === 'err' ? 'F' : v[0] === 'warn' ? 'C' : 'A'}">${v[0] === 'err' ? '✕' : v[0] === 'warn' ? '!' : '✓'}</div><div class="grade-text"><b>${v[1]}</b><span>${v[2]}</span></div></div></div>
          <div class="cols"><div class="panel"><h3>Befunde</h3>${findings(F)}</div><div class="panel"><h3>Zerlegung</h3>${U.kv([['Führt zu Domain', reg], ['Vollständiger Host', host], ...(uni !== host ? [['Angezeigt als', uni]] : []), ['Protokoll', u.protocol.replace(':', '')], ['Pfad', decodeURIComponent(u.pathname)], ['Parameter', u.search], ['Entschärft', defang(u.href)]])}
            <div class="callout info" style="margin-top:12px">Phishing gesehen? Melden bei <a href="https://www.antiphishing.ch" target="_blank" rel="noopener">antiphishing.ch</a> (BACS). Mit dem Mail-Header-Analyse-Tool den Absender prüfen.</div></div></div>`;
      };
      U.q('#u').addEventListener('input', U.debounce(run, 200));
    },
  });

  /* ================= Mail-Header-Analyse ================= */
  const FREEMAIL = ['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'yahoo.de', 'gmx.ch', 'gmx.net', 'gmx.de', 'web.de', 'bluewin.ch', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'aol.com', 'mail.com', 'yandex.com', 'hispeed.ch', 'sunrise.ch'];
  const decodeMime = (s) => s.replace(/=\?([^?]+)\?([BQ])\?([^?]*)\?=/gi, (m, cs, enc, txt) => {
    try {
      const bytes = enc.toUpperCase() === 'B' ? Uint8Array.from(atob(txt), (c) => c.charCodeAt(0))
        : Uint8Array.from(txt.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/gi, (x, h) => String.fromCharCode(parseInt(h, 16))), (c) => c.charCodeAt(0));
      return new TextDecoder(cs).decode(bytes);
    } catch { return m; }
  }).replace(/\?=\s+=\?/g, '');
  const addrOf = (v) => { const m = (v || '').match(/<([^>]+)>/) || (v || '').match(/([^\s<>"]+@[^\s<>"]+)/); return m ? m[1].toLowerCase() : ''; };
  const domOf = (a) => (a.split('@')[1] || '').replace(/>$/, '');
  register({
    id: 'mail-header', name: 'Mail-Header-Analyse', glyph: 'HDR', cat: 'orbit',
    desc: 'Kopfzeilen einer verdächtigen E-Mail auswerten: echter Absender, SPF/DKIM/DMARC, Reply-To-Tricks, Server-Route.',
    keywords: 'email header analyse phishing spoofing received spf dkim dmarc reply-to ceo fraud absender',
    render(root, U) {
      root.innerHTML = `<div class="panel"><div class="field"><div class="label">Original-Header<span class="hint">Outlook: Datei → Eigenschaften · Gmail: ⋮ → Original anzeigen · Apple Mail: Darstellung → Nachricht → Alle Header</span></div>
        <textarea id="in" style="min-height:200px" spellcheck="false" placeholder="Received: from …&#10;From: …&#10;Authentication-Results: …"></textarea></div></div><div id="res"></div>`;
      const run = () => {
        const raw = U.q('#in').value.replace(/\r/g, ''); if (!raw.trim()) { U.q('#res').innerHTML = ''; return; }
        const head = raw.split(/\n\s*\n/)[0].replace(/\n[ \t]+/g, ' ');
        const H = []; head.split('\n').forEach((l) => { const m = l.match(/^([\w-]+):\s*(.*)$/); if (m) H.push([m[1].toLowerCase(), m[2]]); });
        const get = (k) => (H.find(([x]) => x === k) || [])[1] || '';
        const all = (k) => H.filter(([x]) => x === k).map(([, v]) => v);
        const from = decodeMime(get('from')), replyTo = decodeMime(get('reply-to')), rp = get('return-path'), subj = decodeMime(get('subject'));
        const fa = addrOf(from), fd = domOf(fa), rd = domOf(addrOf(replyTo)), rpd = domOf(addrOf(rp));
        const disp = from.replace(/<[^>]+>/, '').replace(/"/g, '').trim();
        const auth = all('authentication-results').join(' ; ') + ' ' + all('arc-authentication-results').join(' ; ');
        const res = (k) => ((auth.match(new RegExp(k + '\\s*=\\s*(\\w+)', 'i')) || [])[1] || '').toLowerCase();
        const spf = res('spf') || ((get('received-spf').match(/^(\w+)/) || [])[1] || '').toLowerCase();
        const dkim = res('dkim'), dmarc = res('dmarc');
        const dkimD = ((get('dkim-signature').match(/\bd=([^;\s]+)/) || [])[1] || '').toLowerCase();
        const F = [];
        F.push(dmarc === 'pass' ? { s: 'ok', t: 'DMARC bestanden', d: 'Die Absenderdomain hat diese Mail autorisiert.', tag: 'DMARC' } : dmarc === 'fail' ? { s: 'err', t: 'DMARC fehlgeschlagen', d: `Die Mail stammt nicht von einem für <code>${esc(fd)}</code> erlaubten Server. Sehr wahrscheinlich gefälscht.`, tag: 'DMARC' } : { s: 'warn', t: dmarc ? 'DMARC: ' + dmarc : 'Kein DMARC-Ergebnis', d: 'Herkunft nicht bestätigt.', tag: 'DMARC' });
        F.push(spf === 'pass' ? { s: 'ok', t: 'SPF bestanden', tag: 'SPF' } : /fail/.test(spf) ? { s: spf === 'softfail' ? 'warn' : 'err', t: 'SPF: ' + spf, d: 'Der sendende Server ist für die Absenderdomain nicht eingetragen.', tag: 'SPF' } : { s: 'info', t: spf ? 'SPF: ' + spf : 'Kein SPF-Ergebnis', tag: 'SPF' });
        F.push(dkim === 'pass' ? { s: dkimD && fd && !fd.endsWith(dkimD) && !dkimD.endsWith(fd) ? 'warn' : 'ok', t: 'DKIM gültig' + (dkimD ? ` (signiert von ${dkimD})` : ''), d: dkimD && fd && !fd.endsWith(dkimD) && !dkimD.endsWith(fd) ? 'Signiert von einer anderen Domain als dem Absender (z. B. Versanddienst). Prüfen.' : '', tag: 'DKIM' } : dkim ? { s: 'err', t: 'DKIM: ' + dkim, d: 'Signatur ungültig: Inhalt verändert oder gefälscht.', tag: 'DKIM' } : { s: 'info', t: 'Keine DKIM-Signatur', tag: 'DKIM' });
        if (replyTo && rd && rd !== fd) F.push({ s: 'err', t: 'Antworten gehen an eine andere Domain', d: `Absender <code>${esc(fa)}</code>, Antwort an <code>${esc(addrOf(replyTo))}</code>. Typisch für CEO-Fraud und Rechnungsbetrug.`, tag: 'Reply-To' });
        const dispMail = (disp.match(/[\w.+-]+@[\w.-]+\.\w+/) || [])[0];
        if (dispMail && dispMail.toLowerCase() !== fa) F.push({ s: 'err', t: 'Anzeigename täuscht eine andere Adresse vor', d: `Angezeigt: «${esc(disp)}», tatsächlich: <code>${esc(fa)}</code>`, tag: 'From' });
        const brand = BRANDS.find((b) => disp.toLowerCase().replace(/\s/g, '').includes(b) && !fd.includes(b));
        if (brand) F.push({ s: 'warn', t: `Anzeigename nennt «${brand}», Domain passt nicht`, d: `Absenderdomain: <code>${esc(fd)}</code>`, tag: 'From' });
        if (FREEMAIL.includes(fd)) F.push({ s: 'info', t: 'Absender nutzt Gratis-Mail (' + fd + ')', d: 'Firmen, Banken und Behörden schreiben nicht von Gmail, GMX oder Bluewin.', tag: 'From' });
        if (rpd && fd && rpd !== fd && !rpd.endsWith('.' + fd)) F.push({ s: 'info', t: 'Return-Path weicht ab', d: `<code>${esc(rpd)}</code> – bei Newsletter-Diensten normal, sonst auffällig.`, tag: 'Return-Path' });
        const mid = get('message-id'); const midD = (mid.match(/@([^>]+)>/) || [])[1];
        if (midD && fd && !midD.toLowerCase().endsWith(fd) && !fd.endsWith(midD.toLowerCase())) F.push({ s: 'info', t: 'Message-ID von anderer Domain', d: `<code>${esc(midD)}</code>`, tag: 'ID' });
        // Received-Kette
        const rec = all('received').reverse().map((r) => {
          const fromH = (r.match(/from\s+(\S+)/i) || [])[1] || '';
          const by = (r.match(/by\s+(\S+)/i) || [])[1] || '';
          const ip = (r.match(/\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{6,})\]/i) || [])[1] || '';
          const dt = new Date((r.split(';').pop() || '').trim());
          return { fromH, by, ip, dt: isNaN(dt) ? null : dt };
        });
        const priv = (ip) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|fe80|fc|fd)/i.test(ip);
        const firstExt = rec.find((r) => r.ip && !priv(r.ip));
        const total = rec.length > 1 && rec[0].dt && rec[rec.length - 1].dt ? (rec[rec.length - 1].dt - rec[0].dt) / 1000 : null;
        if (total !== null && total > 3600) F.push({ s: 'info', t: `Zustellung dauerte ${Math.round(total / 60)} Minuten`, d: 'Lange Verzögerungen können auf Massenversand oder Zwischenstationen hindeuten.', tag: 'Route' });
        const xoip = get('x-originating-ip').replace(/[[\]]/g, '');
        U.q('#res').innerHTML = `<div class="cols"><div class="panel"><h3>Befunde</h3>${findings(F)}</div><div class="panel"><h3>Eckdaten</h3>${U.kv([
          ['Betreff', subj], ['Anzeigename', disp], ['Absender', fa], ['Antwort an', addrOf(replyTo)], ['Return-Path', addrOf(rp)], ['Datum', get('date')],
          ['Erster externer Server', firstExt ? `${firstExt.fromH} [${firstExt.ip}]` : ''], ['X-Originating-IP', xoip], ['Mailprogramm', get('x-mailer') || get('user-agent')], ['Message-ID', mid],
        ])}</div></div>
          ${rec.length ? `<div class="panel"><h3>Server-Route (älteste zuerst)</h3><div class="tbl-wrap"><table class="tbl"><tr><th>#</th><th>Von</th><th>IP</th><th>An</th><th>Zeit</th><th>Δ</th></tr>${rec.map((r, i) => `<tr><td>${i + 1}</td><td class="mono small">${esc(r.fromH)}</td><td class="mono small">${esc(r.ip)}${r.ip && priv(r.ip) ? ' <span class="small muted">privat</span>' : ''}</td><td class="mono small">${esc(r.by)}</td><td class="small">${r.dt ? r.dt.toLocaleString('de-CH') : ''}</td><td class="small mono">${i && r.dt && rec[i - 1].dt ? Math.max(0, Math.round((r.dt - rec[i - 1].dt) / 1000)) + ' s' : ''}</td></tr>`).join('')}</table></div></div>` : ''}`;
      };
      U.q('#in').addEventListener('input', U.debounce(run, 250));
    },
  });

  /* ================= IOC-Extraktor ================= */
  const FILE_EXT = /\.(txt|json|js|ts|py|exe|dll|png|jpe?g|gif|log|html?|php|md|xml|ya?ml|csv|sh|ps1|bat|zip|pdf|docx?|xlsx?|pptx?|conf|ini|cfg|tmp|bak|old|local|lan|internal|sys|dat|lnk|vbs|msi|iso|img|rar|7z|tar|gz|jar|class|so|dylib|plist|db|sqlite|key|pem|crt)$/i;
  register({
    id: 'ioc', name: 'IOC-Extraktor', glyph: 'IOC', cat: 'orbit',
    desc: 'IPs, Domains, URLs, Hashes, E-Mails und CVEs aus Berichten, Mails oder Logs ziehen – entschärft und exportierbar.',
    keywords: 'ioc indicator of compromise extract ip domain hash url defang refang threat intel cti',
    render(root, U) {
      root.innerHTML = `<div class="cols"><div class="panel"><h3>Text</h3><textarea id="in" style="min-height:300px" placeholder="Bericht, Warnmeldung, Mail oder Log einfügen. Entschärfte Angaben wie hxxp://evil[.]com werden erkannt."></textarea>
          <div class="row" style="margin-top:10px"><label class="check"><input type="checkbox" id="priv"/> Private IPs ausblenden</label><label class="check"><input type="checkbox" id="def" checked/> Ausgabe entschärfen</label></div></div>
        <div class="panel"><h3>Gefunden</h3><div id="res" class="muted">Noch nichts.</div><div class="row end" style="margin-top:10px"><button class="btn btn-sm" id="csv">${U.icon('download')}CSV</button><button class="btn btn-sm" id="json">${U.icon('download')}JSON</button><button class="btn btn-sm" id="cp">${U.icon('copy')}Alles kopieren</button></div></div></div>`;
      let found = {};
      const run = () => {
        const t = refang(U.q('#in').value);
        const uniq = (a) => [...new Set(a)];
        const urls = uniq(t.match(/\bhttps?:\/\/[^\s"'<>()[\]{}]+/gi) || []).map((x) => x.replace(/[.,;:]+$/, ''));
        const emails = uniq((t.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g) || []).map((x) => x.toLowerCase()));
        let ipv4 = uniq(t.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []);
        if (U.q('#priv').checked) ipv4 = ipv4.filter((ip) => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.|169\.254\.|255\.)/.test(ip));
        const ipv6 = uniq((t.match(/(?<![\w:])(?:[0-9a-f]{1,4}:){1,7}(?::|[0-9a-f]{1,4})(?::[0-9a-f]{1,4}){0,6}(?![\w:])/gi) || []).filter((x) => x.includes('::') || x.split(':').length >= 6).filter((x) => /[a-f]/i.test(x) || x.includes('::')));
        const sha256 = uniq((t.match(/\b[a-f0-9]{64}\b/gi) || []).map((x) => x.toLowerCase()));
        const sha1 = uniq((t.match(/\b[a-f0-9]{40}\b/gi) || []).map((x) => x.toLowerCase()));
        const md5 = uniq((t.match(/\b[a-f0-9]{32}\b/gi) || []).map((x) => x.toLowerCase()));
        const cve = uniq((t.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((x) => x.toUpperCase()));
        const attck = uniq(t.match(/\bT1\d{3}(?:\.\d{3})?\b/g) || []);
        const emailDoms = new Set(emails.map((e) => e.split('@')[1]));
        const urlHosts = new Set(urls.map((x) => { try { return new URL(x).hostname; } catch { return ''; } }));
        const domains = uniq((t.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi) || []).map((x) => x.toLowerCase()))
          .filter((d) => !FILE_EXT.test(d) && !/^\d+(\.\d+)+$/.test(d) && !emailDoms.has(d) && !urlHosts.has(d) && /\.[a-z]{2,}$/.test(d) && !/^(e\.g|i\.e|z\.b|u\.a|d\.h|bzw|usw)\b/.test(d));
        found = { URLs: urls, Domains: [...urlHosts].filter(Boolean).concat(domains).filter((v, i, a) => a.indexOf(v) === i), 'IPv4': ipv4, 'IPv6': ipv6, 'E-Mails': emails, 'SHA-256': sha256, 'SHA-1': sha1, MD5: md5, CVEs: cve, 'MITRE ATT&CK': attck };
        const df = U.q('#def').checked;
        const show = (k, v) => df && ['URLs', 'Domains', 'IPv4', 'E-Mails'].includes(k) ? defang(v) : v;
        const total = Object.values(found).reduce((a, v) => a + v.length, 0);
        U.q('#res').innerHTML = total ? Object.entries(found).filter(([, v]) => v.length).map(([k, v]) => `<div style="margin-bottom:14px"><div class="row"><b>${esc(k)}</b><span class="badge">${v.length}</span><span class="spacer"></span><button class="btn btn-sm btn-ghost" data-copy-text="${esc(v.map((x) => show(k, x)).join('\n'))}">${U.icon('copy')}</button></div>
          <div class="out" style="margin-top:6px;max-height:180px;overflow:auto">${esc(v.map((x) => show(k, x)).join('\n'))}</div></div>`).join('') : '<span class="muted">Keine Indikatoren gefunden.</span>';
      };
      const flat = () => Object.entries(found).flatMap(([k, v]) => v.map((x) => [k, U.q('#def').checked && ['URLs', 'Domains', 'IPv4', 'E-Mails'].includes(k) ? defang(x) : x]));
      U.q('#csv').onclick = () => U.download('iocs.csv', 'typ;wert\n' + flat().map((r) => r.join(';')).join('\n'), 'text/csv');
      U.q('#json').onclick = () => U.download('iocs.json', JSON.stringify(found, null, 2), 'application/json');
      U.q('#cp').onclick = () => U.copy(flat().map((r) => r[1]).join('\n'));
      U.q('#in').addEventListener('input', U.debounce(run, 250));
      U.q('#priv').onchange = run; U.q('#def').onchange = run;
    },
  });

  /* ================= Log-Auswertung ================= */
  const WINEV = {
    4624: ['Anmeldung erfolgreich', 'info'], 4625: ['Anmeldung fehlgeschlagen', 'warn'], 4634: ['Abmeldung', 'info'], 4648: ['Anmeldung mit expliziten Anmeldedaten', 'info'], 4672: ['Anmeldung mit Admin-Rechten', 'info'],
    4688: ['Neuer Prozess', 'info'], 4697: ['Dienst installiert', 'warn'], 4698: ['Geplante Aufgabe erstellt', 'warn'], 4719: ['Audit-Richtlinie geändert', 'err'], 4720: ['Benutzerkonto erstellt', 'warn'], 4722: ['Benutzerkonto aktiviert', 'warn'],
    4724: ['Passwort zurückgesetzt', 'warn'], 4726: ['Benutzerkonto gelöscht', 'warn'], 4728: ['Zu globaler Gruppe hinzugefügt', 'warn'], 4732: ['Zu lokaler Gruppe hinzugefügt (z. B. Administratoren)', 'err'], 4740: ['Konto gesperrt', 'warn'],
    4756: ['Zu universeller Gruppe hinzugefügt', 'warn'], 4767: ['Konto entsperrt', 'info'], 4771: ['Kerberos-Vorauthentifizierung fehlgeschlagen', 'warn'], 4776: ['NTLM-Anmeldeprüfung', 'info'], 1102: ['Sicherheitslog gelöscht', 'err'], 104: ['Ereignisprotokoll gelöscht', 'err'], 7045: ['Neuer Dienst installiert', 'warn'], 1116: ['Defender: Schadsoftware erkannt', 'err'], 5001: ['Defender: Echtzeitschutz deaktiviert', 'err'],
  };
  const WEB_ATT = [[/wp-login|xmlrpc\.php/i, 'WordPress-Login-Angriffe'], [/\.env|\.git\/|config\.php|\.aws|id_rsa/i, 'Suche nach Konfigurationsdateien'], [/\.\.\/|%2e%2e/i, 'Path Traversal'], [/union(\s|%20|\+)+select|sleep\(|or(\s|%20|\+)+1=1|information_schema/i, 'SQL-Injection-Versuch'], [/<script|%3cscript|javascript:/i, 'XSS-Versuch'], [/\/etc\/passwd|cmd\.exe|\/bin\/sh|powershell/i, 'Befehlsausführung'], [/phpmyadmin|adminer|\/admin|\/manager\/html/i, 'Suche nach Admin-Oberflächen'], [/jndi:|\$\{/i, 'Log4Shell / Template-Injection']];
  register({
    id: 'log-triage', name: 'Log-Auswertung', glyph: 'LOG', cat: 'orbit',
    desc: 'Linux auth.log, Webserver- und Windows-Ereignislogs auswerten: Brute-Force, neue Admins, gelöschte Logs, Web-Angriffe.',
    keywords: 'log auth.log ssh brute force windows event 4625 4720 1102 nginx apache access log triage incident',
    render(root, U) {
      root.innerHTML = `<div class="panel"><div class="dropzone" id="dz"><b>Logdatei hierher ziehen</b> oder klicken · auth.log, secure, access.log, Windows-Export (CSV/Text)</div>
        <textarea id="in" style="margin-top:10px;min-height:140px" placeholder="…oder Logzeilen einfügen"></textarea><div class="small muted" style="margin-top:6px">Auswertung lokal. Windows: Ereignisanzeige → Sicherheit → «Alle Ereignisse speichern unter» → CSV.</div></div><div id="res"></div>`;
      const run = (t) => {
        const lines = t.split(/\r?\n/).filter(Boolean); if (!lines.length) { U.q('#res').innerHTML = ''; return; }
        const fail = {}, failUser = {}, ok = [], sudo = [], users = [], rootSess = [], web = {}, web4 = {}, webIp = {}, win = {};
        let csvIdx = -1;
        const hdr = lines[0].split(/[,;\t]/).map((x) => x.replace(/"/g, '').trim().toLowerCase());
        csvIdx = hdr.findIndex((h) => /^(event id|ereignis-id|eventid|id)$/.test(h));
        lines.forEach((l, n) => {
          let m;
          if ((m = l.match(/Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.a-f:]+)/i)) || (m = l.match(/Invalid user (\S+) from ([\d.a-f:]+)/i))) { fail[m[2]] = (fail[m[2]] || 0) + 1; failUser[m[1]] = (failUser[m[1]] || 0) + 1; }
          else if ((m = l.match(/Accepted (\S+) for (\S+) from ([\d.a-f:]+)/i))) ok.push({ how: m[1], user: m[2], ip: m[3], line: n + 1, ts: l.slice(0, 15) });
          if ((m = l.match(/sudo:\s+(\S+)\s*:.*COMMAND=(.*)$/))) sudo.push({ user: m[1], cmd: m[2], ts: l.slice(0, 15) });
          if ((m = l.match(/new user: name=(\w+)/)) || (m = l.match(/useradd.*?(?:name=|user )'?(\w+)/))) users.push({ user: m[1], ts: l.slice(0, 15), what: 'neuer Benutzer' });
          if ((m = l.match(/(?:usermod|gpasswd).*?(?:add|to group) '?(\w+)'? .*?(sudo|wheel|admin)/i)) || (m = l.match(/add '?(\w+)'? to group '?(sudo|wheel|admin)/i))) users.push({ user: m[1], ts: l.slice(0, 15), what: 'zu ' + m[2] + ' hinzugefügt' });
          if (/session opened for user root/.test(l) && !/sudo|cron|CRON/.test(l)) rootSess.push(l.slice(0, 15));
          if ((m = l.match(/^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) ([^"]*?)(?: HTTP\/[\d.]+)?" (\d{3})/))) {
            const [, ip, , path, st] = m;
            if (+st >= 400) web4[st] = (web4[st] || 0) + 1;
            WEB_ATT.forEach(([re, name]) => { if (re.test(decodeURIComponent(path.replace(/%(?![0-9a-f]{2})/gi, '%25')))) { web[name] = (web[name] || 0) + 1; webIp[ip] = (webIp[ip] || 0) + 1; } });
          }
          let id = null;
          if (csvIdx >= 0 && n > 0) id = +(l.split(/[,;\t](?=(?:[^"]*"[^"]*")*[^"]*$)/)[csvIdx] || '').replace(/"/g, '');
          else if ((m = l.match(/(?:Event ?ID|EventID|Ereignis-ID|EventCode)\D{0,6}(\d{3,4})/i))) id = +m[1];
          if (id && WINEV[id]) win[id] = (win[id] || 0) + 1;
        });
        const F = [];
        const brute = Object.entries(fail).filter(([, c]) => c >= 10).sort((a, b) => b[1] - a[1]);
        if (brute.length) F.push({ s: 'warn', t: `Brute-Force von ${brute.length} IP-Adresse${brute.length > 1 ? 'n' : ''}`, d: brute.slice(0, 5).map(([ip, c]) => `<code>${esc(ip)}</code> ${c}×`).join(', '), fix: 'Passwort-Anmeldung abschalten (nur SSH-Schlüssel) und Fail2ban einsetzen.' });
        const pwned = ok.filter((o) => fail[o.ip] >= 5);
        pwned.forEach((o) => F.push({ s: 'err', t: `Erfolgreiche Anmeldung nach Fehlversuchen: ${o.user} von ${o.ip}`, d: `${fail[o.ip]} Fehlversuche, dann Erfolg (${esc(o.how)}, Zeile ${o.line}). Möglicher Einbruch.`, fix: 'Sofort prüfen: Ist das ein eigener Zugriff? Sonst Konto sperren, Passwort ändern, Playbook «Konto kompromittiert» starten.' }));
        if (ok.some((o) => o.user === 'root')) F.push({ s: 'warn', t: 'Direkte Root-Anmeldungen', d: ok.filter((o) => o.user === 'root').slice(0, 5).map((o) => `${esc(o.ts)} von <code>${esc(o.ip)}</code>`).join(', '), fix: 'PermitRootLogin no' });
        if (ok.some((o) => o.how === 'password')) F.push({ s: 'info', t: `${ok.filter((o) => o.how === 'password').length} Anmeldungen mit Passwort`, d: 'Schlüssel sind sicherer als Passwörter.' });
        users.forEach((u) => F.push({ s: 'warn', t: `Benutzerkonto: ${u.user} ${u.what}`, d: esc(u.ts) + ' – war das geplant?' }));
        if (rootSess.length) F.push({ s: 'info', t: `${rootSess.length} Root-Sitzungen`, d: 'Sitzungen als root (nicht über sudo/cron).' });
        Object.entries(web).forEach(([k, c]) => F.push({ s: 'warn', t: `Web: ${k}`, d: `${c} Anfragen. Meist automatisierte Scanner; prüfen, ob Antworten 200 statt 404 waren.` }));
        Object.entries(win).forEach(([id, c]) => { const [n, s] = WINEV[id]; if (s !== 'info' || id === '4625') F.push({ s: id === '4625' && c < 20 ? 'info' : s, t: `Windows ${id}: ${n}`, d: `${c}×` }); });
        if (!F.length) F.push({ s: 'ok', t: 'Keine auffälligen Muster gefunden', d: 'Das ersetzt keine vollständige Analyse, aber die häufigsten Warnzeichen fehlen.' });
        const top = (o) => Object.entries(o).sort((a, b) => b[1] - a[1]).slice(0, 10);
        U.q('#res').innerHTML = `<div class="panel"><div class="stat-grid"><div class="stat"><b>${U.fmtNum(lines.length, 0)}</b><span>Zeilen</span></div><div class="stat"><b style="color:var(--warn)">${Object.values(fail).reduce((a, b) => a + b, 0)}</b><span>Fehlanmeldungen</span></div><div class="stat"><b>${ok.length}</b><span>erfolgreiche Logins</span></div><div class="stat"><b>${sudo.length}</b><span>sudo-Befehle</span></div><div class="stat"><b>${Object.values(win).reduce((a, b) => a + b, 0)}</b><span>Windows-Ereignisse</span></div></div></div>
          <div class="panel"><h3>Befunde</h3>${findings(F)}</div>
          <div class="cols">${Object.keys(fail).length ? `<div class="panel"><h3>Top-Angreifer-IPs</h3><table class="tbl">${top(fail).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${v}</td></tr>`).join('')}</table></div><div class="panel"><h3>Angegriffene Benutzernamen</h3><table class="tbl">${top(failUser).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${v}</td></tr>`).join('')}</table></div>` : ''}
          ${ok.length ? `<div class="panel"><h3>Erfolgreiche Anmeldungen</h3><div class="tbl-wrap" style="max-height:300px"><table class="tbl"><tr><th>Zeit</th><th>Benutzer</th><th>IP</th><th>Methode</th></tr>${ok.slice(-50).reverse().map((o) => `<tr><td class="small">${esc(o.ts)}</td><td class="mono">${esc(o.user)}</td><td class="mono">${esc(o.ip)}</td><td class="small">${esc(o.how)}</td></tr>`).join('')}</table></div></div>` : ''}
          ${sudo.length ? `<div class="panel"><h3>sudo-Befehle</h3><div class="tbl-wrap" style="max-height:300px"><table class="tbl">${sudo.slice(-50).reverse().map((s) => `<tr><td class="small">${esc(s.ts)}</td><td class="mono">${esc(s.user)}</td><td class="mono small">${esc(s.cmd)}</td></tr>`).join('')}</table></div></div>` : ''}
          ${Object.keys(win).length ? `<div class="panel"><h3>Windows-Ereignisse</h3><table class="tbl">${Object.entries(win).map(([id, c]) => `<tr><td class="mono">${id}</td><td>${esc(WINEV[id][0])}</td><td>${c}</td></tr>`).join('')}</table></div>` : ''}
          ${Object.keys(webIp).length ? `<div class="panel"><h3>Web-Scanner-IPs</h3><table class="tbl">${top(webIp).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td>${v}</td></tr>`).join('')}</table></div>` : ''}</div>`;
      };
      U.q('#in').addEventListener('input', U.debounce(() => run(U.q('#in').value), 300));
      U.dropzone(U.q('#dz'), async (f) => { if (f[0].size > 50 * 1048576) { U.q('#res').innerHTML = '<div class="msg err">Datei grösser als 50 MB. Bitte vorher filtern (z. B. grep).</div>'; return; } run(await U.readFile(f[0])); });
    },
  });

  /* ================= CVSS 3.1 Rechner ================= */
  const CV = {
    AV: { name: 'Angriffsweg', o: { N: ['Netzwerk', 0.85], A: ['Nachbarnetz', 0.62], L: ['Lokal', 0.55], P: ['Physisch', 0.2] } },
    AC: { name: 'Komplexität', o: { L: ['Niedrig', 0.77], H: ['Hoch', 0.44] } },
    PR: { name: 'Benötigte Rechte', o: { N: ['Keine', 0.85], L: ['Niedrig', 0.62], H: ['Hoch', 0.27] } },
    UI: { name: 'Benutzerinteraktion', o: { N: ['Keine', 0.85], R: ['Nötig', 0.62] } },
    S: { name: 'Auswirkungsbereich', o: { U: ['Unverändert', 0], C: ['Verändert', 0] } },
    C: { name: 'Vertraulichkeit', o: { N: ['Keine', 0], L: ['Niedrig', 0.22], H: ['Hoch', 0.56] } },
    I: { name: 'Integrität', o: { N: ['Keine', 0], L: ['Niedrig', 0.22], H: ['Hoch', 0.56] } },
    A: { name: 'Verfügbarkeit', o: { N: ['Keine', 0], L: ['Niedrig', 0.22], H: ['Hoch', 0.56] } },
  };
  const roundup = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };
  const cvss31 = (v) => {
    const g = (k) => CV[k].o[v[k]][1];
    const changed = v.S === 'C';
    const pr = v.PR === 'L' ? (changed ? 0.68 : 0.62) : v.PR === 'H' ? (changed ? 0.5 : 0.27) : 0.85;
    const iss = 1 - (1 - g('C')) * (1 - g('I')) * (1 - g('A'));
    const imp = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
    const ex = 8.22 * g('AV') * g('AC') * pr * g('UI');
    if (imp <= 0) return { score: 0, imp: 0, ex };
    return { score: changed ? roundup(Math.min(1.08 * (imp + ex), 10)) : roundup(Math.min(imp + ex, 10)), imp, ex };
  };
  const sevOf = (s) => s === 0 ? ['keine', 'Keine'] : s < 4 ? ['tief', 'Tief'] : s < 7 ? ['mittel', 'Mittel'] : s < 9 ? ['hoch', 'Hoch'] : ['krit', 'Kritisch'];
  register({
    id: 'cvss', name: 'CVSS-3.1-Rechner', glyph: '9.8', cat: 'orbit',
    desc: 'Schweregrad einer Schwachstelle nach CVSS 3.1 berechnen oder einen Vektor-String entschlüsseln.',
    keywords: 'cvss score rechner vulnerability schwachstelle severity vector base score 3.1',
    render(root, U) {
      const v = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' };
      root.innerHTML = `<div class="panel"><div class="row"><input id="vec" class="mono grow" style="font-size:15px" spellcheck="false"/>${U.copyBtn('#vec')}</div></div>
        <div class="cols"><div class="panel"><div class="cvss-grid" id="g">${Object.entries(CV).map(([k, d]) => `<div class="field"><div class="label">${esc(d.name)} <span class="hint">${k}</span></div><div class="seg" data-k="${k}">${Object.entries(d.o).map(([o, [n]]) => `<button data-o="${o}">${esc(n)}</button>`).join('')}</div></div>`).join('')}</div></div>
        <div class="panel" id="out"></div></div>`;
      const draw = (fromVec) => {
        U.qa('.seg[data-k]').forEach((s) => s.querySelectorAll('button').forEach((b) => b.classList.toggle('on', v[s.dataset.k] === b.dataset.o)));
        const r = cvss31(v); const [cls, name] = sevOf(r.score);
        const vec = 'CVSS:3.1/' + Object.keys(CV).map((k) => k + ':' + v[k]).join('/');
        if (!fromVec) U.q('#vec').value = vec;
        U.q('#out').innerHTML = `<div class="grade-wrap"><div class="grade g-${r.score >= 9 ? 'F' : r.score >= 7 ? 'D' : r.score >= 4 ? 'C' : r.score > 0 ? 'B' : 'none'}" style="font-size:30px">${r.score.toFixed(1)}</div><div class="grade-text"><b>${name}</b><span class="sev ${cls}">${name}</span></div></div>
          <div style="margin-top:16px">${U.kv([['Basiswert', r.score.toFixed(1)], ['Ausnutzbarkeit', r.ex.toFixed(2)], ['Auswirkung', Math.max(0, r.imp).toFixed(2)], ['Vektor', vec]])}</div>
          <div class="callout info" style="margin-top:14px">Der Basiswert beschreibt die Schwachstelle an sich. Für die eigene Priorisierung zählen zusätzlich: Ist das System aus dem Internet erreichbar? Wird die Lücke aktiv ausgenutzt (CISA KEV)? Wie wichtig ist das System?</div>`;
      };
      U.q('#g').onclick = (e) => { const b = e.target.closest('button'); if (!b) return; v[b.closest('.seg').dataset.k] = b.dataset.o; draw(); };
      U.q('#vec').addEventListener('input', () => {
        const s = U.q('#vec').value.replace(/^CVSS:3\.[01]\//i, '');
        s.split('/').forEach((p) => { const [k, o] = p.split(':'); if (CV[k] && CV[k].o[o]) v[k] = o; });
        draw(true);
      });
      draw();
    },
  });
  window.TB.cvss = { cvss31, sevOf };

  /* ================= CVE-Suche ================= */
  register({
    id: 'cve', name: 'CVE-Suche', glyph: 'CVE', cat: 'orbit',
    desc: 'Schwachstelle nachschlagen: Beschreibung, CVSS, aktiv ausgenutzt (CISA KEV), betroffene Produkte und Quellen (NVD).',
    keywords: 'cve nvd vulnerability schwachstelle lookup kev cisa exploited cwe patch',
    render(root, U) {
      root.innerHTML = `<div class="panel"><div class="row"><input id="id" class="mono grow" placeholder="CVE-2024-3094" style="font-size:16px"/><button class="btn btn-primary" id="go">Nachschlagen</button></div>
        <div class="small muted" style="margin-top:8px">Quelle: National Vulnerability Database (NIST). Ohne API-Schlüssel sind wenige Abfragen pro Minute möglich.</div></div><div id="res"></div>`;
      U.q('#id').value = U.store.get('cve-id', '');
      const go = async () => {
        const id = (U.q('#id').value.match(/CVE-\d{4}-\d{4,7}/i) || [''])[0].toUpperCase();
        if (!id) { U.q('#res').innerHTML = '<div class="msg err">Format: CVE-JJJJ-NNNN</div>'; return; }
        U.q('#id').value = id; U.store.set('cve-id', id);
        U.q('#res').innerHTML = '<div class="panel muted">Lade …</div>';
        try {
          const r = await net.get('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + id, { maxBytes: 2 * 1048576, timeout: 20000 });
          if (r.status !== 200) throw new Error(r.status === 403 || r.status === 429 ? 'NVD-Limit erreicht, bitte in einer Minute erneut versuchen.' : 'NVD antwortet mit HTTP ' + r.status);
          const j = JSON.parse(r.body); const c = j.vulnerabilities && j.vulnerabilities[0] && j.vulnerabilities[0].cve;
          if (!c) throw new Error('CVE nicht gefunden.');
          const desc = (c.descriptions.find((d) => d.lang === 'en') || c.descriptions[0] || {}).value || '';
          const m = c.metrics || {};
          const v31 = (m.cvssMetricV31 || m.cvssMetricV30 || [])[0]; const v40 = (m.cvssMetricV40 || [])[0]; const v2 = (m.cvssMetricV2 || [])[0];
          const best = v40 || v31;
          const score = best ? best.cvssData.baseScore : v2 ? v2.cvssData.baseScore : null;
          const [cls, name] = score === null ? ['keine', 'Nicht bewertet'] : sevOf(score);
          const cwe = (c.weaknesses || []).flatMap((w) => w.description.map((d) => d.value)).filter((x) => /CWE-\d/.test(x));
          const cpes = [...new Set((c.configurations || []).flatMap((cf) => cf.nodes.flatMap((n) => n.cpeMatch.filter((x) => x.vulnerable).map((x) => { const p = x.criteria.split(':'); return `${p[3]} ${p[4]}${p[5] && p[5] !== '*' ? ' ' + p[5] : ''}${x.versionEndExcluding ? ' < ' + x.versionEndExcluding : x.versionEndIncluding ? ' ≤ ' + x.versionEndIncluding : ''}${x.versionStartIncluding ? ' (ab ' + x.versionStartIncluding + ')' : ''}`; }))))].slice(0, 30);
          const refs = (c.references || []).slice(0, 20);
          U.q('#res').innerHTML = `<div class="panel"><div class="grade-wrap"><div class="grade g-${score >= 9 ? 'F' : score >= 7 ? 'D' : score >= 4 ? 'C' : score ? 'B' : 'none'}" style="font-size:30px">${score === null ? '–' : score.toFixed(1)}</div><div class="grade-text"><b>${esc(c.id)}</b><span class="sev ${cls}">${esc(name)}</span> <span class="small muted">· ${esc(c.vulnStatus || '')}</span></div></div>
            ${c.cisaExploitAdd ? `<div class="callout warn" style="margin-top:14px"><b>Wird aktiv ausgenutzt (CISA KEV)</b> seit ${esc(c.cisaExploitAdd)}. ${esc(c.cisaVulnerabilityName || '')}<br>${esc(c.cisaRequiredAction || '')}</div>` : ''}
            <p style="margin:14px 0 0;line-height:1.6">${esc(desc)}</p></div>
            <div class="cols"><div class="panel"><h3>Details</h3>${U.kv([
              ['Veröffentlicht', new Date(c.published).toLocaleDateString('de-CH')], ['Zuletzt geändert', new Date(c.lastModified).toLocaleDateString('de-CH')],
              ['CVSS 4.0', v40 ? `${v40.cvssData.baseScore} · ${v40.cvssData.vectorString}` : ''], ['CVSS 3.x', v31 ? `${v31.cvssData.baseScore} · ${v31.cvssData.vectorString}` : ''],
              ['Schwachstellen-Typ', cwe.join(', ')], ['Quelle der Bewertung', best ? best.source : ''],
            ])}</div><div class="panel"><h3>Betroffene Produkte</h3>${cpes.length ? `<div class="out" style="max-height:260px;overflow:auto">${esc(cpes.join('\n'))}</div>` : '<span class="muted">Noch keine Produktzuordnung.</span>'}</div></div>
            <div class="panel"><h3>Quellen und Patches</h3>${refs.map((x) => `<div style="padding:4px 0"><a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.url)}</a> ${(x.tags || []).map((t) => `<span class="badge ${/Patch|Vendor/.test(t) ? 'ok' : /Exploit/.test(t) ? 'err' : ''}">${esc(t)}</span>`).join(' ')}</div>`).join('')}</div>`;
        } catch (e) { U.q('#res').innerHTML = `<div class="msg err">${esc(e.message)}</div>`; }
      };
      U.q('#go').onclick = go;
      U.q('#id').addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
    },
  });

  window.TB.orbit = { refang, defang, regDomain };
})();
