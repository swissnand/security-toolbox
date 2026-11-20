/* Sphera Lens · Prüfen — Wie sieht mich ein Angreifer von aussen? */
(() => {
  'use strict';
  const { register, util } = window.TB;
  const { esc, net, findings, gradeBox, normDomain, isDomain, fmtDate } = util;

  const domainForm = (ph = 'firma.ch', btn = 'Prüfen') => `<div class="panel"><div class="row">
      <input id="dom" class="mono grow" placeholder="${ph}" style="font-size:16px" autocomplete="off" spellcheck="false"/>
      <button class="btn btn-primary" id="go">${window.TB.icon('play')}${btn}</button></div>
      <div class="small muted" style="margin-top:8px">Passive Prüfung öffentlicher DNS-Einträge über Cloudflare DNS-over-HTTPS. Es wird nichts gespeichert.</div></div>
    <div id="res"></div>`;

  const bindDomain = (U, key, run) => {
    const inp = U.q('#dom');
    inp.value = U.store.get(key, '');
    const go = async () => {
      const d = normDomain(inp.value);
      if (!isDomain(d)) { U.q('#res').innerHTML = '<div class="msg err">Bitte eine gültige Domain eingeben, z. B. firma.ch</div>'; return; }
      inp.value = d; U.store.set(key, d);
      U.q('#res').innerHTML = '<div class="panel muted">Prüfe …</div>';
      try { await run(d); } catch (e) { U.q('#res').innerHTML = `<div class="msg err">${esc(e.message)}</div>`; }
    };
    U.q('#go').onclick = go;
    inp.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  };

  const mdReport = (title, target, list) => {
    const s = { ok: '✅', warn: '⚠️', err: '❌', info: 'ℹ️' };
    const strip = (h) => String(h || '').replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/&quot;/g, '"');
    return `# ${title}\n\n**Ziel:** ${target}  \n**Datum:** ${new Date().toLocaleString('de-CH')}  \n**Erstellt mit:** Infosphera Security Toolbox\n\n` +
      list.map((f) => `- ${s[f.s]} **${strip(f.t)}**${f.d ? ' — ' + strip(f.d) : ''}${f.fix ? `\n  - Massnahme: ${strip(f.fix)}` : ''}`).join('\n') + '\n';
  };
  const reportButtons = (U, title, target, list) => {
    const bar = document.createElement('div');
    bar.className = 'row end'; bar.style.marginTop = '12px';
    bar.innerHTML = `<button class="btn btn-sm" data-r="copy">${U.icon('copy')}Bericht kopieren</button><button class="btn btn-sm" data-r="dl">${U.icon('download')}Als Markdown</button>`;
    bar.querySelector('[data-r=copy]').onclick = () => U.copy(mdReport(title, target, list));
    bar.querySelector('[data-r=dl]').onclick = () => U.download(`${title.toLowerCase().replace(/\s+/g, '-')}-${target}.md`, mdReport(title, target, list), 'text/markdown');
    return bar;
  };

  /* ---------- SPF-Analyse (rekursiv, zählt DNS-Lookups) ---------- */
  const spfOf = async (d) => (await net.txt(d)).filter((t) => /^v=spf1(\s|$)/i.test(t));
  const spfAnalyze = async (domain, depth = 0, seen = new Set()) => {
    const node = { domain, record: null, lookups: 0, children: [], issues: [], all: null };
    if (seen.has(domain)) { node.issues.push('Schleife: ' + domain + ' wird mehrfach eingebunden'); return node; }
    seen.add(domain);
    const recs = await spfOf(domain);
    if (!recs.length) { node.issues.push('Kein SPF-Eintrag bei ' + domain); return node; }
    if (recs.length > 1) node.issues.push(`${recs.length} SPF-Einträge bei ${domain} (erlaubt ist genau einer → PermError)`);
    node.record = recs[0];
    const terms = recs[0].split(/\s+/).slice(1);
    for (const t of terms) {
      const m = t.match(/^([+\-~?]?)(include|all|a|mx|ptr|exists|redirect|ip4|ip6)(?=$|[:=/])(?::|=)?(.*)$/i);
      if (!m) { if (t && !/^exp=/i.test(t)) node.issues.push('Unbekannter Ausdruck: ' + t); continue; }
      const mech = m[2].toLowerCase(), arg = m[3];
      if (mech === 'all') node.all = (m[1] || '+') + 'all';
      if (['include', 'a', 'mx', 'ptr', 'exists', 'redirect'].includes(mech)) node.lookups++;
      if (mech === 'ptr') node.issues.push('«ptr» ist veraltet (RFC 7208) und sollte entfernt werden');
      if ((mech === 'include' || mech === 'redirect') && arg && depth < 10) {
        const child = await spfAnalyze(arg.toLowerCase(), depth + 1, seen);
        child.via = mech;
        node.children.push(child);
      }
    }
    return node;
  };
  const spfTotal = (n) => n.lookups + n.children.reduce((a, c) => a + spfTotal(c), 0);
  const spfIssues = (n) => [...n.issues, ...n.children.flatMap(spfIssues)];

  /* ================= Mail Security Check ================= */
  const DKIM_SELECTORS = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'smtp', 'mx', 'key1', 'key2', 'sig1', 'mandrill', 'mailjet', 'zoho', 'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3', 'hs1', 'hs2', 'everlytic', 'mxvault', 'cm', 'sendgrid', 's1024', 'infomaniak', 'ik', 'mailo', 'ovh'];

  register({
    id: 'mail-check', name: 'Mail Security Check', glyph: '@', cat: 'lens',
    desc: 'SPF, DKIM, DMARC, MTA-STS, TLS-RPT und BIMI einer Domain prüfen – mit Note und Massnahmen.',
    keywords: 'email spf dkim dmarc mta-sts bimi tls-rpt spoofing phishing mx domain',
    render(root, U) {
      root.innerHTML = domainForm('firma.ch', 'Domain prüfen');
      bindDomain(U, 'mail-dom', async (d) => {
        const [mx, spfRecs, dmarc, sts, rpt, bimi] = await Promise.all([
          net.doh(d, 'MX'), spfOf(d), net.txt('_dmarc.' + d), net.txt('_mta-sts.' + d), net.txt('_smtp._tls.' + d), net.txt('default._bimi.' + d),
        ]);
        const dkimHits = (await Promise.all(DKIM_SELECTORS.map(async (s) => {
          try {
            const r = await net.doh(`${s}._domainkey.${d}`, 'TXT');
            const rec = r.all.filter((a) => a.type === 16).map((a) => a.data.replace(/"\s*"/g, '').replace(/^"|"$/g, '')).find((t) => /v=DKIM1|k=rsa|k=ed25519|p=/i.test(t));
            const cname = r.all.find((a) => a.type === 5);
            return rec || cname ? { s, rec: rec || '', cname: cname ? cname.data : '' } : null;
          } catch { return null; }
        }))).filter(Boolean);

        const F = [];
        const mxs = mx.answers.map((a) => a.data);
        const nullMx = mxs.length === 1 && /^0 \.$/.test(mxs[0]);
        const sendsMail = mxs.length && !nullMx;
        if (nullMx) F.push({ s: 'info', t: 'Null-MX gesetzt', d: 'Die Domain empfängt bewusst keine E-Mails (RFC 7505).', tag: 'MX' });
        else if (mxs.length) F.push({ s: 'ok', t: `${mxs.length} Mailserver (MX)`, d: mxs.map((m) => `<code>${esc(m)}</code>`).join(' '), tag: 'MX' });
        else F.push({ s: 'info', t: 'Keine Mailserver (MX)', d: 'Die Domain empfängt keine E-Mails. Trotzdem sollte sie mit SPF «-all» und DMARC «reject» gegen Missbrauch geschützt sein.', tag: 'MX' });

        // SPF
        if (!spfRecs.length) F.push({ s: 'err', t: 'Kein SPF-Eintrag', d: 'Ohne SPF kann jeder Server E-Mails im Namen dieser Domain versenden.', fix: sendsMail ? 'TXT-Eintrag anlegen, z. B. <code>v=spf1 include:spf.protection.outlook.com -all</code> (je nach Mail-Anbieter).' : 'Für Domains ohne Mailversand: <code>v=spf1 -all</code>', tag: 'SPF' });
        else if (spfRecs.length > 1) F.push({ s: 'err', t: `${spfRecs.length} SPF-Einträge`, d: 'Es darf nur genau einen geben, sonst ist SPF ungültig (PermError).', fix: 'Einträge zu einem zusammenführen.', tag: 'SPF' });
        else {
          const tree = await spfAnalyze(d);
          const total = spfTotal(tree);
          const all = tree.all || (/redirect=/i.test(tree.record) ? 'redirect' : null);
          F.push({ s: 'ok', t: 'SPF vorhanden', d: `<code>${esc(spfRecs[0])}</code>`, tag: 'SPF' });
          if (all === '-all') F.push({ s: 'ok', t: 'SPF endet mit «-all» (strikt)', d: 'Nicht erlaubte Server werden abgelehnt.', tag: 'SPF' });
          else if (all === '~all') F.push({ s: 'warn', t: 'SPF endet mit «~all» (Softfail)', d: 'Fremde Server werden nur markiert, nicht abgelehnt. Zusammen mit DMARC «reject» ist das akzeptabel.', fix: 'Wenn alle Versender erfasst sind, auf «-all» wechseln.', tag: 'SPF' });
          else if (all === 'redirect') F.push({ s: 'info', t: 'SPF verweist per redirect', d: 'Die Regel wird von einer anderen Domain übernommen.', tag: 'SPF' });
          else F.push({ s: 'err', t: `SPF endet mit «${esc(all || 'nichts')}»`, d: '«+all», «?all» oder ein fehlendes all erlauben praktisch jedem Server den Versand.', fix: 'Mit «-all» oder «~all» abschliessen.', tag: 'SPF' });
          F.push(total > 10 ? { s: 'err', t: `${total} DNS-Lookups (max. 10)`, d: 'Zu viele include/a/mx: Empfänger werten SPF als Fehler.', fix: 'Includes reduzieren oder SPF-Flattening nutzen.', tag: 'SPF' }
            : { s: total > 8 ? 'warn' : 'ok', t: `${total} von 10 DNS-Lookups`, d: total > 8 ? 'Knapp an der Grenze.' : 'Im erlaubten Bereich.', tag: 'SPF' });
          spfIssues(tree).forEach((i) => F.push({ s: 'warn', t: 'SPF-Hinweis', d: esc(i), tag: 'SPF' }));
        }

        // DKIM
        if (dkimHits.length) F.push({ s: 'ok', t: `DKIM gefunden (${dkimHits.length} Selektor${dkimHits.length > 1 ? 'en' : ''})`, d: dkimHits.map((h) => `<code>${esc(h.s)}</code>${h.cname ? ' → ' + esc(h.cname) : ''}`).join(', '), tag: 'DKIM' });
        else F.push({ s: sendsMail ? 'warn' : 'info', t: 'Kein DKIM unter gängigen Selektoren', d: `Geprüft: ${DKIM_SELECTORS.length} übliche Selektoren. DKIM kann trotzdem unter einem anderen Namen existieren (steht im Header «DKIM-Signature: s=…» einer versendeten Mail).`, fix: 'DKIM beim Mail-Anbieter aktivieren und den öffentlichen Schlüssel im DNS veröffentlichen.', tag: 'DKIM' });
        dkimHits.forEach((h) => {
          const p = (h.rec.match(/p=([^;]*)/) || [])[1];
          if (h.rec && p !== undefined && !p.trim()) F.push({ s: 'info', t: `DKIM-Selektor «${h.s}» widerrufen`, d: 'Leerer Schlüssel (p=): Selektor ist deaktiviert.', tag: 'DKIM' });
          else if (p && /k=rsa|^v=DKIM1/i.test(h.rec) && !/k=ed25519/i.test(h.rec) && p.length < 300) F.push({ s: 'warn', t: `DKIM-Schlüssel «${h.s}» vermutlich 1024 Bit`, d: 'Empfohlen sind mindestens 2048 Bit.', fix: 'Neuen 2048-Bit-Schlüssel erzeugen und rotieren.', tag: 'DKIM' });
        });

        // DMARC
        const dm = dmarc.find((t) => /^v=DMARC1/i.test(t));
        if (!dm) F.push({ s: 'err', t: 'Kein DMARC-Eintrag', d: 'Ohne DMARC bleiben gefälschte Absender oft unbemerkt und werden zugestellt.', fix: `TXT bei <code>_dmarc.${esc(d)}</code>: <code>v=DMARC1; p=none; rua=mailto:dmarc@${esc(d)}</code> – nach Auswertung auf quarantine/reject erhöhen.`, tag: 'DMARC' });
        else {
          const tag = (k) => ((dm.match(new RegExp('(?:^|;)\\s*' + k + '\\s*=\\s*([^;]+)', 'i')) || [])[1] || '').trim();
          const p = tag('p').toLowerCase(), pct = tag('pct'), rua = tag('rua'), sp = tag('sp').toLowerCase();
          F.push({ s: 'ok', t: 'DMARC vorhanden', d: `<code>${esc(dm)}</code>`, tag: 'DMARC' });
          if (p === 'reject') F.push({ s: 'ok', t: 'DMARC-Richtlinie «reject»', d: 'Gefälschte Mails werden abgewiesen. Bestmöglicher Schutz.', tag: 'DMARC' });
          else if (p === 'quarantine') F.push({ s: 'ok', t: 'DMARC-Richtlinie «quarantine»', d: 'Gefälschte Mails landen im Spam.', fix: 'Wenn die Berichte sauber sind: auf «reject» erhöhen.', tag: 'DMARC' });
          else F.push({ s: 'warn', t: 'DMARC-Richtlinie «none» (nur Beobachten)', d: 'Gefälschte Mails werden weiterhin zugestellt.', fix: 'Berichte (rua) 2–4 Wochen auswerten, dann auf «quarantine» und später «reject» erhöhen.', tag: 'DMARC' });
          if (pct && +pct < 100) F.push({ s: 'warn', t: `DMARC gilt nur für ${esc(pct)} %`, d: 'Ein Teil der gefälschten Mails ist nicht abgedeckt.', fix: 'pct auf 100 setzen oder entfernen.', tag: 'DMARC' });
          if (sp === 'none' && p !== 'none') F.push({ s: 'warn', t: 'Subdomains ausgenommen (sp=none)', d: 'Angreifer können Subdomains wie rechnung.' + esc(d) + ' fälschen.', tag: 'DMARC' });
          F.push(rua ? { s: 'ok', t: 'DMARC-Berichte aktiviert', d: `<code>${esc(rua)}</code>`, tag: 'DMARC' } : { s: 'warn', t: 'Keine DMARC-Berichte (rua)', d: 'Ohne Berichte siehst du nicht, wer in deinem Namen versendet.', fix: 'rua=mailto:… ergänzen.', tag: 'DMARC' });
        }

        // MTA-STS / TLS-RPT / BIMI
        const stsRec = sts.find((t) => /^v=STSv1/i.test(t));
        if (stsRec) {
          let det = `<code>${esc(stsRec)}</code>`, s = 'ok';
          if (net.isApp) {
            try {
              const pol = await net.get(`https://mta-sts.${d}/.well-known/mta-sts.txt`, { maxBytes: 8192 });
              const mode = ((pol.body || '').match(/mode:\s*(\w+)/) || [])[1];
              det += pol.status === 200 ? ` · Policy: mode <code>${esc(mode || '?')}</code>` : ` · Policy-Datei nicht erreichbar (HTTP ${pol.status})`;
              if (pol.status !== 200) s = 'warn'; else if (mode !== 'enforce') s = 'warn';
            } catch (e) { det += ' · Policy-Datei nicht erreichbar'; s = 'warn'; }
          }
          F.push({ s, t: 'MTA-STS aktiv', d: det + (s === 'warn' ? ' – Modus sollte «enforce» sein.' : ''), tag: 'MTA-STS' });
        } else if (sendsMail) F.push({ s: 'info', t: 'Kein MTA-STS', d: 'MTA-STS erzwingt verschlüsselte Zustellung an deine Mailserver und schützt vor Downgrade-Angriffen.', fix: 'Optional, aber empfohlen für Organisationen mit sensiblen Mails.', tag: 'MTA-STS' });
        const rp = rpt.find((t) => /^v=TLSRPTv1/i.test(t));
        if (rp) F.push({ s: 'ok', t: 'TLS-Reporting aktiv', d: `<code>${esc(rp)}</code>`, tag: 'TLS-RPT' });
        else if (sendsMail) F.push({ s: 'info', t: 'Kein TLS-Reporting', d: 'Liefert Berichte, wenn verschlüsselte Zustellung scheitert.', tag: 'TLS-RPT' });
        const bm = bimi.find((t) => /^v=BIMI1/i.test(t));
        if (bm) F.push({ s: 'ok', t: 'BIMI-Logo hinterlegt', d: `<code>${esc(bm)}</code>`, tag: 'BIMI' });

        F.push(mx.ad ? { s: 'ok', t: 'DNSSEC validiert', d: 'Die DNS-Antworten sind kryptografisch signiert.', tag: 'DNS' } : { s: 'info', t: 'DNSSEC nicht aktiv', d: 'DNS-Antworten sind nicht signiert. Bei .ch/.swiss beim Registrar mit einem Klick aktivierbar.', tag: 'DNS' });

        U.q('#res').innerHTML = `<div class="panel">${gradeBox(F, 'Mail-Sicherheit von ' + d)}</div><div class="panel"><h3>Befunde</h3>${findings(F)}</div>`;
        U.q('#res .panel:last-child').appendChild(reportButtons(U, 'Mail Security Check', d, F));
      });
    },
  });

  /* ================= SPF-Analyse ================= */
  register({
    id: 'spf', name: 'SPF-Analyse', glyph: 'SPF', cat: 'lens',
    desc: 'SPF-Eintrag als Baum auflösen: alle Includes, DNS-Lookups (max. 10) und Fehler.',
    keywords: 'spf include lookup limit permerror sender policy framework',
    render(root, U) {
      root.innerHTML = domainForm('firma.ch', 'Auflösen');
      bindDomain(U, 'spf-dom', async (d) => {
        const tree = await spfAnalyze(d);
        const total = spfTotal(tree);
        const draw = (n, lvl = 0) => `<div style="margin-left:${lvl * 22}px;padding:8px 10px;border-left:2px solid ${lvl ? 'var(--border-strong)' : 'var(--accent-text)'};margin-bottom:6px">
            <div class="row"><b class="mono">${esc(n.domain)}</b>${n.via ? `<span class="badge">${esc(n.via)}</span>` : ''}<span class="spacer"></span><span class="small muted">${n.lookups} Lookup${n.lookups === 1 ? '' : 's'} direkt · ${spfTotal(n)} total</span></div>
            <div class="mono small" style="margin-top:4px;word-break:break-all;color:var(--text-2)">${n.record ? esc(n.record).replace(/(include:|redirect=|ip4:|ip6:|[-~?+]?all\b)/g, '<b style="color:var(--accent-text)">$1</b>') : '<span style="color:var(--err)">kein SPF</span>'}</div>
            ${n.issues.map((i) => `<div class="small" style="color:var(--warn);margin-top:3px">! ${esc(i)}</div>`).join('')}
          </div>${n.children.map((c) => draw(c, lvl + 1)).join('')}`;
        U.q('#res').innerHTML = `<div class="panel"><div class="stat-grid">
            <div class="stat"><b style="color:${total > 10 ? 'var(--err)' : total > 8 ? 'var(--warn)' : 'var(--ok)'}">${total}/10</b><span>DNS-Lookups</span></div>
            <div class="stat"><b>${esc(tree.all || '–')}</b><span>Abschluss</span></div>
            <div class="stat"><b>${spfIssues(tree).length}</b><span>Hinweise</span></div></div></div>
          <div class="panel"><h3>Auflösung</h3>${draw(tree)}</div>`;
      });
    },
  });

  /* ================= DMARC-Generator ================= */
  register({
    id: 'dmarc-gen', name: 'DMARC-Generator', glyph: 'DM', cat: 'lens',
    desc: 'DMARC-Eintrag zusammenstellen, inkl. Einführungsplan von «none» bis «reject».',
    keywords: 'dmarc record generator policy reject quarantine rua ruf',
    render(root, U) {
      root.innerHTML = `<div class="cols"><div class="panel"><h3>Einstellungen</h3>
          <div class="field"><div class="label">Domain</div><input id="d" class="mono" placeholder="firma.ch"/></div>
          <div class="field"><div class="label">Richtlinie (p)</div><div class="seg" id="p"><button data-v="none">none · beobachten</button><button data-v="quarantine">quarantine · Spam</button><button data-v="reject">reject · ablehnen</button></div></div>
          <div class="field"><div class="label">Subdomains (sp)</div><select id="sp"><option value="">wie Hauptdomain</option><option>none</option><option>quarantine</option><option>reject</option></select></div>
          <div class="field"><div class="label">Sammelberichte an (rua)<span class="hint">täglich, XML</span></div><input id="rua" class="mono" placeholder="dmarc@firma.ch"/></div>
          <div class="field"><div class="label">Fehlerberichte an (ruf)<span class="hint">optional, selten unterstützt</span></div><input id="ruf" class="mono" placeholder=""/></div>
          <div class="cols"><div class="field"><div class="label">Anteil (pct)</div><input id="pct" type="number" min="1" max="100" value="100"/></div>
          <div class="field"><div class="label">Ausrichtung DKIM / SPF</div><div class="row"><select id="adkim"><option value="r">DKIM relaxed</option><option value="s">DKIM strict</option></select><select id="aspf"><option value="r">SPF relaxed</option><option value="s">SPF strict</option></select></div></div></div>
          <button class="btn btn-sm" id="load">${U.icon('refresh')}Bestehenden Eintrag laden</button><span id="lmsg" class="small muted" style="margin-left:8px"></span>
        </div><div><div class="panel"><h3>DNS-Eintrag</h3>
          <div class="kv" id="kv"></div>
          <div class="row end" style="margin-top:10px">${U.copyBtn('#val', 'Wert kopieren')}</div><div id="val" hidden></div></div>
          <div class="panel"><h3>Einführungsplan</h3>${findings([
            { s: 'info', t: 'Woche 0: p=none mit rua', d: 'Nur beobachten. Berichte zeigen, welche Dienste in deinem Namen senden (Newsletter, CRM, Rechnungssoftware).', tag: '1' },
            { s: 'info', t: 'Woche 2–4: alle Versender mit SPF/DKIM ausrichten', d: 'Jeden legitimen Dienst in SPF aufnehmen und DKIM beim Dienst aktivieren.', tag: '2' },
            { s: 'warn', t: 'Danach: p=quarantine (evtl. pct=25 → 100)', d: 'Fälschungen landen im Spam. Berichte weiter beobachten.', tag: '3' },
            { s: 'ok', t: 'Ziel: p=reject', d: 'Fälschungen werden abgewiesen. Für Domains ohne Mailversand direkt reject setzen.', tag: '4' },
          ])}</div></div></div>`;
      let p = 'none';
      const seg = U.q('#p');
      const upd = () => {
        seg.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.v === p));
        const d = normDomain(U.q('#d').value) || 'firma.ch';
        const parts = ['v=DMARC1', 'p=' + p];
        if (U.q('#sp').value) parts.push('sp=' + U.q('#sp').value);
        const pct = +U.q('#pct').value; if (pct && pct < 100) parts.push('pct=' + pct);
        const mails = (v) => v.split(/[,;\s]+/).filter(Boolean).map((m) => 'mailto:' + m.replace(/^mailto:/, '')).join(',');
        if (U.q('#rua').value.trim()) parts.push('rua=' + mails(U.q('#rua').value));
        if (U.q('#ruf').value.trim()) { parts.push('ruf=' + mails(U.q('#ruf').value)); parts.push('fo=1'); }
        if (U.q('#adkim').value === 's') parts.push('adkim=s');
        if (U.q('#aspf').value === 's') parts.push('aspf=s');
        const val = parts.join('; ');
        U.q('#val').textContent = val;
        U.q('#kv').innerHTML = U.kv([['Typ', 'TXT'], ['Name', '_dmarc.' + d], ['Wert', val], ['TTL', '3600']]);
      };
      seg.onclick = (e) => { const b = e.target.closest('button'); if (b) { p = b.dataset.v; upd(); } };
      root.querySelectorAll('input,select').forEach((el) => el.addEventListener('input', upd));
      U.q('#load').onclick = async () => {
        const d = normDomain(U.q('#d').value);
        if (!isDomain(d)) { U.q('#lmsg').textContent = 'Domain fehlt'; return; }
        const rec = (await net.txt('_dmarc.' + d)).find((t) => /^v=DMARC1/i.test(t));
        if (!rec) { U.q('#lmsg').textContent = 'Kein DMARC vorhanden'; return; }
        const get = (k) => ((rec.match(new RegExp('(?:^|;)\\s*' + k + '\\s*=\\s*([^;]+)', 'i')) || [])[1] || '').trim();
        p = get('p').toLowerCase() || 'none';
        U.q('#sp').value = get('sp').toLowerCase();
        U.q('#pct').value = get('pct') || 100;
        U.q('#rua').value = get('rua').replace(/mailto:/g, '');
        U.q('#ruf').value = get('ruf').replace(/mailto:/g, '');
        U.q('#adkim').value = get('adkim') || 'r'; U.q('#aspf').value = get('aspf') || 'r';
        U.q('#lmsg').textContent = 'Geladen: ' + rec;
        upd();
      };
      upd();
    },
  });

  /* ================= DNS & Domain Check ================= */
  const TAKEOVER = [
    ['github.io', 'GitHub Pages'], ['herokuapp.com', 'Heroku'], ['herokudns.com', 'Heroku'], ['azurewebsites.net', 'Azure App Service'], ['cloudapp.net', 'Azure'],
    ['cloudapp.azure.com', 'Azure'], ['trafficmanager.net', 'Azure Traffic Manager'], ['blob.core.windows.net', 'Azure Blob'], ['azureedge.net', 'Azure CDN'],
    ['s3.amazonaws.com', 'AWS S3'], ['s3-website', 'AWS S3'], ['cloudfront.net', 'AWS CloudFront'], ['elasticbeanstalk.com', 'AWS Beanstalk'],
    ['netlify.app', 'Netlify'], ['vercel.app', 'Vercel'], ['surge.sh', 'Surge'], ['bitbucket.io', 'Bitbucket'], ['ghost.io', 'Ghost'],
    ['myshopify.com', 'Shopify'], ['wordpress.com', 'WordPress.com'], ['pantheonsite.io', 'Pantheon'], ['zendesk.com', 'Zendesk'],
    ['readthedocs.io', 'Read the Docs'], ['fly.dev', 'Fly.io'], ['webflow.io', 'Webflow'], ['wixdns.net', 'Wix'], ['helpscoutdocs.com', 'Help Scout'],
  ];
  const SUBS = ['www', 'mail', 'webmail', 'autodiscover', 'shop', 'blog', 'dev', 'staging', 'test', 'api', 'app', 'cdn', 'portal', 'vpn', 'remote', 'docs', 'status', 'help', 'support', 'news', 'm', 'intranet', 'owa', 'cloud', 'files'];

  register({
    id: 'dns-check', name: 'DNS & Domain Check', glyph: 'DNS', cat: 'lens',
    desc: 'DNSSEC, CAA, Nameserver, Wildcards und verwaiste Subdomains (Takeover-Risiko) prüfen.',
    keywords: 'dns dnssec caa nameserver subdomain takeover dangling cname wildcard',
    render(root, U) {
      root.innerHTML = domainForm('firma.ch', 'Domain prüfen');
      bindDomain(U, 'dns-dom', async (d) => {
        const rnd = 'is-' + Math.random().toString(36).slice(2, 10);
        const [ns, soa, ds, caa, a, aaaa, wild] = await Promise.all([
          net.doh(d, 'NS'), net.doh(d, 'SOA'), net.doh(d, 'DS'), net.doh(d, 'CAA'), net.doh(d, 'A'), net.doh(d, 'AAAA'), net.doh(rnd + '.' + d, 'A'),
        ]);
        const F = [];
        if (ns.status === 3) throw new Error('Domain existiert nicht (NXDOMAIN).');
        const nsl = ns.answers.map((x) => x.data);
        F.push(nsl.length >= 2 ? { s: 'ok', t: `${nsl.length} Nameserver`, d: nsl.map((n) => `<code>${esc(n)}</code>`).join(' '), tag: 'NS' }
          : { s: 'warn', t: nsl.length ? 'Nur ein Nameserver' : 'Keine Nameserver gefunden', d: 'Fällt er aus, ist die Domain nicht erreichbar.', fix: 'Mindestens zwei Nameserver in getrennten Netzen.', tag: 'NS' });
        const provs = new Set(nsl.map((n) => n.split('.').slice(-3).join('.')));
        if (nsl.length >= 2 && provs.size === 1) F.push({ s: 'info', t: 'Alle Nameserver beim selben Anbieter', d: 'Üblich, aber ein Ausfall des Anbieters trifft alle.', tag: 'NS' });
        if (soa.answers.length) {
          const p = soa.answers[0].data.split(/\s+/);
          F.push({ s: 'info', t: 'SOA', d: `Primär <code>${esc(p[0])}</code>, Kontakt <code>${esc((p[1] || '').replace('.', '@'))}</code>, Seriennr. <code>${esc(p[2])}</code>`, tag: 'SOA' });
        }
        F.push(ds.answers.length && ns.ad ? { s: 'ok', t: 'DNSSEC aktiv und gültig', d: 'Schützt vor gefälschten DNS-Antworten (Cache Poisoning).', tag: 'DNSSEC' }
          : ds.answers.length ? { s: 'err', t: 'DNSSEC fehlerhaft', d: 'DS-Eintrag vorhanden, aber Validierung schlägt fehl. Die Domain kann für validierende Resolver unerreichbar sein.', fix: 'DNSSEC-Schlüssel beim DNS-Anbieter und DS beim Registrar abgleichen.', tag: 'DNSSEC' }
            : { s: 'warn', t: 'DNSSEC nicht aktiv', d: 'DNS-Antworten sind nicht signiert.', fix: 'Beim DNS-Anbieter aktivieren und DS-Eintrag beim Registrar hinterlegen (bei .ch über den Registrar).', tag: 'DNSSEC' });
        const caal = caa.answers.map((x) => x.data);
        F.push(caal.length ? { s: 'ok', t: 'CAA gesetzt', d: 'Nur diese Zertifizierungsstellen dürfen Zertifikate ausstellen: ' + caal.map((c) => `<code>${esc(c)}</code>`).join(' '), tag: 'CAA' }
          : { s: 'warn', t: 'Kein CAA-Eintrag', d: 'Jede Zertifizierungsstelle darf Zertifikate für diese Domain ausstellen.', fix: `z. B. <code>${esc(d)}. CAA 0 issue "letsencrypt.org"</code> und <code>0 iodef "mailto:security@${esc(d)}"</code>`, tag: 'CAA' });
        F.push(wild.answers.length ? { s: 'warn', t: 'Wildcard-DNS aktiv', d: `Auch zufällige Namen wie <code>${rnd}.${esc(d)}</code> lösen auf. Erschwert Phishing-Erkennung und kann Fehlkonfigurationen verdecken.`, tag: 'DNS' }
          : { s: 'ok', t: 'Kein Wildcard-DNS', d: 'Nur explizit angelegte Namen existieren.', tag: 'DNS' });
        F.push(aaaa.answers.length ? { s: 'info', t: 'IPv6 erreichbar', d: aaaa.answers.map((x) => `<code>${esc(x.data)}</code>`).join(' '), tag: 'IPv6' } : { s: 'info', t: 'Kein IPv6 (AAAA)', d: 'Kein Sicherheitsproblem, nur ein Hinweis.', tag: 'IPv6' });
        if (!a.answers.length) F.push({ s: 'info', t: 'Hauptdomain hat keine IPv4-Adresse', tag: 'A' });

        // Subdomains und verwaiste CNAMEs
        const subRes = await Promise.all(SUBS.map(async (s) => {
          const r = await net.doh(`${s}.${d}`, 'CNAME').catch(() => null);
          const c = r && r.all.find((x) => x.type === 5);
          if (!c) return null;
          const target = c.data.replace(/\.$/, '');
          const t = await net.doh(target, 'A').catch(() => null);
          return { s, target, nx: t && t.status === 3, svc: (TAKEOVER.find(([k]) => target.includes(k)) || [])[1] };
        }));
        const subs = subRes.filter(Boolean);
        subs.forEach((x) => {
          if (x.nx && x.svc) F.push({ s: 'err', t: `Mögliche Subdomain-Übernahme: ${x.s}.${d}`, d: `Zeigt auf <code>${esc(x.target)}</code> (${esc(x.svc)}), das Ziel existiert nicht mehr. Ein Angreifer könnte es registrieren und Inhalte unter deiner Domain ausliefern.`, fix: 'CNAME sofort löschen oder Ziel wieder belegen.', tag: 'Takeover' });
          else if (x.nx) F.push({ s: 'warn', t: `Verwaister CNAME: ${x.s}.${d}`, d: `Ziel <code>${esc(x.target)}</code> existiert nicht.`, fix: 'Eintrag entfernen.', tag: 'CNAME' });
        });
        const live = subs.filter((x) => !x.nx);
        if (!subs.some((x) => x.nx)) F.push({ s: 'ok', t: 'Keine verwaisten CNAMEs gefunden', d: `${SUBS.length} gängige Subdomains geprüft.`, tag: 'Takeover' });

        U.q('#res').innerHTML = `<div class="panel">${gradeBox(F, 'DNS von ' + d)}</div><div class="panel"><h3>Befunde</h3>${findings(F)}</div>
          ${live.length ? `<div class="panel"><h3>Gefundene CNAMEs</h3><div class="tbl-wrap"><table class="tbl"><tr><th>Subdomain</th><th>Ziel</th><th>Dienst</th></tr>${live.map((x) => `<tr><td class="mono">${esc(x.s)}.${esc(d)}</td><td class="mono">${esc(x.target)}</td><td>${esc(x.svc || '')}</td></tr>`).join('')}</table></div></div>` : ''}`;
        U.q('#res .panel:nth-child(2)').appendChild(reportButtons(U, 'DNS Check', d, F));
      });
    },
  });

  /* ================= Web Security Check ================= */
  const TLSN = { TLSv1: 'TLS 1.0', 'TLSv1.1': 'TLS 1.1', 'TLSv1.2': 'TLS 1.2', 'TLSv1.3': 'TLS 1.3' };
  const parseHeaderText = (t) => {
    const h = {};
    t.split(/\r?\n/).forEach((l) => {
      const m = l.match(/^([A-Za-z0-9-]+)\s*:\s*(.*)$/);
      if (!m) return;
      const k = m[1].toLowerCase();
      h[k] = h[k] ? (Array.isArray(h[k]) ? [...h[k], m[2]] : [h[k], m[2]]) : m[2];
    });
    return h;
  };
  const one = (v) => Array.isArray(v) ? v.join(', ') : (v || '');
  const headerFindings = (h, https = true) => {
    const F = [];
    const hsts = one(h['strict-transport-security']);
    if (!https) F.push({ s: 'err', t: 'Keine Verschlüsselung (HTTP)', d: 'Daten werden im Klartext übertragen.', fix: 'TLS-Zertifikat einrichten (z. B. Let\'s Encrypt) und auf HTTPS umleiten.', tag: 'TLS' });
    if (hsts) {
      const ma = +((hsts.match(/max-age=(\d+)/i) || [])[1] || 0);
      F.push(ma >= 15552000 ? { s: 'ok', t: 'HSTS aktiv', d: `<code>${esc(hsts)}</code>`, tag: 'HSTS' } : { s: 'warn', t: 'HSTS mit kurzer Laufzeit', d: `max-age=${ma} (${Math.round(ma / 86400)} Tage). Empfohlen: mindestens 180 Tage.`, fix: '<code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code>', tag: 'HSTS' });
      if (!/includesubdomains/i.test(hsts)) F.push({ s: 'info', t: 'HSTS ohne includeSubDomains', d: 'Subdomains sind nicht abgedeckt.', tag: 'HSTS' });
    } else if (https) F.push({ s: 'err', t: 'Kein HSTS', d: 'Browser könnten auf unverschlüsseltes HTTP zurückfallen (SSL-Stripping).', fix: '<code>Strict-Transport-Security: max-age=31536000; includeSubDomains</code>', tag: 'HSTS' });
    const csp = one(h['content-security-policy']);
    if (csp) {
      const weak = [/'unsafe-inline'/.test(csp) && '\'unsafe-inline\'', /'unsafe-eval'/.test(csp) && '\'unsafe-eval\'', /(^|\s)\*(\s|;|$)/.test(csp) && 'Platzhalter *'].filter(Boolean);
      F.push(weak.length ? { s: 'warn', t: 'CSP vorhanden, aber aufgeweicht', d: 'Enthält ' + weak.join(', ') + '. Das schwächt den Schutz vor Cross-Site-Scripting.', fix: 'Mit dem CSP-Builder schärfen.', tag: 'CSP' } : { s: 'ok', t: 'Content-Security-Policy gesetzt', d: `<code>${esc(csp.slice(0, 220))}${csp.length > 220 ? '…' : ''}</code>`, tag: 'CSP' });
    } else F.push({ s: 'warn', t: 'Keine Content-Security-Policy', d: 'CSP ist der wirksamste Schutz gegen eingeschleuste Skripte (XSS).', fix: 'Mit dem CSP-Builder eine Richtlinie erstellen, zuerst als Report-Only testen.', tag: 'CSP' });
    const xcto = one(h['x-content-type-options']);
    F.push(/nosniff/i.test(xcto) ? { s: 'ok', t: 'X-Content-Type-Options: nosniff', tag: 'Header' } : { s: 'warn', t: 'X-Content-Type-Options fehlt', d: 'Browser könnten Dateien als Skript interpretieren.', fix: '<code>X-Content-Type-Options: nosniff</code>', tag: 'Header' });
    const xfo = one(h['x-frame-options']);
    F.push(xfo || /frame-ancestors/i.test(csp) ? { s: 'ok', t: 'Schutz vor Clickjacking', d: xfo ? `X-Frame-Options: <code>${esc(xfo)}</code>` : 'über CSP frame-ancestors', tag: 'Header' } : { s: 'warn', t: 'Kein Schutz vor Clickjacking', d: 'Die Seite kann unsichtbar in fremde Seiten eingebettet werden.', fix: '<code>Content-Security-Policy: frame-ancestors \'self\'</code> oder <code>X-Frame-Options: DENY</code>', tag: 'Header' });
    const rp = one(h['referrer-policy']);
    F.push(rp ? { s: /unsafe-url|no-referrer-when-downgrade/i.test(rp) ? 'warn' : 'ok', t: 'Referrer-Policy: ' + rp, tag: 'Header' } : { s: 'warn', t: 'Keine Referrer-Policy', d: 'Vollständige URLs (evtl. mit Tokens) gehen an Drittseiten.', fix: '<code>Referrer-Policy: strict-origin-when-cross-origin</code>', tag: 'Header' });
    F.push(h['permissions-policy'] ? { s: 'ok', t: 'Permissions-Policy gesetzt', tag: 'Header' } : { s: 'info', t: 'Keine Permissions-Policy', d: 'Schränkt Kamera, Mikrofon, Standort usw. für eingebettete Inhalte ein.', fix: '<code>Permissions-Policy: camera=(), microphone=(), geolocation=()</code>', tag: 'Header' });
    const srv = one(h.server), xpb = one(h['x-powered-by']);
    if (/\d/.test(srv)) F.push({ s: 'warn', t: 'Server verrät Version', d: `<code>Server: ${esc(srv)}</code> – erleichtert Angreifern die Suche nach passenden Schwachstellen.`, fix: 'Versionsangabe ausblenden (z. B. nginx: server_tokens off; Apache: ServerTokens Prod).', tag: 'Info-Leak' });
    if (xpb) F.push({ s: 'warn', t: 'X-Powered-By sichtbar', d: `<code>${esc(xpb)}</code>`, fix: 'Header entfernen.', tag: 'Info-Leak' });
    const cookies = [].concat(h['set-cookie'] || []);
    cookies.forEach((c) => {
      const name = c.split('=')[0];
      const miss = [!/;\s*secure/i.test(c) && https && 'Secure', !/;\s*httponly/i.test(c) && 'HttpOnly', !/;\s*samesite/i.test(c) && 'SameSite'].filter(Boolean);
      F.push(miss.length ? { s: 'warn', t: `Cookie «${name}» ohne ${miss.join(', ')}`, d: 'Cookies sollten Secure, HttpOnly (falls kein JavaScript-Zugriff nötig) und SameSite tragen.', tag: 'Cookie' } : { s: 'ok', t: `Cookie «${name}» sicher gesetzt`, tag: 'Cookie' });
    });
    return F;
  };

  register({
    id: 'web-check', name: 'Web Security Check', glyph: 'TLS', cat: 'lens',
    desc: 'TLS-Versionen, Zertifikat, HTTPS-Umleitung, Security-Header, Cookies und security.txt mit Note A–F.',
    keywords: 'https tls ssl certificate header hsts csp cookie security.txt website scan grade',
    render(root, U) {
      root.innerHTML = `${U.appOnlyNote('Der Live-Check einer Website')}
        <div class="panel"><div class="row"><input id="dom" class="mono grow" placeholder="https://www.firma.ch" style="font-size:16px" spellcheck="false"/>
        <button class="btn btn-primary" id="go" ${net.isApp ? '' : 'disabled'}>${U.icon('play')}Website prüfen</button></div>
        <div class="small muted" style="margin-top:8px">Ein normaler Seitenaufruf wie im Browser plus ein TLS-Handshake pro Version. Kein Scan, keine Angriffe.</div></div>
        <details class="panel" ${net.isApp ? '' : 'open'}><summary style="cursor:pointer;font-weight:600">Header manuell einfügen und analysieren</summary>
          <div class="field" style="margin-top:12px"><div class="label">Response-Header<span class="hint">z. B. aus <code>curl -sI https://…</code> oder den Entwicklertools</span></div>
          <textarea id="hdr" placeholder="strict-transport-security: max-age=31536000&#10;content-security-policy: default-src 'self'&#10;…"></textarea></div>
          <button class="btn" id="ana">Analysieren</button></details>
        <div id="res"></div>`;
      const inp = U.q('#dom');
      inp.value = U.store.get('web-url', '');
      U.q('#ana').onclick = () => {
        const F = headerFindings(parseHeaderText(U.q('#hdr').value), true);
        U.q('#res').innerHTML = `<div class="panel">${gradeBox(F, 'Security-Header')}</div><div class="panel"><h3>Befunde</h3>${findings(F)}</div>`;
      };
      const go = async () => {
        let url = inp.value.trim();
        if (!url) return;
        if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
        let host;
        try { host = new URL(url).hostname; } catch { U.q('#res').innerHTML = '<div class="msg err">Ungültige Adresse</div>'; return; }
        U.store.set('web-url', url);
        U.q('#res').innerHTML = '<div class="panel muted">Prüfe Verbindung, Zertifikat und Header …</div>';
        try {
          const [r, plain, tv, sec] = await Promise.all([
            net.probe(url.replace(/^http:/i, 'https:')),
            net.probe('http://' + host + '/').catch((e) => ({ error: e.message })),
            net.tlsVersions(host).catch(() => []),
            net.get(`https://${host}/.well-known/security.txt`, { maxBytes: 32768 }).catch(() => null),
          ]);
          const F = [];
          const t = r.tls;
          // HTTPS-Umleitung
          if (plain.error) F.push({ s: 'info', t: 'HTTP (Port 80) nicht erreichbar', d: esc(plain.error), tag: 'TLS' });
          else F.push(/^https:/i.test(plain.url) ? { s: 'ok', t: 'HTTP leitet auf HTTPS um', d: plain.chain.map((c) => `${c.status} <code>${esc(c.url)}</code>`).join(' → '), tag: 'TLS' } : { s: 'err', t: 'Keine Umleitung von HTTP auf HTTPS', d: 'Besucher, die http:// eintippen, bleiben unverschlüsselt.', fix: 'Permanente Umleitung (301) auf https:// einrichten.', tag: 'TLS' });
          // Zertifikat
          if (t && t.cert) {
            const c = t.cert, days = Math.floor((new Date(c.valid_to) - Date.now()) / 86400000);
            F.push(t.authorized ? { s: 'ok', t: 'Zertifikat gültig und vertrauenswürdig', d: `Für <code>${esc(c.subject.CN || '')}</code>, ausgestellt von ${esc(c.issuer.O || c.issuer.CN || '')}`, tag: 'Zertifikat' }
              : { s: 'err', t: 'Zertifikat nicht vertrauenswürdig', d: esc(t.authError || ''), fix: 'Gültiges Zertifikat inkl. Zwischenzertifikaten installieren.', tag: 'Zertifikat' });
            F.push(days < 0 ? { s: 'err', t: 'Zertifikat abgelaufen', d: 'seit ' + fmtDate(c.valid_to), tag: 'Zertifikat' }
              : days < 14 ? { s: 'err', t: `Zertifikat läuft in ${days} Tagen ab`, d: fmtDate(c.valid_to), fix: 'Sofort erneuern und automatische Verlängerung prüfen.', tag: 'Zertifikat' }
                : days < 30 ? { s: 'warn', t: `Zertifikat läuft in ${days} Tagen ab`, d: fmtDate(c.valid_to), tag: 'Zertifikat' }
                  : { s: 'ok', t: `Zertifikat noch ${days} Tage gültig`, d: 'bis ' + fmtDate(c.valid_to), tag: 'Zertifikat' });
            if (c.bits && !c.asn1Curve && c.bits < 2048) F.push({ s: 'err', t: `Schwacher RSA-Schlüssel (${c.bits} Bit)`, fix: 'Mindestens 2048 Bit oder ECDSA P-256.', tag: 'Zertifikat' });
          }
          // TLS-Versionen
          const on = (v) => (tv.find((x) => x.version === v) || {}).ok;
          if (tv.length) {
            const legacy = ['TLSv1', 'TLSv1.1'].filter(on);
            F.push(legacy.length ? { s: 'warn', t: 'Veraltete TLS-Versionen aktiv: ' + legacy.map((v) => TLSN[v]).join(', '), d: 'TLS 1.0 und 1.1 gelten seit 2021 als unsicher (RFC 8996).', fix: 'Auf dem Server nur TLS 1.2 und 1.3 erlauben.', tag: 'TLS' } : { s: 'ok', t: 'Keine veralteten TLS-Versionen', d: 'TLS 1.0/1.1 sind deaktiviert.', tag: 'TLS' });
            F.push(on('TLSv1.3') ? { s: 'ok', t: 'TLS 1.3 unterstützt', tag: 'TLS' } : { s: 'info', t: 'Kein TLS 1.3', d: 'TLS 1.2 reicht, 1.3 ist schneller und moderner.', tag: 'TLS' });
          }
          if (t && t.cipher) F.push({ s: /CBC|RC4|3DES|NULL|EXPORT/i.test(t.cipher.name) ? 'warn' : 'info', t: 'Ausgehandelt: ' + (t.protocol || '') + ' · ' + t.cipher.name, tag: 'TLS' });
          // Header
          F.push(...headerFindings(r.headers, true));
          // security.txt
          if (sec && sec.status === 200 && /contact:/i.test(sec.body || '')) {
            const exp = ((sec.body.match(/^expires:\s*(.+)$/im) || [])[1] || '').trim();
            const expired = exp && new Date(exp) < new Date();
            F.push(expired ? { s: 'warn', t: 'security.txt abgelaufen', d: 'Expires: ' + esc(exp), fix: 'Datum aktualisieren.', tag: 'security.txt' } : { s: 'ok', t: 'security.txt vorhanden', d: 'Sicherheitsforschende wissen, wohin sie Lücken melden können.', tag: 'security.txt' });
          } else F.push({ s: 'warn', t: 'Keine security.txt', d: 'Wer eine Lücke findet, weiss nicht, wem er sie melden soll (RFC 9116).', fix: 'Mit dem security.txt-Generator erstellen und unter /.well-known/security.txt ablegen.', tag: 'security.txt' });
          // Mixed Content
          const mixed = (r.body || '').match(/(?:src|href)\s*=\s*["']http:\/\/[^"']+\.(?:js|css)(?:\?[^"']*)?["']/gi) || [];
          if (mixed.length) F.push({ s: 'warn', t: `${mixed.length} unverschlüsselte Skripte/Stylesheets`, d: mixed.slice(0, 3).map((m) => `<code>${esc(m)}</code>`).join('<br>'), fix: 'Alle Ressourcen über https:// laden.', tag: 'Mixed' });

          const hdrRows = Object.entries(r.headers).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(one(v))}</td></tr>`).join('');
          U.q('#res').innerHTML = `<div class="panel">${gradeBox(F, 'Website ' + host)}</div>
            <div class="panel"><h3>Befunde</h3>${findings(F)}</div>
            <div class="cols"><div class="panel"><h3>Verbindung</h3>${U.kv([
              ['Endadresse', r.url], ['HTTP-Status', r.status + ' ' + (r.statusText || '')], ['IP-Adresse', r.remoteAddress || ''],
              ['Protokoll', t ? t.protocol : ''], ['Cipher', t && t.cipher ? t.cipher.name : ''],
              ['TLS-Versionen', tv.map((x) => (x.ok ? '✓ ' : '✕ ') + TLSN[x.version]).join('   ')],
              ['Weiterleitungen', r.chain.map((c) => c.status).join(' → ')],
            ])}</div><div class="panel"><h3>Zertifikat</h3>${t && t.cert ? U.kv([
              ['Inhaber (CN)', t.cert.subject.CN || ''], ['Organisation', t.cert.subject.O || ''], ['Aussteller', [t.cert.issuer.CN, t.cert.issuer.O].filter(Boolean).join(' · ')],
              ['Gültig ab', fmtDate(t.cert.valid_from)], ['Gültig bis', fmtDate(t.cert.valid_to)], ['Schlüssel', t.cert.asn1Curve ? 'EC ' + t.cert.asn1Curve : 'RSA ' + (t.cert.bits || '') + ' Bit'],
              ['Alternative Namen', (t.cert.subjectaltname || '').replace(/DNS:/g, '')], ['SHA-256', t.cert.fingerprint256 || ''],
            ]) : '<span class="muted">kein TLS</span>'}</div></div>
            <div class="panel"><h3>Alle Response-Header</h3><div class="tbl-wrap"><table class="tbl">${hdrRows}</table></div></div>`;
          U.q('#res .panel:nth-child(2)').appendChild(reportButtons(U, 'Web Security Check', host, F));
        } catch (e) { U.q('#res').innerHTML = `<div class="msg err">${esc(e.message)}</div>`; }
      };
      U.q('#go').onclick = go;
      inp.addEventListener('keydown', (e) => { if (e.key === 'Enter' && net.isApp) go(); });
    },
  });

  /* ================= Zertifikat-Decoder (X.509, ASN.1/DER) ================= */
  const OID = {
    '2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'E',
    '1.2.840.113549.1.1.1': 'RSA', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519',
    '1.2.840.113549.1.1.5': 'SHA1-RSA', '1.2.840.113549.1.1.11': 'SHA256-RSA', '1.2.840.113549.1.1.12': 'SHA384-RSA', '1.2.840.113549.1.1.13': 'SHA512-RSA', '1.2.840.113549.1.1.10': 'RSA-PSS',
    '1.2.840.10045.4.3.2': 'ECDSA-SHA256', '1.2.840.10045.4.3.3': 'ECDSA-SHA384', '1.2.840.10045.4.3.4': 'ECDSA-SHA512', '1.2.840.113549.1.1.4': 'MD5-RSA',
    '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
    '2.5.29.17': 'subjectAltName', '2.5.29.19': 'basicConstraints', '2.5.29.15': 'keyUsage', '2.5.29.37': 'extKeyUsage', '2.5.29.14': 'subjectKeyId', '2.5.29.35': 'authorityKeyId', '2.5.29.31': 'crlDistributionPoints', '2.5.29.32': 'certificatePolicies', '1.3.6.1.5.5.7.1.1': 'authorityInfoAccess', '1.3.6.1.4.1.11129.2.4.2': 'SCT (Certificate Transparency)',
    '1.3.6.1.5.5.7.3.1': 'Serverauthentifizierung', '1.3.6.1.5.5.7.3.2': 'Clientauthentifizierung', '1.3.6.1.5.5.7.3.3': 'Codesignatur', '1.3.6.1.5.5.7.3.4': 'E-Mail-Schutz', '1.3.6.1.5.5.7.3.8': 'Zeitstempel', '1.3.6.1.5.5.7.3.9': 'OCSP-Signatur',
  };
  const der = (b, pos = 0) => {
    const tag = b[pos]; let len = b[pos + 1], hl = 2;
    if (len & 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[pos + 2 + i]; hl = 2 + n; }
    const node = { tag, pos, hl, len, start: pos + hl, end: pos + hl + len };
    if (tag & 0x20) { node.kids = []; let p = node.start; while (p < node.end) { const k = der(b, p); node.kids.push(k); p = k.end; } }
    return node;
  };
  const oidStr = (b, n) => {
    const v = b.subarray(n.start, n.end); const out = [Math.floor(v[0] / 40), v[0] % 40]; let x = 0;
    for (let i = 1; i < v.length; i++) { x = x * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { out.push(x); x = 0; } }
    return out.join('.');
  };
  const str = (b, n) => new TextDecoder().decode(b.subarray(n.start, n.end));
  const timeOf = (b, n) => {
    const s = str(b, n);
    const m = n.tag === 0x17 ? s.match(/^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/) : s.match(/^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/);
    if (!m) return null;
    let y = +m[1]; if (n.tag === 0x17) y += y < 50 ? 2000 : 1900;
    return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  };
  const nameOf = (b, n) => n.kids.map((set) => set.kids.map((atv) => `${OID[oidStr(b, atv.kids[0])] || oidStr(b, atv.kids[0])}=${str(b, atv.kids[1])}`).join('+')).join(', ');
  const hexOf = (b, n) => U8hex(b.subarray(n.start, n.end));
  const U8hex = (a) => Array.from(a, (x) => x.toString(16).padStart(2, '0')).join(':');
  const parseCert = (b) => {
    const cert = der(b); const tbs = cert.kids[0]; const k = tbs.kids; let i = 0;
    let version = 1;
    if (k[0].tag === 0xa0) { version = b[k[0].kids[0].start] + 1; i++; }
    const serial = hexOf(b, k[i++]); const sigAlg = OID[oidStr(b, k[i++].kids[0])] || '?';
    const issuer = nameOf(b, k[i++]); const val = k[i++]; const subject = nameOf(b, k[i++]); const spki = k[i++];
    const algOid = oidStr(b, spki.kids[0].kids[0]); let key = OID[algOid] || algOid;
    if (key === 'RSA') {
      const bs = spki.kids[1]; const inner = der(b, bs.start + 1); const n = inner.kids[0];
      let nb = b.subarray(n.start, n.end); while (nb[0] === 0) nb = nb.subarray(1);
      key = `RSA ${nb.length * 8} Bit`;
    } else if (key === 'EC' && spki.kids[0].kids[1]) key = 'EC ' + (OID[oidStr(b, spki.kids[0].kids[1])] || '');
    const ext = {}; const san = [];
    const extNode = k.slice(i).find((x) => x.tag === 0xa3);
    if (extNode) for (const e of extNode.kids[0].kids) {
      const id = oidStr(b, e.kids[0]); const name = OID[id] || id; const crit = e.kids.length === 3 && b[e.kids[1].start] !== 0;
      const oct = e.kids[e.kids.length - 1]; let val2 = '';
      try {
        const inner = der(b, oct.start);
        if (id === '2.5.29.17') inner.kids.forEach((g) => { if (g.tag === 0x82) san.push(str(b, g)); else if (g.tag === 0x87) { const ip = b.subarray(g.start, g.end); san.push(ip.length === 4 ? Array.from(ip).join('.') : U8hex(ip)); } else if (g.tag === 0x81) san.push(str(b, g)); });
        else if (id === '2.5.29.19') val2 = inner.kids && inner.kids[0] && inner.kids[0].tag === 1 && b[inner.kids[0].start] ? 'CA: ja' : 'CA: nein';
        else if (id === '2.5.29.37') val2 = inner.kids.map((o) => OID[oidStr(b, o)] || oidStr(b, o)).join(', ');
        else if (id === '2.5.29.15') { const names = ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign']; const by = b[inner.start + 1] || 0; val2 = names.filter((_, j) => by & (0x80 >> j)).join(', '); }
      } catch { /* ignore */ }
      ext[name] = (val2 || (id === '2.5.29.17' ? san.join(', ') : 'vorhanden')) + (crit ? ' (kritisch)' : '');
    }
    return { version, serial, sigAlg, issuer, subject, from: timeOf(b, val.kids[0]), to: timeOf(b, val.kids[1]), key, san, ext, der: b.subarray(cert.pos, cert.end) };
  };

  register({
    id: 'cert-decode', name: 'Zertifikat-Decoder', glyph: 'X509', cat: 'lens',
    desc: 'X.509-Zertifikate (PEM/DER) lokal lesen: Inhaber, Laufzeit, Schlüssel, SAN, Fingerprints und Schwächen.',
    keywords: 'x509 certificate pem der crt cer san fingerprint ssl zertifikat decoder chain',
    render(root, U) {
      root.innerHTML = `<div class="panel"><div class="field"><div class="label">Zertifikat(e) im PEM-Format<span class="hint">auch ganze Ketten</span></div>
        <textarea id="in" placeholder="-----BEGIN CERTIFICATE-----&#10;MIIF…&#10;-----END CERTIFICATE-----"></textarea></div>
        <div class="dropzone" id="dz"><b>Datei hierher ziehen</b> oder klicken · .pem .crt .cer .der</div></div><div id="res"></div>`;
      const show = async (blobs) => {
        const out = [];
        for (const b of blobs) {
          try {
            const c = parseCert(b);
            const [s256, s1] = await Promise.all(['SHA-256', 'SHA-1'].map(async (a) => U8hex(new Uint8Array(await crypto.subtle.digest(a, c.der))).toUpperCase()));
            const days = Math.floor((c.to - Date.now()) / 86400000);
            const F = [];
            F.push(days < 0 ? { s: 'err', t: 'Abgelaufen', d: 'seit ' + fmtDate(c.to) } : days < 30 ? { s: 'warn', t: `Läuft in ${days} Tagen ab` } : { s: 'ok', t: `Noch ${days} Tage gültig` });
            if (c.from > new Date()) F.push({ s: 'warn', t: 'Noch nicht gültig', d: 'ab ' + fmtDate(c.from) });
            if (c.issuer === c.subject) F.push({ s: 'info', t: 'Selbst signiert', d: 'Normal für Stammzertifikate, für Webserver nur intern akzeptabel.' });
            if (/SHA1|MD5/.test(c.sigAlg)) F.push({ s: 'err', t: 'Veraltete Signatur: ' + c.sigAlg, fix: 'Zertifikat mit SHA-256 neu ausstellen.' });
            const bits = +((c.key.match(/RSA (\d+)/) || [])[1] || 0);
            if (bits && bits < 2048) F.push({ s: 'err', t: `Schwacher Schlüssel (${bits} Bit)` });
            const life = Math.round((c.to - c.from) / 86400000);
            if (life > 398 && !/CA: ja/.test(c.ext.basicConstraints || '')) F.push({ s: 'info', t: `Laufzeit ${life} Tage`, d: 'Öffentliche TLS-Zertifikate dürfen höchstens 398 Tage gültig sein; die Branche senkt das schrittweise weiter.' });
            out.push(`<div class="panel"><h3>${esc((c.subject.match(/CN=([^,]+)/) || [])[1] || c.subject)}</h3>${findings(F)}<div style="margin-top:12px">${U.kv([
              ['Inhaber', c.subject], ['Aussteller', c.issuer], ['Gültig ab', fmtDate(c.from)], ['Gültig bis', fmtDate(c.to)], ['Schlüssel', c.key], ['Signatur', c.sigAlg],
              ['Seriennummer', c.serial.toUpperCase()], ['Version', 'v' + c.version], ['Alternative Namen', c.san.join(', ')],
              ...Object.entries(c.ext).filter(([k2]) => k2 !== 'subjectAltName').map(([k2, v]) => [k2, v]),
              ['SHA-256', s256], ['SHA-1', s1],
            ])}</div></div>`);
          } catch (e) { out.push(`<div class="msg err">Kein gültiges Zertifikat: ${esc(e.message)}</div>`); }
        }
        U.q('#res').innerHTML = out.join('');
      };
      const fromPem = (t) => (t.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || []).map((p) => U.b64ToBytes(p.replace(/-----[^-]+-----|\s/g, '')));
      U.q('#in').addEventListener('input', U.debounce(() => { const p = fromPem(U.q('#in').value); if (p.length) show(p); else U.q('#res').innerHTML = ''; }, 250));
      U.dropzone(U.q('#dz'), async (files) => {
        const buf = new Uint8Array(await U.readFile(files[0], 'buffer'));
        const asText = new TextDecoder().decode(buf);
        if (/BEGIN CERTIFICATE/.test(asText)) { U.q('#in').value = asText; show(fromPem(asText)); } else show([buf]);
      });
    },
  });

  /* ================= security.txt ================= */
  register({
    id: 'security-txt', name: 'security.txt Generator', glyph: 'TXT', cat: 'lens',
    desc: 'security.txt nach RFC 9116 erstellen und prüfen: zeigt Forschenden, wohin sie Lücken melden.',
    keywords: 'security.txt rfc 9116 vulnerability disclosure contact well-known',
    render(root, U) {
      const exp = new Date(Date.now() + 365 * 86400000).toISOString().slice(0, 10);
      root.innerHTML = `<div class="cols"><div class="panel"><h3>Angaben</h3>
          <div class="field"><div class="label">Kontakt (Pflicht)<span class="hint">E-Mail oder https-Formular</span></div><input id="contact" class="mono" placeholder="security@firma.ch"/></div>
          <div class="field"><div class="label">Ablaufdatum (Pflicht)<span class="hint">max. 1 Jahr empfohlen</span></div><input id="expires" type="date" value="${exp}"/></div>
          <div class="field"><div class="label">Sprachen</div><input id="lang" value="de, en"/></div>
          <div class="field"><div class="label">Kanonische URL</div><input id="canon" class="mono" placeholder="https://firma.ch/.well-known/security.txt"/></div>
          <div class="field"><div class="label">Richtlinie (Policy)</div><input id="policy" class="mono" placeholder="https://firma.ch/security-policy"/></div>
          <div class="field"><div class="label">PGP-Schlüssel (Encryption)</div><input id="enc" class="mono" placeholder="https://firma.ch/pgp-key.txt"/></div>
          <div class="field"><div class="label">Danksagungen (Acknowledgments)</div><input id="ack" class="mono" placeholder="https://firma.ch/hall-of-fame"/></div>
        </div><div><div class="panel"><h3>security.txt</h3><textarea id="out" readonly style="min-height:260px"></textarea>
          <div class="row end" style="margin-top:10px">${U.copyBtn('#out')}<button class="btn btn-sm btn-primary" id="dl">${U.icon('download')}Herunterladen</button></div>
          <div class="callout info" style="margin-top:12px">Ablegen unter <code>https://deine-domain/.well-known/security.txt</code> (Textdatei, UTF-8). Ablaufdatum im Kalender eintragen.</div></div>
          <div class="panel"><h3>Bestehende prüfen</h3><div class="row"><input id="chk" class="mono grow" placeholder="firma.ch"/><button class="btn" id="chkGo">Prüfen</button></div><div id="chkRes" style="margin-top:10px"></div></div></div></div>`;
      const upd = () => {
        const c = U.q('#contact').value.trim();
        const contact = !c ? 'mailto:security@firma.ch' : /^https?:|^mailto:|^tel:/i.test(c) ? c : c.includes('@') ? 'mailto:' + c : 'https://' + c;
        const lines = [`# security.txt nach RFC 9116 · erstellt mit der Infosphera Security Toolbox`, `Contact: ${contact}`, `Expires: ${new Date(U.q('#expires').value + 'T23:59:59Z').toISOString().replace('.000', '')}`];
        [['enc', 'Encryption'], ['ack', 'Acknowledgments'], ['canon', 'Canonical'], ['policy', 'Policy']].forEach(([id, k]) => { const v = U.q('#' + id).value.trim(); if (v) lines.push(`${k}: ${v}`); });
        if (U.q('#lang').value.trim()) lines.push('Preferred-Languages: ' + U.q('#lang').value.trim());
        U.q('#out').value = lines.join('\n') + '\n';
      };
      root.querySelectorAll('input:not(#chk)').forEach((e) => e.addEventListener('input', upd));
      U.q('#dl').onclick = () => U.download('security.txt', U.q('#out').value);
      U.q('#chkGo').onclick = async () => {
        const d = normDomain(U.q('#chk').value); const box = U.q('#chkRes');
        if (!isDomain(d)) { box.innerHTML = '<div class="msg err">Domain fehlt</div>'; return; }
        box.innerHTML = '<span class="muted">Lade …</span>';
        try {
          const r = await net.get(`https://${d}/.well-known/security.txt`, { maxBytes: 32768 });
          const body = r.body || '';
          const F = [];
          if (r.status !== 200) F.push({ s: 'err', t: `Nicht gefunden (HTTP ${r.status})` });
          else {
            F.push(/^contact:/im.test(body) ? { s: 'ok', t: 'Contact vorhanden' } : { s: 'err', t: 'Contact fehlt (Pflichtfeld)' });
            const ex = (body.match(/^expires:\s*(.+)$/im) || [])[1];
            F.push(!ex ? { s: 'err', t: 'Expires fehlt (Pflichtfeld)' } : new Date(ex) < new Date() ? { s: 'err', t: 'Abgelaufen: ' + ex } : { s: 'ok', t: 'Gültig bis ' + fmtDate(ex) });
            if (/-----BEGIN PGP SIGNED MESSAGE-----/.test(body)) F.push({ s: 'ok', t: 'Mit PGP signiert' });
          }
          box.innerHTML = findings(F) + (r.status === 200 ? `<div class="out" style="margin-top:10px;max-height:200px;overflow:auto">${esc(body)}</div>` : '');
        } catch (e) { box.innerHTML = `<div class="msg err">${esc(net.isApp ? e.message : 'Im Browser blockiert (CORS). In der Mac-App funktioniert die Prüfung.')}</div>`; }
      };
      upd();
    },
  });

  /* ================= CSP-Builder ================= */
  const CSP_PRESETS = {
    strikt: "default-src 'self';\nscript-src 'self';\nstyle-src 'self';\nimg-src 'self' data:;\nfont-src 'self';\nconnect-src 'self';\nobject-src 'none';\nbase-uri 'none';\nform-action 'self';\nframe-ancestors 'none';\nupgrade-insecure-requests",
    statisch: "default-src 'self';\nimg-src 'self' data: https:;\nstyle-src 'self' 'unsafe-inline';\nobject-src 'none';\nbase-uri 'self';\nframe-ancestors 'self';\nupgrade-insecure-requests",
    fonts: "default-src 'self';\nscript-src 'self';\nstyle-src 'self' https://fonts.googleapis.com;\nfont-src 'self' https://fonts.gstatic.com;\nimg-src 'self' data:;\nobject-src 'none';\nbase-uri 'none';\nframe-ancestors 'none'",
  };
  const cspFindings = (csp) => {
    const dir = {};
    csp.split(';').map((x) => x.trim()).filter(Boolean).forEach((x) => { const [k, ...v] = x.split(/\s+/); dir[k.toLowerCase()] = v; });
    const src = (k) => dir[k] || dir['default-src'] || null;
    const F = [];
    if (!dir['default-src']) F.push({ s: 'warn', t: 'default-src fehlt', d: 'Ohne Standard ist alles erlaubt, was nicht explizit geregelt ist.', fix: "<code>default-src 'self'</code>" });
    const sc = src('script-src');
    if (!sc) F.push({ s: 'err', t: 'Skripte uneingeschränkt', d: 'Weder script-src noch default-src gesetzt.' });
    else {
      if (sc.includes("'unsafe-inline'") && !sc.some((x) => /^'(nonce|sha256|sha384|sha512)-/.test(x))) F.push({ s: 'err', t: "script-src erlaubt 'unsafe-inline'", d: 'Eingeschleuste Inline-Skripte laufen. Damit verliert CSP fast die ganze Schutzwirkung.', fix: 'Inline-Skripte auslagern oder Nonces/Hashes verwenden.' });
      if (sc.includes("'unsafe-eval'")) F.push({ s: 'warn', t: "script-src erlaubt 'unsafe-eval'", d: 'eval() und ähnliche Funktionen sind möglich.' });
      if (sc.some((x) => x === '*' || x === 'https:' || x === 'http:' || x === 'data:')) F.push({ s: 'err', t: 'script-src mit Platzhalter (* / https: / data:)', d: 'Skripte von beliebigen Servern sind erlaubt.' });
      if (sc.includes("'strict-dynamic'")) F.push({ s: 'ok', t: "'strict-dynamic' aktiv", d: 'Moderner Ansatz mit Nonces.' });
      if (!F.some((f) => /script-src/.test(f.t))) F.push({ s: 'ok', t: 'Skriptquellen eingeschränkt', d: sc.map((x) => `<code>${esc(x)}</code>`).join(' ') });
    }
    const ob = src('object-src');
    F.push(ob && ob.includes("'none'") ? { s: 'ok', t: "object-src 'none'", d: 'Keine Plugins (Flash, Java).' } : { s: 'warn', t: "object-src nicht 'none'", fix: "<code>object-src 'none'</code>" });
    F.push(dir['base-uri'] ? { s: 'ok', t: 'base-uri gesetzt' } : { s: 'warn', t: 'base-uri fehlt', d: 'Angreifer könnten mit &lt;base&gt; relative Pfade umleiten.', fix: "<code>base-uri 'none'</code> oder <code>'self'</code>" });
    F.push(dir['frame-ancestors'] ? { s: 'ok', t: 'frame-ancestors gesetzt (Clickjacking-Schutz)' } : { s: 'warn', t: 'frame-ancestors fehlt', d: 'Kein Clickjacking-Schutz über CSP.', fix: "<code>frame-ancestors 'self'</code>" });
    if (dir['form-action'] === undefined) F.push({ s: 'info', t: 'form-action nicht gesetzt', d: 'Formulare könnten an fremde Server senden.' });
    if (Object.values(dir).flat().includes('http:')) F.push({ s: 'warn', t: 'Unverschlüsselte Quellen (http:) erlaubt' });
    return F;
  };

  register({
    id: 'csp', name: 'CSP-Builder & Analyse', glyph: 'CSP', cat: 'lens',
    desc: 'Content-Security-Policy bewerten oder aus Vorlagen bauen, inkl. Ausgabe für nginx, Apache und Vercel.',
    keywords: 'content security policy csp xss header nginx apache vercel builder',
    render(root, U) {
      root.innerHTML = `<div class="cols"><div class="panel"><h3>Richtlinie</h3>
          <div class="row" style="margin-bottom:10px"><span class="small muted">Vorlage:</span><button class="btn btn-sm" data-p="strikt">Strikt</button><button class="btn btn-sm" data-p="statisch">Statische Website</button><button class="btn btn-sm" data-p="fonts">Mit Google Fonts</button></div>
          <textarea id="csp" style="min-height:260px" spellcheck="false"></textarea>
          <label class="check" style="margin-top:10px"><input type="checkbox" id="ro"/> Zuerst nur melden (Report-Only)</label></div>
        <div class="panel"><h3>Bewertung</h3><div id="ana"></div></div></div>
        <div class="panel"><h3>Einbau</h3><div class="seg" id="fmt"><button data-f="header" class="on">HTTP-Header</button><button data-f="nginx">nginx</button><button data-f="apache">Apache</button><button data-f="vercel">vercel.json</button><button data-f="meta">HTML-Meta</button></div>
          <div class="out" id="out" style="margin-top:10px"></div><div class="row end" style="margin-top:8px">${U.copyBtn('#out')}</div></div>`;
      let fmt = 'header';
      const ta = U.q('#csp');
      ta.value = U.store.get('csp', CSP_PRESETS.strikt);
      const upd = () => {
        U.store.set('csp', ta.value);
        const line = ta.value.split(/;|\n/).map((x) => x.trim()).filter(Boolean).join('; ');
        const name = U.q('#ro').checked ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
        U.q('#ana').innerHTML = gradeBox(cspFindings(line), 'CSP') + '<div style="margin-top:12px">' + findings(cspFindings(line)) + '</div>';
        const o = {
          header: `${name}: ${line}`,
          nginx: `add_header ${name} "${line}" always;`,
          apache: `Header always set ${name} "${line}"`,
          vercel: JSON.stringify({ headers: [{ source: '/(.*)', headers: [{ key: name, value: line }] }] }, null, 2),
          meta: U.q('#ro').checked ? '<!-- Report-Only funktioniert nicht als Meta-Tag -->' : `<meta http-equiv="Content-Security-Policy" content="${line.replace(/frame-ancestors[^;]*;?\s*/, '')}">`,
        };
        U.q('#out').textContent = o[fmt];
        U.qa('#fmt button').forEach((b) => b.classList.toggle('on', b.dataset.f === fmt));
      };
      root.querySelectorAll('[data-p]').forEach((b) => { b.onclick = () => { ta.value = CSP_PRESETS[b.dataset.p]; upd(); }; });
      U.q('#fmt').onclick = (e) => { const b = e.target.closest('button'); if (b) { fmt = b.dataset.f; upd(); } };
      ta.addEventListener('input', U.debounce(upd, 150));
      U.q('#ro').onchange = upd;
      upd();
    },
  });

  // für andere Module
  window.TB.lens = { headerFindings, parseHeaderText, spfAnalyze, mdReport };
})();
