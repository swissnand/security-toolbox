/* Sphera Command · Reagieren — Was tun wir im Ernstfall, wer meldet was bis wann? */
(() => {
  'use strict';
  const { register, util } = window.TB;
  const { esc, findings } = util;
  const BACS_INFO = 'https://www.ncsc.admin.ch/ncsc/de/home/meldepflicht/meldepflicht-info.html';
  const BACS_WHO = 'https://www.ncsc.admin.ch/ncsc/de/home/meldepflicht/meldepflichtige-organisationen.html';
  const BACS_CSH = 'https://www.ncsc.admin.ch/ncsc/de/home/meldepflicht/informationen-csh.html';
  const BACS_REPORT = 'https://www.report.ncsc.admin.ch/de/';
  const pad = (n) => String(n).padStart(2, '0');
  const localInput = (d) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const fmt = (d) => new Date(d).toLocaleString('de-CH', { weekday: 'short', day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });

  /* ================= Cyber-Quick-Check ================= */
  const QC = [
    ['Identifizieren', 'Gibt es eine aktuelle Liste aller Geräte, Konten und Cloud-Dienste?', 'Inventar der Geräte, Software und Cloud-Dienste mit verantwortlicher Person erstellen.', 2],
    ['Identifizieren', 'Ist klar, wer intern für IT-Sicherheit verantwortlich ist?', 'Eine verantwortliche Person und eine Stellvertretung bestimmen, auch wenn ein Dienstleister die IT betreut.', 2],
    ['Schützen', 'Ist Zwei-Faktor-Anmeldung für E-Mail, Cloud und Fernzugriff Pflicht?', '2FA für alle Konten erzwingen, zuerst für Admins, E-Mail und VPN.', 3],
    ['Schützen', 'Werden Betriebssysteme und Programme automatisch aktualisiert?', 'Automatische Updates überall aktivieren; Geräte ohne Hersteller-Support ersetzen.', 3],
    ['Schützen', 'Arbeiten alle im Alltag ohne Administratorrechte?', 'Admin-Rechte entziehen und separate Admin-Konten nur für die Verwaltung verwenden.', 2],
    ['Schützen', 'Nutzen alle einen Passwort-Manager mit einzigartigen Passwörtern?', 'Passwort-Manager für das Team einführen und Passwort-Wiederverwendung beenden.', 2],
    ['Schützen', 'Sind Notebooks und Smartphones verschlüsselt und mit Sperrcode geschützt?', 'BitLocker/FileVault aktivieren, Gerätesperre und Fernlöschung einrichten.', 2],
    ['Schützen', 'Ist die eigene Mail-Domain mit SPF, DKIM und DMARC geschützt?', 'Mit dem Mail Security Check prüfen und DMARC schrittweise auf «reject» bringen.', 2],
    ['Schützen', 'Wurden die Mitarbeitenden im letzten Jahr zu Phishing und Betrug geschult?', 'Kurze, regelmässige Schulung zu Phishing, Rechnungs- und CEO-Betrug durchführen.', 2],
    ['Erkennen', 'Ist auf allen Geräten ein aktueller Virenschutz aktiv und überwacht?', 'Defender/XProtect aktiv halten und Warnungen zentral oder beim Dienstleister auflaufen lassen.', 2],
    ['Erkennen', 'Bekommt jemand Warnungen bei verdächtigen Anmeldungen (z. B. aus dem Ausland)?', 'Anmeldewarnungen in M365/Google aktivieren und an eine überwachte Adresse senden.', 1],
    ['Reagieren', 'Gibt es eine Notfallkarte: Wen rufen wir an, was tun wir zuerst?', 'Notfallkarte erstellen, aushängen und Nummern testen.', 3],
    ['Reagieren', 'Ist geklärt, ob ihr meldepflichtig seid (BACS, EDÖB)?', 'Mit dem Meldepflicht-Assistenten klären und Meldeweg vorbereiten.', 1],
    ['Wiederherstellen', 'Gibt es Backups, die offline oder unveränderbar sind?', 'Mindestens eine Backup-Kopie getrennt vom Netz bzw. unveränderbar (Immutable) aufbewahren.', 3],
    ['Wiederherstellen', 'Wurde die Wiederherstellung aus dem Backup im letzten Jahr getestet?', 'Einen Wiederherstellungstest durchführen und die Dauer festhalten.', 3],
  ];
  register({
    id: 'quick-check', name: 'Cyber-Quick-Check', glyph: 'QC', cat: 'command',
    desc: '15 Fragen in 5 Minuten: Wo steht deine Organisation? Mit Reifegrad und den wichtigsten nächsten Schritten.',
    keywords: 'self assessment selbsttest kmu reifegrad cyber check ikt minimalstandard fragebogen',
    render(root, U) {
      const ans = U.store.get('qc', {});
      root.innerHTML = `<div class="callout">Angelehnt an die fünf Funktionen des IKT-Minimalstandards des Bundes (Identifizieren, Schützen, Erkennen, Reagieren, Wiederherstellen). Antworten bleiben auf diesem Gerät.</div>
        <div class="cols"><div class="panel"><div id="qs"></div></div><div><div class="panel" id="sum"></div><div class="panel"><h3>Nächste Schritte</h3><div id="todo"></div><div class="row end" style="margin-top:12px"><button class="btn btn-sm" id="exp">${U.icon('download')}Ergebnis als Markdown</button><button class="btn btn-sm btn-ghost" id="rs">${U.icon('trash')}Neu beginnen</button></div></div></div></div>`;
      const OPTS = [['2', 'Ja'], ['1', 'Teilweise'], ['0', 'Nein'], ['?', 'Weiss nicht']];
      U.q('#qs').innerHTML = QC.map(([f, q], i) => `<div class="q-row"><div><span class="small muted">${esc(f)}</span><b style="display:block">${esc(q)}</b></div><div class="pill-q" data-i="${i}">${OPTS.map(([v, n]) => `<button data-v="${v}">${n}</button>`).join('')}</div></div>`).join('');
      const draw = () => {
        U.qa('.pill-q').forEach((p) => p.querySelectorAll('button').forEach((b) => b.classList.toggle('on', ans[p.dataset.i] === b.dataset.v)));
        const answered = Object.keys(ans).length;
        const maxW = QC.reduce((a, q) => a + q[3] * 2, 0);
        const got = QC.reduce((a, q, i) => a + (ans[i] && ans[i] !== '?' ? +ans[i] * q[3] : 0), 0);
        const pct = Math.round((got / maxW) * 100);
        const lvl = pct >= 85 ? ['A', 'Gut aufgestellt', 'Halten und regelmässig testen.'] : pct >= 65 ? ['B', 'Solide Basis', 'Einzelne Lücken gezielt schliessen.'] : pct >= 45 ? ['C', 'Lückenhaft', 'Mehrere wichtige Massnahmen fehlen.'] : pct >= 25 ? ['D', 'Verwundbar', 'Ein typischer Angriff hätte gute Chancen.'] : ['F', 'Stark gefährdet', 'Sofort mit den Top-Massnahmen beginnen.'];
        const fn = [...new Set(QC.map((q) => q[0]))].map((f) => { const qs = QC.map((q, i) => [q, i]).filter(([q]) => q[0] === f); const m = qs.reduce((a, [q]) => a + q[3] * 2, 0); const g = qs.reduce((a, [q, i]) => a + (ans[i] && ans[i] !== '?' ? +ans[i] * q[3] : 0), 0); return [f, Math.round((g / m) * 100)]; });
        U.q('#sum').innerHTML = `<div class="grade-wrap"><div class="grade g-${answered ? lvl[0] : 'none'}">${answered ? lvl[0] : '–'}</div><div class="grade-text"><b>${answered ? lvl[1] : 'Noch keine Antworten'}</b><span>${answered ? `${pct} % · ${lvl[2]}` : 'Beantworte die Fragen links.'}</span><div class="small muted" style="margin-top:4px">${answered}/${QC.length} beantwortet</div></div></div>
          <div style="margin-top:16px">${fn.map(([f, p]) => `<div style="margin-bottom:9px"><div class="row small"><span>${esc(f)}</span><span class="spacer"></span><span class="mono">${p} %</span></div><div class="meter"><i style="width:${p}%;background:${p >= 70 ? 'var(--ok)' : p >= 40 ? 'var(--warn)' : 'var(--err)'}"></i></div></div>`).join('')}</div>`;
        const todo = QC.map((q, i) => [q, i]).filter(([, i]) => ans[i] !== undefined && ans[i] !== '2').sort((a, b) => b[0][3] - a[0][3] || (+ans[a[1]] || 0) - (+ans[b[1]] || 0)).slice(0, 6);
        U.q('#todo').innerHTML = todo.length ? findings(todo.map(([q, i]) => ({ s: q[3] === 3 ? 'err' : 'warn', t: q[2], d: ans[i] === '?' ? 'Unklar: zuerst herausfinden.' : ans[i] === '1' ? 'Teilweise umgesetzt.' : 'Fehlt.', tag: q[0] }))) : `<span class="muted">${answered ? 'Keine offenen Punkte. Sehr gut.' : 'Erscheint nach den ersten Antworten.'}</span>`;
        U.store.set('qc', ans);
        return { pct, lvl, fn, todo };
      };
      U.q('#qs').onclick = (e) => { const b = e.target.closest('button'); if (!b) return; ans[b.parentElement.dataset.i] = b.dataset.v; draw(); };
      U.q('#rs').onclick = () => { Object.keys(ans).forEach((k) => delete ans[k]); draw(); };
      U.q('#exp').onclick = () => {
        const r = draw(); const N = { 2: 'Ja', 1: 'Teilweise', 0: 'Nein', '?': 'Weiss nicht' };
        U.download('cyber-quick-check.md', `# Cyber-Quick-Check\n\nDatum: ${new Date().toLocaleDateString('de-CH')}  \nErgebnis: **${r.lvl[0]} · ${r.lvl[1]}** (${r.pct} %)\n\n## Nach Funktion\n\n${r.fn.map(([f, p]) => `- ${f}: ${p} %`).join('\n')}\n\n## Nächste Schritte\n\n${r.todo.map(([q]) => `1. ${q[2]}`).join('\n')}\n\n## Antworten\n\n${QC.map((q, i) => `- ${q[1]} → **${N[ans[i]] || '–'}**`).join('\n')}\n\n_Erstellt mit der Infosphera Security Toolbox_\n`, 'text/markdown');
      };
      draw();
    },
  });

  /* ================= Notfallkarte ================= */
  const NK_DEFAULT = {
    org: '', it: '', itTel: '', vert: '', vertTel: '', msp: '', mspTel: '', gl: '', glTel: '', vers: '', versNr: '', bank: '',
    steps: 'Ruhe bewahren. Nichts löschen, nichts ausschalten.\nBetroffenes Gerät vom Netz trennen: LAN-Kabel ziehen, WLAN aus.\nSofort die IT-Notfallnummer anrufen.\nNotieren: Was ist passiert, wann, welche Meldung? Foto vom Bildschirm.\nKeine Lösegeldforderung beantworten, keine Zahlungen auslösen.',
    dont: 'Nicht selbst «reparieren», keine Backups anschliessen, Vorfall nicht verschweigen. Wer schnell meldet, hilft allen.',
  };
  register({
    id: 'notfallkarte', name: 'Notfallkarte', glyph: 'SOS', cat: 'command',
    desc: 'Eine Seite für den Ernstfall: erste Schritte, Notfallnummern, Versicherung, Meldestellen. Zum Ausdrucken und Aufhängen.',
    keywords: 'notfall notfallkarte incident response kontakt ernstfall plan aushang drucken poster',
    render(root, U) {
      const d = Object.assign({}, NK_DEFAULT, U.store.get('nk', {}));
      const f = (k, label, ph = '', type = 'text') => `<div class="field"><div class="label">${label}</div><input data-k="${k}" type="${type}" value="${esc(d[k])}" placeholder="${esc(ph)}"/></div>`;
      root.innerHTML = `<div class="cols no-print"><div class="panel"><h3>Organisation & Kontakte</h3>${f('org', 'Organisation', 'Muster AG')}
          <div class="cols">${f('it', 'IT-Notfall (Person)', 'Max Muster')}${f('itTel', 'Telefon', '079 123 45 67', 'tel')}</div>
          <div class="cols">${f('vert', 'Stellvertretung', '')}${f('vertTel', 'Telefon', '', 'tel')}</div>
          <div class="cols">${f('msp', 'IT-Dienstleister', 'Firma IT GmbH')}${f('mspTel', 'Hotline', '', 'tel')}</div>
          <div class="cols">${f('gl', 'Geschäftsleitung', '')}${f('glTel', 'Telefon', '', 'tel')}</div>
          <div class="cols">${f('vers', 'Cyber-Versicherung', 'Versicherer + Notfallnummer')}${f('versNr', 'Policen-Nr.', '')}</div>
          ${f('bank', 'Bank (bei Zahlungsbetrug)', 'Name und Notfallnummer')}</div>
        <div class="panel"><h3>Erste Schritte</h3><div class="field"><div class="label">Je Zeile ein Schritt</div><textarea data-k="steps" style="min-height:170px;font-family:var(--font)">${esc(d.steps)}</textarea></div>
          <div class="field"><div class="label">Nicht tun</div><textarea data-k="dont" style="min-height:70px;font-family:var(--font)">${esc(d.dont)}</textarea></div>
          <div class="row"><button class="btn btn-primary" id="print">${U.icon('print')}Drucken / als PDF</button><button class="btn btn-ghost btn-sm" id="reset">Zurücksetzen</button></div></div></div>
        <div class="print-area" id="card"></div>`;
      const draw = () => {
        const c = (n, v) => v ? `<div><span>${esc(n)}</span><b>${esc(v)}</b></div>` : '';
        U.q('#card').innerHTML = `<div class="ecard"><div class="ecard-head"><div><h2>IT-Notfall</h2><p>${esc(d.org || 'Deine Organisation')} · Cyberangriff, Virus, Erpressung, Datenverlust</p></div><div class="big-num">IT-NOTFALL<b>${esc(d.itTel || '— — —')}</b>${esc(d.it)}</div></div>
          <div class="ecard-body"><div><h4>Sofort tun</h4><ol>${d.steps.split('\n').filter(Boolean).map((s) => `<li>${esc(s)}</li>`).join('')}</ol><div class="dont"><b>Nicht tun:</b> ${esc(d.dont)}</div></div>
          <div class="contacts"><h4>Kontakte</h4>${c('IT-Notfall', [d.it, d.itTel].filter(Boolean).join(' · '))}${c('Stellvertretung', [d.vert, d.vertTel].filter(Boolean).join(' · '))}${c('IT-Dienstleister', [d.msp, d.mspTel].filter(Boolean).join(' · '))}${c('Geschäftsleitung', [d.gl, d.glTel].filter(Boolean).join(' · '))}${c('Cyber-Versicherung', [d.vers, d.versNr && 'Police ' + d.versNr].filter(Boolean).join(' · '))}${c('Bank', d.bank)}
            ${c('Polizei', '117')}${c('BACS (Bundesamt für Cybersicherheit)', 'ncsc.admin.ch')}${c('Phishing melden', 'antiphishing.ch')}</div></div>
          <div class="ecard-foot"><span>Stand ${new Date().toLocaleDateString('de-CH')} · Nummern halbjährlich prüfen</span><span>Infosphera Security Toolbox</span></div></div>`;
      };
      root.querySelectorAll('[data-k]').forEach((el) => el.addEventListener('input', () => { d[el.dataset.k] = el.value; U.store.set('nk', d); draw(); }));
      U.q('#print').onclick = () => window.print();
      U.q('#reset').onclick = () => { U.store.set('nk', {}); location.reload(); };
      draw();
    },
  });

  /* ================= Meldepflicht-Assistent ================= */
  const SECTORS = ['Hochschulen', 'Behörden von Bund, Kantonen und Gemeinden sowie interkantonale und interkommunale Organisationen', 'Organisationen mit öffentlichen Aufgaben in Sicherheit und Rettung, Trinkwasser, Abwasser und Abfall', 'Energieversorgung (z. B. Strom, Gas, Öl, Fernwärme)', 'Finanzbranche unter FINMA-Aufsicht (Banken, Versicherungen, Finanzmarktinfrastrukturen)', 'Gesundheitswesen (z. B. Spitäler auf Spitallisten, medizinische Labore, Arzneimittel)', 'Telekommunikation, Post', 'Verkehr (z. B. Bahn, Luftfahrt, Schifffahrt)', 'Lebensmittelversorgung', 'Anbieter von Cloud-, Rechenzentrums- und bestimmten IT-Diensten oder Software für kritische Infrastrukturen'];
  register({
    id: 'meldepflicht', name: 'Meldepflicht-Assistent', glyph: '24h', cat: 'command',
    desc: 'Klärt die Meldepflicht an das BACS (24 h / 14 Tage) und an den EDÖB – mit Countdown ab Entdeckung.',
    keywords: 'meldepflicht bacs ncsc 24 stunden kritische infrastruktur isg edöb datenschutz dsg melden cyberangriff gemeinde',
    render(root, U) {
      const st = Object.assign({ ki: null, crit: {}, found: '', pd: null }, U.store.get('mp', {}));
      root.innerHTML = `<div class="callout warn"><b>Keine Rechtsberatung.</b> Dieser Assistent fasst die öffentlichen Informationen des BACS zusammen (Stand Nov. 2026). Massgebend sind das Informationssicherheitsgesetz (ISG, Art. 74a ff.), die Cybersicherheitsverordnung (CSV) und das Datenschutzgesetz (DSG). Im Zweifel beim BACS nachfragen.</div>
        <div class="cols"><div>
          <div class="panel"><h3>1 · Betreibt ihr eine kritische Infrastruktur?</h3><div class="small muted" style="margin-bottom:10px">Meldepflichtig sind u. a. (vereinfacht, nicht abschliessend):</div>
            <ul class="small" style="margin:0 0 12px;padding-left:18px;line-height:1.7;color:var(--text-2)">${SECTORS.map((s) => `<li>${esc(s)}</li>`).join('')}</ul>
            <div class="small" style="margin-bottom:10px">Die Verordnung kennt Ausnahmen. Verbindlich: <a href="${BACS_WHO}" target="_blank" rel="noopener">BACS: Wer muss melden?</a></div>
            <div class="pill-q" id="ki"><button data-v="ja">Ja</button><button data-v="nein">Nein</button><button data-v="unklar">Unklar</button></div></div>
          <div class="panel"><h3>2 · Was ist passiert?</h3><div class="small muted" style="margin-bottom:6px">Ein Angriff ist u. a. zu melden, wenn er …</div>
            ${[['f', '… die Funktionsfähigkeit der Infrastruktur gefährdet'], ['m', '… zu Manipulation oder Abfluss von Informationen geführt hat'], ['e', '… mit Erpressung, Drohung oder Nötigung verbunden ist']].map(([k, t]) => `<label class="check-item" style="margin-bottom:6px"><input type="checkbox" data-c="${k}" ${st.crit[k] ? 'checked' : ''}/><div><b>${t}</b></div><span></span></label>`).join('')}
            <div class="q-row" style="margin-top:6px"><div><b>Sind Personendaten betroffen?</b><p>Kundendaten, Personaldaten, Patientendaten …</p></div><div class="pill-q" id="pd"><button data-v="ja">Ja</button><button data-v="nein">Nein</button><button data-v="unklar">Unklar</button></div></div></div>
          <div class="panel"><h3>3 · Wann wurde der Angriff entdeckt?</h3><div class="row"><input type="datetime-local" id="found" value="${esc(st.found)}" style="width:auto"/><button class="btn btn-sm" id="now">Jetzt</button></div></div>
        </div><div><div class="panel" id="verdict"></div><div class="panel" id="clock"></div>
          <div class="panel"><h3>Für die Meldung bereithalten</h3><div class="checklist">${['Organisation, Kontaktperson, erreichbare Telefonnummer', 'Zeitpunkt der Entdeckung (und des Angriffs, falls bekannt)', 'Art des Angriffs (z. B. Ransomware, Kontoübernahme, DDoS, Datenabfluss)', 'Betroffene Systeme und Standorte', 'Auswirkungen auf den Betrieb und auf Dritte', 'Bereits ergriffene Massnahmen', 'Erpressung oder Drohung? (Nachricht sichern, nicht antworten)', 'Bekannte Indikatoren: IPs, Domains, Dateinamen (IOC-Extraktor)'].map((t, i) => `<label class="check-item"><input type="checkbox" data-r="${i}"/><div><b style="font-weight:500">${esc(t)}</b></div><span></span></label>`).join('')}</div></div></div></div>`;
      let timer;
      const draw = () => {
        U.store.set('mp', st);
        U.qa('#ki button').forEach((b) => b.classList.toggle('on', st.ki === b.dataset.v));
        U.qa('#pd button').forEach((b) => b.classList.toggle('on', st.pd === b.dataset.v));
        const crit = Object.values(st.crit).some(Boolean);
        const F = [];
        if (st.ki === 'ja' && crit) F.push({ s: 'err', t: 'Meldepflicht an das BACS sehr wahrscheinlich', d: 'Erstmeldung innert <b>24 Stunden</b> nach Entdeckung über das Meldeformular im Cyber Security Hub (vorher registrieren). Fehlende Angaben innert <b>14 Tagen</b> ergänzen.', fix: `<a href="${BACS_CSH}" target="_blank" rel="noopener">Zum Cyber Security Hub</a> · <a href="${BACS_INFO}" target="_blank" rel="noopener">Infos zur Meldepflicht</a>` });
        else if (st.ki === 'ja') F.push({ s: 'warn', t: 'Ihr seid meldepflichtig, aber dieser Vorfall erfüllt (noch) kein Kriterium', d: 'Lage laufend neu beurteilen. Im Zweifel melden: Eine Meldung zu viel schadet nicht.', fix: `<a href="${BACS_INFO}" target="_blank" rel="noopener">BACS: Welche Angriffe sind zu melden?</a>` });
        else if (st.ki === 'unklar') F.push({ s: 'warn', t: 'Zuerst klären, ob ihr meldepflichtig seid', d: 'Die Frist läuft trotzdem ab Entdeckung. Im Zweifel melden.', fix: `<a href="${BACS_WHO}" target="_blank" rel="noopener">BACS: Wer muss melden?</a>` });
        else if (st.ki === 'nein') F.push({ s: 'info', t: 'Keine gesetzliche Meldepflicht an das BACS', d: 'Eine freiwillige Meldung hilft trotzdem, andere zu warnen, und das BACS kann unterstützen.', fix: `<a href="${BACS_REPORT}" target="_blank" rel="noopener">Freiwillig melden (BACS-Meldeformular)</a>` });
        if (st.pd === 'ja') F.push({ s: 'err', t: 'Datenschutz: Meldung an den EDÖB prüfen', d: 'Führt die Datensicherheitsverletzung voraussichtlich zu einem <b>hohen Risiko</b> für die betroffenen Personen, muss sie dem EDÖB <b>so rasch als möglich</b> gemeldet werden (Art. 24 DSG). Betroffene sind zu informieren, wenn es zu ihrem Schutz nötig ist.', fix: '<a href="https://www.edoeb.admin.ch" target="_blank" rel="noopener">edoeb.admin.ch</a> · Gilt unabhängig von der BACS-Meldepflicht.' });
        else if (st.pd === 'unklar') F.push({ s: 'warn', t: 'Klären, ob Personendaten betroffen sind', d: 'Davon hängt die Meldepflicht an den EDÖB ab.' });
        if (st.crit.e) F.push({ s: 'warn', t: 'Erpressung: Strafanzeige erstatten', d: 'Bei der Kantonspolizei Anzeige erstatten. Nicht verhandeln oder zahlen, bevor Fachleute beigezogen sind. Versicherung informieren.' });
        if (!F.length) F.push({ s: 'info', t: 'Fragen links beantworten' });
        U.q('#verdict').innerHTML = '<h3>Einschätzung</h3>' + findings(F);
        clearInterval(timer);
        const tick = () => {
          if (!st.found) { U.q('#clock').innerHTML = '<h3>Fristen</h3><span class="muted">Entdeckungszeitpunkt eintragen.</span>'; return; }
          const t0 = new Date(st.found), d24 = new Date(+t0 + 864e5), d14 = new Date(+t0 + 14 * 864e5), left = d24 - Date.now();
          const h = Math.floor(Math.abs(left) / 36e5), m = Math.floor((Math.abs(left) % 36e5) / 6e4), s = Math.floor((Math.abs(left) % 6e4) / 1e3);
          U.q('#clock').innerHTML = `<h3>Fristen BACS</h3><div class="countdown ${left < 0 ? 'late' : ''}">${left < 0 ? '−' : ''}${pad(h)}:${pad(m)}:${pad(s)}</div><div class="small muted">${left < 0 ? 'Frist für die Erstmeldung ist abgelaufen. Trotzdem sofort melden.' : 'bis zur Erstmeldung'}</div>
            <div style="margin-top:12px">${U.kv([['Entdeckt', fmt(t0)], ['Erstmeldung bis', fmt(d24)], ['Ergänzung bis', fmt(d14)]])}</div>
            <div class="small muted" style="margin-top:8px">Seit 1. Oktober 2025 kann eine unterlassene Meldung mit Busse bis CHF 100'000 bestraft werden.</div>`;
        };
        tick(); if (st.found) timer = setInterval(tick, 1000);
      };
      U.q('#ki').onclick = (e) => { const b = e.target.closest('button'); if (b) { st.ki = b.dataset.v; draw(); } };
      U.q('#pd').onclick = (e) => { const b = e.target.closest('button'); if (b) { st.pd = b.dataset.v; draw(); } };
      U.qa('[data-c]').forEach((c) => { c.onchange = () => { st.crit[c.dataset.c] = c.checked; draw(); }; });
      U.q('#found').onchange = () => { st.found = U.q('#found').value; draw(); };
      U.q('#now').onclick = () => { st.found = localInput(new Date()); U.q('#found').value = st.found; draw(); };
      U.qa('[data-r]').forEach((c) => { c.onchange = () => c.closest('.check-item').classList.toggle('done', c.checked); });
      draw();
      return () => clearInterval(timer);
    },
  });

  /* ================= Incident Playbooks ================= */
  const PB = {
    ransomware: ['Ransomware / verschlüsselte Dateien', 'Dateien lassen sich nicht öffnen, haben neue Endungen, eine Lösegeldforderung erscheint.', [
      ['Sofort', 'Betroffene Geräte vom Netz trennen (Kabel ziehen, WLAN aus), nicht ausschalten', 'Ausschalten löscht Spuren im Arbeitsspeicher, die für die Aufklärung wichtig sein können.'],
      ['Sofort', 'Backups vom Netz trennen bzw. Zugriff sperren', 'Angreifer versuchen gezielt, Backups zu löschen oder mitzuverschlüsseln.'],
      ['Sofort', 'IT-Notfall und Dienstleister alarmieren, Krisenteam einberufen', 'Geschäftsleitung, IT, Kommunikation. Notfallkarte verwenden.'],
      ['Sofort', 'Lösegeldforderung fotografieren, nicht antworten', 'Keine Kontaktaufnahme ohne Fachleute.'],
      ['Eindämmen', 'Cyber-Versicherung informieren', 'Viele Policen verlangen sofortige Meldung und stellen Incident-Response-Spezialisten.'],
      ['Eindämmen', 'Meldepflichten prüfen (BACS 24 h, EDÖB)', 'Mit dem Meldepflicht-Assistenten.'],
      ['Eindämmen', 'Admin- und Dienstkonten-Passwörter von einem sauberen Gerät aus ändern', 'Insbesondere Domain-Admins, Cloud-Admins, VPN.'],
      ['Eindämmen', 'Strafanzeige bei der Kantonspolizei', ''],
      ['Beseitigen', 'Eintrittsweg finden (Phishing, VPN ohne 2FA, ungepatchter Server)', 'Sonst kommt der Angreifer nach der Wiederherstellung zurück.'],
      ['Wiederherstellen', 'Systeme neu aufsetzen, nicht «reinigen»', 'Daten aus geprüftem Backup zurückspielen, das vor dem Angriff erstellt wurde.'],
      ['Wiederherstellen', 'Überwachung verstärken (Anmeldungen, neue Admins, ausgehender Verkehr)', ''],
      ['Nachbereiten', 'Lessons Learned: Was hat gefehlt? Massnahmenplan mit Terminen', ''],
    ]],
    account: ['Konto kompromittiert (E-Mail / M365 / Google)', 'Unbekannte Anmeldungen, verschickte Mails, die niemand geschrieben hat, neue Weiterleitungsregeln.', [
      ['Sofort', 'Passwort ändern und alle Sitzungen abmelden', 'M365: «Sitzungen widerrufen». Google: Admin-Konsole → Benutzer → Anmeldecookies zurücksetzen.'],
      ['Sofort', '2FA aktivieren bzw. registrierte Methoden prüfen', 'Angreifer registrieren gerne ihr eigenes Gerät als zweiten Faktor.'],
      ['Sofort', 'Weiterleitungs- und Posteingangsregeln prüfen und löschen', 'Typisch: Regeln, die Mails mit «Rechnung» oder «Zahlung» verstecken oder weiterleiten.'],
      ['Eindämmen', 'App-Berechtigungen (OAuth) prüfen und fremde Apps entfernen', ''],
      ['Eindämmen', 'Gesendete Elemente prüfen: Wer wurde angeschrieben?', 'Empfänger warnen, besonders bei Zahlungsaufforderungen.'],
      ['Eindämmen', 'Anmeldeprotokoll sichern (IP, Land, Zeit)', 'Für Aufklärung und allfällige Meldung.'],
      ['Beseitigen', 'Gleiches Passwort überall sonst ändern', 'Passwort-Leak-Check verwenden.'],
      ['Beseitigen', 'Prüfen, ob Daten abgeflossen sind (Datenschutz-Meldepflicht?)', ''],
      ['Nachbereiten', 'Ursache klären: Phishing? Wiederverwendetes Passwort? Gerät infiziert?', ''],
    ]],
    phishing: ['Phishing-Link geklickt / Daten eingegeben', 'Jemand hat auf einen Link geklickt, ein Login eingegeben oder einen Anhang geöffnet.', [
      ['Sofort', 'Passwort des betroffenen Kontos sofort ändern (von einem anderen Gerät)', 'Gilt auch für alle Konten mit demselben Passwort.'],
      ['Sofort', 'Bei Anhang/Download: Gerät vom Netz trennen und IT informieren', ''],
      ['Sofort', 'Bei Kreditkarten- oder Bankdaten: Bank sofort anrufen und Karte sperren', ''],
      ['Eindämmen', 'Sitzungen abmelden und Anmeldeprotokoll prüfen', ''],
      ['Eindämmen', 'Mail mit Header sichern (Mail-Header-Analyse) und Kolleginnen warnen', 'Gleiche Mail wurde oft an mehrere Personen gesendet.'],
      ['Eindämmen', 'Link und Absender im Mailsystem sperren', ''],
      ['Beseitigen', 'Virenscan durchführen, bei Verdacht Gerät neu aufsetzen', ''],
      ['Nachbereiten', 'Phishing bei antiphishing.ch melden', ''],
      ['Nachbereiten', 'Kein Schuldzuweisen: Wer schnell meldet, hat richtig gehandelt', 'Fehlerkultur entscheidet, ob der nächste Klick gemeldet wird.'],
    ]],
    payment: ['Zahlungsbetrug / CEO-Fraud / falsche IBAN', 'Eine Zahlung ging auf ein fremdes Konto, z. B. nach angeblich geänderter Bankverbindung oder «Chef»-Mail.', [
      ['Sofort', 'Eigene Bank sofort anrufen und Rückruf der Zahlung verlangen', 'Je schneller, desto grösser die Chance, Geld zurückzuholen. Minuten zählen.'],
      ['Sofort', 'Empfängerbank über die eigene Bank informieren lassen', ''],
      ['Sofort', 'Alle Belege sichern: Mails mit Header, Rechnungen, Zahlungsauftrag', ''],
      ['Eindämmen', 'Strafanzeige bei der Kantonspolizei', 'Die Bank verlangt oft eine Anzeige.'],
      ['Eindämmen', 'Prüfen, ob ein eigenes Mailkonto kompromittiert ist', 'Häufig liest der Täter mit. Playbook «Konto kompromittiert».'],
      ['Eindämmen', 'Lieferant/Kunde über bekannte Telefonnummer informieren', 'Nicht über die Kontaktdaten aus der verdächtigen Mail.'],
      ['Nachbereiten', 'Prozess anpassen: IBAN-Änderungen nur nach Rückruf, Vier-Augen-Prinzip', ''],
    ]],
    device: ['Gerät verloren oder gestohlen', 'Notebook, Smartphone, USB-Stick oder Festplatte ist weg.', [
      ['Sofort', 'Gerät orten, sperren und bei Bedarf fernlöschen', '«Wo ist?», Google «Mein Gerät finden», Intune/MDM.'],
      ['Sofort', 'Passwörter von Konten ändern, die auf dem Gerät angemeldet waren', ''],
      ['Eindämmen', 'Prüfen: War das Gerät verschlüsselt (BitLocker/FileVault)?', 'Wenn ja, sind die Daten meist geschützt. Wenn nein: Datenschutz-Meldepflicht prüfen.'],
      ['Eindämmen', 'Zertifikate, VPN-Zugänge und App-Tokens des Geräts widerrufen', ''],
      ['Eindämmen', 'Diebstahl bei der Polizei melden', 'Für Versicherung nötig.'],
      ['Nachbereiten', 'Geräte-Inventar aktualisieren, Ersatz sauber einrichten', ''],
    ]],
    leak: ['Datenleck (Personendaten)', 'Daten sind an Unbefugte gelangt: Fehlversand, offene Freigabe, Diebstahl, Hack.', [
      ['Sofort', 'Leck schliessen: Freigabe entfernen, Zugang sperren, Rückruf der Mail', ''],
      ['Sofort', 'Festhalten: Welche Daten, wie viele Personen, seit wann, an wen?', ''],
      ['Eindämmen', 'Risiko für die Betroffenen beurteilen', 'Gesundheits-, Finanz- oder Ausweisdaten erhöhen das Risiko.'],
      ['Eindämmen', 'Bei voraussichtlich hohem Risiko: Meldung an den EDÖB so rasch als möglich', 'Art. 24 DSG. Mit dem Meldepflicht-Assistenten.'],
      ['Eindämmen', 'Betroffene informieren, wenn es zu ihrem Schutz nötig ist', 'Konkrete Tipps geben (Passwort ändern, auf Phishing achten).'],
      ['Nachbereiten', 'Ursache beheben und Datenschutz-Verletzung dokumentieren', 'Auch nicht meldepflichtige Fälle dokumentieren.'],
    ]],
    website: ['Website gehackt oder verunstaltet', 'Fremde Inhalte, Weiterleitungen auf Spam, Warnung von Google, unbekannte Admin-Konten.', [
      ['Sofort', 'Website in den Wartungsmodus nehmen', ''],
      ['Sofort', 'Hosting-Anbieter informieren', ''],
      ['Eindämmen', 'Alle Passwörter ändern: CMS-Admins, FTP/SFTP, Datenbank, Hosting-Panel', ''],
      ['Eindämmen', 'Unbekannte Admin-Konten, Plugins und Dateien sichern, dann entfernen', 'Kopie für die Analyse behalten.'],
      ['Beseitigen', 'Aus sauberem Backup wiederherstellen, dann sofort alles aktualisieren', 'CMS, Plugins, Themes.'],
      ['Beseitigen', 'Prüfen, ob Kundendaten oder Formulareingaben betroffen sind', 'Datenschutz-Meldepflicht?'],
      ['Wiederherstellen', 'Google Search Console: Sicherheitsprobleme prüfen und Überprüfung anfordern', ''],
      ['Nachbereiten', 'Web Security Check durchführen, 2FA für Admins, Plugins reduzieren', ''],
    ]],
  };
  register({
    id: 'playbooks', name: 'Incident Playbooks', glyph: 'PB', cat: 'command',
    desc: 'Schritt-für-Schritt-Abläufe für Ransomware, gehackte Konten, Phishing, Zahlungsbetrug, Geräteverlust, Datenlecks und Websites.',
    keywords: 'incident response playbook ransomware phishing ceo fraud kompromittiert datenleck notfall ablauf checkliste',
    render(root, U) {
      let cur = U.store.get('pb-cur', 'ransomware');
      root.innerHTML = `<div class="grid" id="pick" style="margin-bottom:16px">${Object.entries(PB).map(([k, [n, d]]) => `<div class="card" data-k="${k}" role="button" tabindex="0" style="cursor:pointer"><div class="card-icon">${U.icon('command')}</div><div><h3>${esc(n)}</h3><p>${esc(d)}</p></div></div>`).join('')}</div><div id="body"></div>`;
      const draw = () => {
        U.store.set('pb-cur', cur);
        U.qa('#pick .card').forEach((c) => { c.style.borderColor = c.dataset.k === cur ? 'var(--accent-text)' : ''; c.style.boxShadow = c.dataset.k === cur ? '0 0 0 3px var(--accent-ring)' : ''; });
        const [name, desc, steps] = PB[cur]; const st = U.store.get('pb-' + cur, { start: null, done: {} });
        const done = Object.keys(st.done).length;
        let phase = '';
        U.q('#body').innerHTML = `<div class="panel"><div class="row"><div class="grow"><b style="font:800 18px var(--display)">${esc(name)}</b><div class="small muted">${esc(desc)}</div></div>
          ${st.start ? `<span class="badge warn">Vorfall seit ${esc(fmt(st.start))}</span>` : `<button class="btn btn-primary" id="start">${U.icon('play')}Vorfall starten</button>`}<button class="btn btn-sm" id="exp">${U.icon('download')}Protokoll</button><button class="btn btn-sm btn-ghost" id="rs">${U.icon('trash')}Neu</button></div>
          <div class="meter" style="margin:14px 0 6px"><i style="width:${Math.round((done / steps.length) * 100)}%;background:var(--accent-text)"></i></div><div class="small muted" style="margin-bottom:14px">${done}/${steps.length} Schritte erledigt · Abhaken setzt einen Zeitstempel fürs Protokoll</div>
          <div class="checklist">${steps.map(([ph, t, d], i) => (ph !== phase ? `<div class="small" style="margin:10px 0 2px;font:700 11px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--accent-text)">${esc(phase = ph)}</div>` : '') +
            `<label class="check-item ${st.done[i] ? 'done' : ''}"><input type="checkbox" data-i="${i}" ${st.done[i] ? 'checked' : ''}/><div><b>${esc(t)}</b>${d ? `<p>${esc(d)}</p>` : ''}</div>${st.done[i] ? `<time>${new Date(st.done[i]).toLocaleTimeString('de-CH', { hour: '2-digit', minute: '2-digit' })}</time>` : '<span></span>'}</label>`).join('')}</div></div>`;
        const save = (s) => U.store.set('pb-' + cur, s);
        if (U.q('#start')) U.q('#start').onclick = () => { st.start = Date.now(); save(st); draw(); };
        U.qa('[data-i]').forEach((c) => { c.onchange = () => { if (!st.start) st.start = Date.now(); if (c.checked) st.done[c.dataset.i] = Date.now(); else delete st.done[c.dataset.i]; save(st); draw(); }; });
        U.q('#rs').onclick = () => { save({ start: null, done: {} }); draw(); };
        U.q('#exp').onclick = () => {
          const lines = steps.map(([ph, t], i) => [st.done[i], ph, t]).filter((x) => x[0]).sort((a, b) => a[0] - b[0]);
          U.download(`vorfall-${cur}-${new Date().toISOString().slice(0, 10)}.md`, `# Vorfallprotokoll: ${name}\n\nBeginn: ${st.start ? fmt(st.start) : '–'}  \nExport: ${fmt(Date.now())}  \nErledigt: ${done}/${steps.length}\n\n## Zeitachse\n\n| Zeit | Phase | Schritt |\n|---|---|---|\n${lines.map(([ts, ph, t]) => `| ${fmt(ts)} | ${ph} | ${t} |`).join('\n')}\n\n## Offen\n\n${steps.filter((_, i) => !st.done[i]).map(([ph, t]) => `- [ ] ${ph}: ${t}`).join('\n') || '–'}\n\n_Erstellt mit der Infosphera Security Toolbox_\n`, 'text/markdown');
        };
      };
      U.q('#pick').onclick = (e) => { const c = e.target.closest('.card'); if (c) { e.preventDefault(); cur = c.dataset.k; draw(); } };
      draw();
    },
  });

  /* ================= Vorfall-Logbuch ================= */
  register({
    id: 'incident-log', name: 'Vorfall-Logbuch', glyph: 'LOG', cat: 'command',
    desc: 'Während eines Vorfalls alles mit Zeitstempel festhalten: Beobachtungen, Entscheide, Anrufe. Export für Versicherung und Behörden.',
    keywords: 'incident log logbuch protokoll zeitachse timeline vorfall dokumentation forensik',
    render(root, U) {
      const st = Object.assign({ title: '', lead: '', entries: [] }, U.store.get('ilog', {}));
      const CATS = ['Beobachtung', 'Entscheid', 'Massnahme', 'Kommunikation', 'Meldung'];
      root.innerHTML = `<div class="panel"><div class="cols"><div class="field"><div class="label">Vorfall</div><input id="title" value="${esc(st.title)}" placeholder="z. B. Verdacht Ransomware Buchhaltung"/></div><div class="field"><div class="label">Leitung</div><input id="lead" value="${esc(st.lead)}" placeholder="Name"/></div></div></div>
        <div class="panel"><div class="row"><input type="datetime-local" id="ts" style="width:auto"/><select id="cat" style="width:auto">${CATS.map((c) => `<option>${c}</option>`).join('')}</select><input id="who" placeholder="Wer" style="width:140px"/></div>
          <div class="row" style="margin-top:8px"><input id="txt" class="grow" placeholder="Was ist passiert / was wurde entschieden? (Enter speichert)"/><button class="btn btn-primary" id="add">${U.icon('plus')}Eintragen</button></div></div>
        <div class="panel"><div class="row"><b class="grow" id="cnt"></b><button class="btn btn-sm" id="md">${U.icon('download')}Markdown</button><button class="btn btn-sm" id="csv">${U.icon('download')}CSV</button><button class="btn btn-sm btn-ghost" id="clr">${U.icon('trash')}Leeren</button></div><div id="list" style="margin-top:12px"></div></div>`;
      const save = () => U.store.set('ilog', st);
      const resetTs = () => { U.q('#ts').value = localInput(new Date()); };
      const draw = () => {
        const e = [...st.entries].sort((a, b) => new Date(a.ts) - new Date(b.ts));
        U.q('#cnt').textContent = `${e.length} Einträge`;
        U.q('#list').innerHTML = e.length ? `<div class="tbl-wrap"><table class="tbl"><tr><th>Zeit</th><th>Art</th><th>Wer</th><th>Eintrag</th><th></th></tr>${e.map((x) => `<tr><td class="mono small" style="white-space:nowrap">${esc(fmt(x.ts))}</td><td><span class="badge">${esc(x.cat)}</span></td><td class="small">${esc(x.who)}</td><td>${esc(x.txt)}</td><td><button class="copy-btn" data-del="${x.id}" title="Löschen">${U.icon('trash')}</button></td></tr>`).join('')}</table></div>` : '<span class="muted">Noch keine Einträge. Tipp: Auch «nichts Neues» mit Uhrzeit festhalten.</span>';
        U.qa('[data-del]').forEach((b) => { b.onclick = () => { st.entries = st.entries.filter((x) => x.id !== b.dataset.del); save(); draw(); }; });
      };
      const add = () => {
        const txt = U.q('#txt').value.trim(); if (!txt) return;
        st.entries.push({ id: Math.random().toString(36).slice(2), ts: U.q('#ts').value || localInput(new Date()), cat: U.q('#cat').value, who: U.q('#who').value.trim(), txt });
        U.store.set('ilog-who', U.q('#who').value.trim());
        U.q('#txt').value = ''; resetTs(); save(); draw(); U.q('#txt').focus();
      };
      U.q('#who').value = U.store.get('ilog-who', '');
      U.q('#add').onclick = add;
      U.q('#txt').addEventListener('keydown', (e) => { if (e.key === 'Enter') add(); });
      U.q('#title').oninput = () => { st.title = U.q('#title').value; save(); };
      U.q('#lead').oninput = () => { st.lead = U.q('#lead').value; save(); };
      U.q('#clr').onclick = () => { if (st.entries.length && !confirmClear()) return; st.entries = []; save(); draw(); };
      const confirmClear = () => { const b = U.q('#clr'); if (b.dataset.arm) return true; b.dataset.arm = '1'; b.lastChild.textContent = 'Wirklich leeren?'; setTimeout(() => { delete b.dataset.arm; b.lastChild.textContent = 'Leeren'; }, 3000); return false; };
      const sorted = () => [...st.entries].sort((a, b) => new Date(a.ts) - new Date(b.ts));
      U.q('#md').onclick = () => U.download('vorfall-logbuch.md', `# Vorfall-Logbuch: ${st.title || '–'}\n\nLeitung: ${st.lead || '–'}  \nExport: ${fmt(Date.now())}\n\n| Zeit | Art | Wer | Eintrag |\n|---|---|---|---|\n${sorted().map((x) => `| ${fmt(x.ts)} | ${x.cat} | ${x.who} | ${x.txt.replace(/\|/g, '/')} |`).join('\n')}\n`, 'text/markdown');
      U.q('#csv').onclick = () => U.download('vorfall-logbuch.csv', 'zeit;art;wer;eintrag\n' + sorted().map((x) => [x.ts, x.cat, x.who, '"' + x.txt.replace(/"/g, '""') + '"'].join(';')).join('\n'), 'text/csv');
      resetTs(); draw();
    },
  });
})();
