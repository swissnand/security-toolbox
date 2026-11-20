/* Sphera Shield · Härten — Sind Geräte, Server und Daten richtig geschützt? */
(() => {
  'use strict';
  const { register, util } = window.TB;
  const { esc, findings, gradeBox } = util;

  /* ================= macOS Hardening Check ================= */
  const MAC_CMDS = [
    ['FileVault (Festplattenverschlüsselung)', 'fdesetup status'],
    ['Firewall', '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate'],
    ['Tarnmodus', '/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode'],
    ['Gatekeeper', 'spctl --status'],
    ['Systemintegritätsschutz (SIP)', 'csrutil status'],
    ['Automatische Updates', 'defaults read /Library/Preferences/com.apple.SoftwareUpdate'],
    ['Gastkonto', 'defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled'],
    ['Automatische Anmeldung', 'defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser'],
    ['Bildschirmsperre', 'sysadminctl -screenLock status'],
    ['Entfernte Anmeldung (SSH)', 'launchctl print-disabled system | grep sshd'],
  ];
  const macFindings = (r) => {
    const F = []; const o = (k) => ((r[k] && (r[k].out + ' ' + r[k].err)) || '').trim();
    const has = (k) => r[k] && r[k].ok;
    F.push(/FileVault is On/i.test(o('filevault')) ? { s: 'ok', t: 'FileVault aktiv', d: 'Die Festplatte ist verschlüsselt. Bei Verlust oder Diebstahl sind die Daten geschützt.', tag: 'Daten' }
      : /Encryption in progress/i.test(o('filevault')) ? { s: 'warn', t: 'FileVault wird gerade aktiviert', tag: 'Daten' }
        : { s: 'err', t: 'FileVault aus', d: 'Wer den Mac in die Hände bekommt, kann alle Daten lesen.', fix: 'Systemeinstellungen → Datenschutz & Sicherheit → FileVault → Einschalten. Wiederherstellungsschlüssel sicher aufbewahren.', tag: 'Daten' });
    const fw = o('firewall');
    F.push(/enabled|State = [12]/i.test(fw) && !/disabled/i.test(fw) ? { s: 'ok', t: 'Firewall aktiv', tag: 'Netz' } : { s: 'err', t: 'Firewall aus', d: 'Eingehende Verbindungen werden nicht gefiltert.', fix: 'Systemeinstellungen → Netzwerk → Firewall → Einschalten.', tag: 'Netz' });
    F.push(/enabled|on/i.test(o('stealth')) && !/disabled|off/i.test(o('stealth')) ? { s: 'ok', t: 'Tarnmodus aktiv', d: 'Der Mac antwortet nicht auf Pings und Port-Anfragen.', tag: 'Netz' } : { s: 'info', t: 'Tarnmodus aus', d: 'Empfohlen für Notebooks in fremden Netzen (Hotel, Café).', fix: 'Firewall → Optionen → Tarnmodus aktivieren.', tag: 'Netz' });
    F.push(/assessments enabled/i.test(o('gatekeeper')) ? { s: 'ok', t: 'Gatekeeper aktiv', d: 'Nur geprüfte Apps starten ohne Rückfrage.', tag: 'Apps' } : { s: 'err', t: 'Gatekeeper deaktiviert', d: 'Beliebige, auch manipulierte Apps können starten.', fix: 'Im Terminal: <code>sudo spctl --master-enable</code>', tag: 'Apps' });
    F.push(/enabled/i.test(o('sip')) && !/disabled/i.test(o('sip')) ? { s: 'ok', t: 'Systemintegritätsschutz aktiv', tag: 'System' } : { s: 'err', t: 'Systemintegritätsschutz (SIP) aus', d: 'Schadsoftware kann Systemdateien verändern.', fix: 'Im Wiederherstellungsmodus <code>csrutil enable</code> ausführen.', tag: 'System' });
    const flag = (k) => has(k) ? r[k].out.trim() === '1' : null; // null = nicht gesetzt (Standard)
    const ac = flag('autoCheck'), ad = flag('autoDownload'), cr = flag('critical'), am = flag('autoMacOS');
    F.push(ac === false || ad === false ? { s: 'err', t: 'Automatische Updates aus', d: 'Sicherheitslücken bleiben offen.', fix: 'Systemeinstellungen → Allgemein → Softwareupdate → Automatische Updates → alles aktivieren.', tag: 'Updates' }
      : { s: 'ok', t: 'Updates werden automatisch gesucht und geladen', tag: 'Updates' });
    F.push(cr === false ? { s: 'err', t: 'Sicherheitsantworten und Systemdateien werden nicht automatisch installiert', fix: 'Softwareupdate → Automatische Updates → «Sicherheitsantworten und Systemdateien installieren».', tag: 'Updates' } : { s: 'ok', t: 'Sicherheitsupdates werden automatisch installiert', tag: 'Updates' });
    F.push(am === true ? { s: 'ok', t: 'macOS-Updates werden automatisch installiert', tag: 'Updates' } : { s: 'info', t: 'macOS-Updates nicht automatisch installiert', d: 'Bewusst manuell ist okay, wenn du zeitnah installierst.', tag: 'Updates' });
    F.push(flag('guest') === true ? { s: 'warn', t: 'Gastkonto aktiv', fix: 'Systemeinstellungen → Benutzer:innen & Gruppen → Gastbenutzer aus.', tag: 'Konten' } : { s: 'ok', t: 'Gastkonto aus', tag: 'Konten' });
    F.push(has('autoLogin') && r.autoLogin.out ? { s: 'err', t: `Automatische Anmeldung für «${r.autoLogin.out}»`, d: 'Nach dem Start ist der Mac ohne Passwort offen. FileVault wird damit teilweise ausgehebelt.', fix: 'Benutzer:innen & Gruppen → Automatisch anmelden als → Aus.', tag: 'Konten' } : { s: 'ok', t: 'Keine automatische Anmeldung', tag: 'Konten' });
    const sl = o('screenLock');
    if (/immediate/i.test(sl)) F.push({ s: 'ok', t: 'Passwort sofort nach Ruhezustand', tag: 'Sperre' });
    else if (/off/i.test(sl)) F.push({ s: 'err', t: 'Bildschirmsperre ohne Passwort', fix: 'Sperrbildschirm → Passwort erforderlich: sofort.', tag: 'Sperre' });
    else if (/(\d+)\s*seconds/i.test(sl)) { const s = +sl.match(/(\d+)\s*seconds/i)[1]; F.push(s <= 60 ? { s: 'ok', t: `Passwort nach ${s} Sekunden`, tag: 'Sperre' } : { s: 'warn', t: `Passwort erst nach ${Math.round(s / 60)} Minuten`, fix: 'Auf «sofort» oder höchstens 1 Minute stellen.', tag: 'Sperre' }); }
    else F.push({ s: 'info', t: 'Bildschirmsperre nicht auslesbar', d: 'Bitte manuell prüfen: Sperrbildschirm → Passwort erforderlich.', tag: 'Sperre' });
    const ssh = o('sshd');
    F.push(/"com\.openssh\.sshd"\s*=>\s*(enabled|false)/i.test(ssh) ? { s: 'warn', t: 'Entfernte Anmeldung (SSH) aktiv', d: 'Der Mac nimmt SSH-Verbindungen an.', fix: 'Wenn nicht nötig: Allgemein → Teilen → Entfernte Anmeldung aus.', tag: 'Dienste' } : { s: 'ok', t: 'Entfernte Anmeldung (SSH) aus', tag: 'Dienste' });
    if (has('sharing')) F.push({ s: 'info', t: 'Entfernte Verwaltung/Bildschirmfreigabe läuft', d: 'ARDAgent ist aktiv. Nur eingeschaltet lassen, wenn bewusst genutzt.', tag: 'Dienste' });
    if (has('smb')) F.push({ s: 'info', t: 'Dateifreigabe (SMB) läuft', d: 'Freigegebene Ordner sind im Netz sichtbar.', tag: 'Dienste' });
    return F;
  };

  register({
    id: 'mac-audit', name: 'macOS Hardening Check', glyph: 'MAC', cat: 'shield', appOnly: true,
    desc: 'Prüft FileVault, Firewall, Gatekeeper, SIP, Updates, Sperre und Freigaben dieses Macs. Nur lesend.',
    keywords: 'mac macos hardening filevault firewall gatekeeper sip update härten check audit',
    render(root, U) {
      if (!U.isApp) {
        root.innerHTML = `${U.appOnlyNote('Der automatische Mac-Check')}<div class="panel"><h3>Manuell im Terminal prüfen</h3><div class="tbl-wrap"><table class="tbl"><tr><th>Prüfpunkt</th><th>Befehl</th><th></th></tr>
          ${MAC_CMDS.map(([n, c]) => `<tr><td>${esc(n)}</td><td class="mono">${esc(c)}</td><td><button class="copy-btn" data-copy-text="${esc(c)}">${U.icon('copy')}</button></td></tr>`).join('')}</table></div></div>`;
        return;
      }
      root.innerHTML = `<div class="panel"><div class="row"><div class="grow"><b>Diesen Mac prüfen</b><div class="small muted">Liest Einstellungen mit Bordmitteln (fdesetup, spctl, csrutil, defaults …). Ändert nichts, braucht kein Admin-Passwort.</div></div>
        <button class="btn btn-primary" id="go">${U.icon('play')}Check starten</button></div></div><div id="res"></div>`;
      U.q('#go').onclick = async () => {
        U.q('#res').innerHTML = '<div class="panel muted">Prüfe …</div>';
        try {
          const a = await window.toolbox.macAudit();
          if (a.platform !== 'darwin') { U.q('#res').innerHTML = '<div class="msg err">Dieser Check läuft nur auf macOS.</div>'; return; }
          const F = macFindings(a.results);
          const ver = (a.results.swVers.out.match(/ProductVersion:\s*(\S+)/) || [])[1] || '';
          U.q('#res').innerHTML = `<div class="panel">${gradeBox(F, 'macOS ' + ver + ' · ' + (a.arch === 'arm64' ? 'Apple Silicon' : 'Intel'))}</div><div class="panel"><h3>Befunde</h3>${findings(F)}</div>
            <details class="panel"><summary style="cursor:pointer;font-weight:600">Rohdaten</summary><div class="out" style="margin-top:10px;max-height:300px;overflow:auto">${esc(Object.entries(a.results).map(([k, v]) => `${k}: ${v.out || v.err || '(leer)'}`).join('\n'))}</div></details>`;
        } catch (e) { U.q('#res').innerHTML = `<div class="msg err">${esc(e.message)}</div>`; }
      };
    },
  });

  /* ================= SSH-Konfiguration prüfen ================= */
  const SSH_HARD = `# Gehärtete Grundkonfiguration (OpenSSH 8+), danach: sshd -t && systemctl reload ssh
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
AllowGroups ssh-users
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com`;
  register({
    id: 'ssh-audit', name: 'SSH-Konfiguration prüfen', glyph: 'SSH', cat: 'shield',
    desc: 'sshd_config einfügen: Root-Login, Passwörter, schwache Algorithmen und Weiterleitungen bewerten.',
    keywords: 'ssh sshd_config openssh server hardening linux root login password cipher kex',
    render(root, U) {
      root.innerHTML = `<div class="cols"><div class="panel"><h3>sshd_config</h3><textarea id="in" style="min-height:340px" spellcheck="false" placeholder="Inhalt von /etc/ssh/sshd_config einfügen&#10;(oder Ausgabe von: sudo sshd -T)"></textarea>
          <div class="small muted" style="margin-top:8px">Tipp: <code>sudo sshd -T</code> zeigt die wirksame Konfiguration inkl. Standardwerten. Wird nur lokal ausgewertet.</div></div>
        <div class="panel"><h3>Bewertung</h3><div id="res" class="muted">Konfiguration links einfügen.</div></div></div>
        <div class="panel"><h3>Empfohlene Grundkonfiguration</h3><div class="out" id="hard">${esc(SSH_HARD)}</div><div class="row end" style="margin-top:8px">${U.copyBtn('#hard')}</div></div>`;
      const run = () => {
        const txt = U.q('#in').value; if (!txt.trim()) return;
        const c = {}; let inMatch = false;
        txt.split(/\r?\n/).forEach((l) => {
          l = l.replace(/#.*/, '').trim(); if (!l) return;
          const [k, ...v] = l.split(/\s+/); const key = k.toLowerCase();
          if (key === 'match') { inMatch = true; return; }
          if (!inMatch && c[key] === undefined) c[key] = v.join(' ').toLowerCase();
        });
        const F = [];
        const pr = c.permitrootlogin;
        F.push(pr === 'no' ? { s: 'ok', t: 'Root-Login verboten', tag: 'Login' } : pr === 'yes' ? { s: 'err', t: 'Root darf sich anmelden (auch mit Passwort)', d: 'Root ist das Hauptziel von Brute-Force-Angriffen.', fix: '<code>PermitRootLogin no</code>', tag: 'Login' }
          : { s: 'warn', t: `Root-Login nur mit Schlüssel (${pr || 'Standard: prohibit-password'})`, fix: 'Besser: <code>PermitRootLogin no</code> und sudo verwenden.', tag: 'Login' });
        const pa = c.passwordauthentication;
        F.push(pa === 'no' ? { s: 'ok', t: 'Passwort-Anmeldung aus (nur Schlüssel)', tag: 'Login' } : { s: pa === 'yes' ? 'err' : 'warn', t: pa === 'yes' ? 'Passwort-Anmeldung erlaubt' : 'Passwort-Anmeldung nicht explizit aus (Standard: yes)', d: 'Passwörter lassen sich erraten. Schlüssel nicht.', fix: '<code>PasswordAuthentication no</code> (vorher Schlüssel hinterlegen!)', tag: 'Login' });
        const kb = c.kbdinteractiveauthentication || c.challengeresponseauthentication;
        if (kb === 'yes') F.push({ s: 'warn', t: 'Keyboard-Interactive aktiv', d: 'Erlaubt Passwörter über PAM, auch wenn PasswordAuthentication aus ist.', fix: '<code>KbdInteractiveAuthentication no</code>', tag: 'Login' });
        if (c.permitemptypasswords === 'yes') F.push({ s: 'err', t: 'Leere Passwörter erlaubt', fix: '<code>PermitEmptyPasswords no</code>', tag: 'Login' });
        if (c.pubkeyauthentication === 'no') F.push({ s: 'err', t: 'Schlüssel-Anmeldung deaktiviert', tag: 'Login' });
        const mat = +(c.maxauthtries || 6);
        F.push(mat <= 4 ? { s: 'ok', t: `MaxAuthTries ${mat}`, tag: 'Login' } : { s: 'info', t: `MaxAuthTries ${mat}${c.maxauthtries ? '' : ' (Standard)'}`, fix: '<code>MaxAuthTries 3</code>', tag: 'Login' });
        const lgt = parseInt(c.logingracetime || '120', 10);
        if (lgt > 60) F.push({ s: 'info', t: `LoginGraceTime ${lgt} s`, d: 'Lange offene, unauthentifizierte Verbindungen.', fix: '<code>LoginGraceTime 30</code>', tag: 'Login' });
        F.push(c.allowusers || c.allowgroups ? { s: 'ok', t: 'Zugriff auf bestimmte Benutzer/Gruppen beschränkt', tag: 'Zugriff' } : { s: 'info', t: 'Keine AllowUsers/AllowGroups', d: 'Jedes Konto mit Shell darf sich anmelden.', fix: '<code>AllowGroups ssh-users</code>', tag: 'Zugriff' });
        if (c.x11forwarding === 'yes') F.push({ s: 'warn', t: 'X11-Weiterleitung aktiv', fix: '<code>X11Forwarding no</code>', tag: 'Weiterleitung' });
        if (c.allowagentforwarding !== 'no') F.push({ s: 'info', t: 'Agent-Weiterleitung erlaubt', d: 'Ein kompromittierter Server kann deinen SSH-Agenten missbrauchen.', tag: 'Weiterleitung' });
        if (c.allowtcpforwarding === 'yes' || c.allowtcpforwarding === undefined) F.push({ s: 'info', t: 'TCP-Weiterleitung erlaubt', d: 'Tunnel durch den Server sind möglich. Auf Bastion-Hosts gewollt, sonst abschalten.', tag: 'Weiterleitung' });
        if (c.protocol && c.protocol.includes('1')) F.push({ s: 'err', t: 'SSH-Protokoll 1', d: 'Seit Jahren gebrochen.', tag: 'Krypto' });
        const weakC = (c.ciphers || '').split(',').filter((x) => /cbc|3des|arcfour|blowfish|cast128/.test(x));
        const weakM = (c.macs || '').split(',').filter((x) => /md5|^hmac-sha1$|^hmac-sha1-96|umac-64(?!-etm)/.test(x));
        const weakK = (c.kexalgorithms || '').split(',').filter((x) => /group1-sha1|group14-sha1|group-exchange-sha1/.test(x));
        if (weakC.length) F.push({ s: 'err', t: 'Schwache Ciphers', d: weakC.map((x) => `<code>${esc(x)}</code>`).join(' '), tag: 'Krypto' });
        if (weakM.length) F.push({ s: 'warn', t: 'Schwache MACs', d: weakM.map((x) => `<code>${esc(x)}</code>`).join(' '), tag: 'Krypto' });
        if (weakK.length) F.push({ s: 'warn', t: 'Schwacher Schlüsseltausch', d: weakK.map((x) => `<code>${esc(x)}</code>`).join(' '), tag: 'Krypto' });
        if (!weakC.length && !weakM.length && !weakK.length) F.push({ s: c.ciphers || c.kexalgorithms ? 'ok' : 'info', t: c.ciphers || c.kexalgorithms ? 'Keine schwachen Algorithmen gefunden' : 'Algorithmen nicht festgelegt (OpenSSH-Standard)', d: c.ciphers ? '' : 'Aktuelle OpenSSH-Versionen haben sichere Standards. Bei alten Servern explizit festlegen.', tag: 'Krypto' });
        if (/dsa/.test(c.hostkey || '') && !/ecdsa/.test(c.hostkey || '')) F.push({ s: 'err', t: 'DSA-Hostschlüssel', tag: 'Krypto' });
        if (!c.clientaliveinterval || c.clientaliveinterval === '0') F.push({ s: 'info', t: 'Inaktive Sitzungen bleiben offen', fix: '<code>ClientAliveInterval 300</code> und <code>ClientAliveCountMax 2</code>', tag: 'Sitzung' });
        if ((c.port || '22') === '22') F.push({ s: 'info', t: 'Standard-Port 22', d: 'Kein Sicherheitsgewinn durch anderen Port, aber deutlich weniger Rauschen in den Logs. Wichtiger: Fail2ban oder Firewall-Regeln.', tag: 'Netz' });
        U.q('#res').innerHTML = gradeBox(F, 'sshd_config') + '<div style="margin-top:14px">' + findings(F) + '</div>' + (inMatch ? '<div class="callout info" style="margin-top:12px">Match-Blöcke wurden nicht ausgewertet. Sie können Werte für bestimmte Benutzer überschreiben.</div>' : '');
      };
      U.q('#in').addEventListener('input', U.debounce(run, 250));
    },
  });

  /* ================= Secret Scanner ================= */
  const SECRETS = [
    ['Privater Schlüssel', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, 'krit'],
    ['AWS Access Key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 'krit'],
    ['AWS Secret Key', /aws.{0,30}?['"=:\s]([0-9a-zA-Z/+]{40})(?![0-9a-zA-Z/+])/gi, 'krit'],
    ['GitHub Token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, 'krit'],
    ['GitLab Token', /\bglpat-[A-Za-z0-9_-]{20,}\b/g, 'krit'],
    ['Anthropic API Key', /\bsk-ant-[A-Za-z0-9_-]{30,}/g, 'krit'],
    ['OpenAI API Key', /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}/g, 'krit'],
    ['Stripe Live Key', /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g, 'krit'],
    ['Stripe Test Key', /\bsk_test_[A-Za-z0-9]{20,}\b/g, 'tief'],
    ['Slack Token', /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, 'hoch'],
    ['Slack Webhook', /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{20,}/g, 'hoch'],
    ['Google API Key', /\bAIza[0-9A-Za-z_-]{35}\b/g, 'hoch'],
    ['SendGrid Key', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, 'hoch'],
    ['npm Token', /\bnpm_[A-Za-z0-9]{36}\b/g, 'hoch'],
    ['Telegram Bot Token', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g, 'hoch'],
    ['Azure Storage Key', /AccountKey=[A-Za-z0-9+/=]{80,}/g, 'krit'],
    ['Twilio API Key', /\bSK[0-9a-f]{32}\b/g, 'mittel'],
    ['Zugangsdaten in URL', /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"]+:[^\s:/@'"]{3,}@[^\s/'"]+/gi, 'hoch'],
    ['JSON Web Token', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, 'mittel'],
    ['Passwort im Code', /\b(?:pass(?:word|wd)?|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']([^"'\s]{6,})["']/gi, 'mittel'],
  ];
  const PLACEHOLDER = /^(x+|\*+|\.+|changeme|password|passwort|secret|example|beispiel|your[_-]?.*|<.*>|\$\{.*\}|test|dummy|xxx.*)$/i;
  const mask = (s) => s.length <= 10 ? s.slice(0, 2) + '…' : s.slice(0, 6) + '…' + s.slice(-3);
  const scanText = (text, file) => {
    const hits = []; const seen = new Set();
    const lineStarts = [0]; for (let i = 0; i < text.length; i++) if (text[i] === '\n') lineStarts.push(i + 1);
    const lineOf = (idx) => { let lo = 0, hi = lineStarts.length - 1; while (lo < hi) { const m = (lo + hi + 1) >> 1; if (lineStarts[m] <= idx) lo = m; else hi = m - 1; } return lo + 1; };
    for (const [name, re, sev] of SECRETS) {
      re.lastIndex = 0; let m;
      while ((m = re.exec(text))) {
        const val = m[1] || m[0];
        if (PLACEHOLDER.test(val)) continue;
        const key = m.index + ':' + val.slice(0, 12);
        if ([...seen].some((k) => +k.split(':')[0] === m.index)) continue;
        seen.add(key);
        let s = sev, n = name;
        if (name === 'JSON Web Token') { try { const p = JSON.parse(atob(m[0].split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); if (p.role === 'service_role') { s = 'krit'; n = 'Supabase service_role Key'; } } catch { /* ignore */ } }
        hits.push({ file, line: lineOf(m.index), type: n, sev: s, val: mask(val) });
      }
    }
    return hits;
  };
  register({
    id: 'secret-scan', name: 'Secret Scanner', glyph: 'KEY', cat: 'shield',
    desc: 'Findet API-Keys, Tokens, private Schlüssel und Passwörter in Code, Ordnern und Konfigurationen. Lokal.',
    keywords: 'secret scanner api key token password leak git repository env aws github stripe supabase',
    render(root, U) {
      root.innerHTML = `<div class="callout">Läuft vollständig lokal. Dateien werden nur gelesen, nichts wird hochgeladen. Gefundene Werte werden maskiert angezeigt.</div>
        <div class="cols"><div class="panel"><h3>Ordner oder Dateien</h3><div class="dropzone" id="dzDir"><b>Projektordner wählen</b><br><span class="small">node_modules, .git und Binärdateien werden übersprungen</span></div>
          <div class="dropzone" id="dzFiles" style="margin-top:10px"><b>Einzelne Dateien</b> hierher ziehen oder klicken</div></div>
        <div class="panel"><h3>Text einfügen</h3><textarea id="txt" placeholder=".env, Konfiguration, Logausgabe …" style="min-height:178px"></textarea></div></div><div id="res"></div>`;
      const show = (hits, stats) => {
        const order = { krit: 0, hoch: 1, mittel: 2, tief: 3 };
        hits.sort((a, b) => order[a.sev] - order[b.sev]);
        const cnt = (s) => hits.filter((h) => h.sev === s).length;
        U.q('#res').innerHTML = `<div class="panel"><div class="stat-grid"><div class="stat"><b>${stats.files}</b><span>Dateien geprüft</span></div><div class="stat"><b style="color:var(--err)">${cnt('krit')}</b><span>kritisch</span></div><div class="stat"><b style="color:var(--warn)">${cnt('hoch') + cnt('mittel')}</b><span>hoch/mittel</span></div><div class="stat"><b>${stats.skipped}</b><span>übersprungen</span></div></div>
          ${hits.length ? `<div class="tbl-wrap" style="margin-top:14px"><table class="tbl"><tr><th>Stufe</th><th>Typ</th><th>Datei</th><th>Zeile</th><th>Wert</th></tr>${hits.map((h) => `<tr><td><span class="sev ${h.sev}">${h.sev}</span></td><td>${esc(h.type)}</td><td class="mono">${esc(h.file)}</td><td class="mono">${h.line}</td><td class="secret">${esc(h.val)}</td></tr>`).join('')}</table></div>
          <div class="callout warn" style="margin-top:14px"><b>Was jetzt?</b> Ein Secret, das je in Git committet wurde, gilt als kompromittiert, auch wenn es heute gelöscht ist. 1) Schlüssel beim Anbieter <b>widerrufen und neu erstellen</b>. 2) In Umgebungsvariablen oder einen Secret-Manager verschieben. 3) <code>.env</code> in <code>.gitignore</code>. 4) Optional Git-Historie bereinigen (git filter-repo).</div>`
          : '<div class="msg ok" style="margin-top:14px">Keine bekannten Secret-Muster gefunden.</div>'}</div>`;
      };
      const scanFiles = async (files) => {
        U.q('#res').innerHTML = '<div class="panel muted">Durchsuche …</div>';
        const hits = []; let n = 0, skipped = 0;
        for (const f of files) {
          const p = f.webkitRelativePath || f.name;
          if (/(^|\/)(node_modules|\.git|dist|build|vendor|\.next|__pycache__)\//.test(p) || /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|dmg|woff2?|ttf|mp4|mov|mp3|exe|dll|so|dylib|class|jar|lock)$/i.test(p) || f.size > 2 * 1024 * 1024) { skipped++; continue; }
          const t = await U.readFile(f);
          if (t.includes('\u0000')) { skipped++; continue; }
          n++; hits.push(...scanText(t, p));
        }
        show(hits, { files: n, skipped });
      };
      U.dropzone(U.q('#dzDir'), scanFiles, { dir: true });
      U.dropzone(U.q('#dzFiles'), scanFiles, { multiple: true });
      U.q('#txt').addEventListener('input', U.debounce(() => { const t = U.q('#txt').value; if (t.trim()) show(scanText(t, '(Text)'), { files: 1, skipped: 0 }); }, 250));
    },
  });

  /* ================= Härtungs-Checklisten ================= */
  const LISTS = {
    kmu: ['KMU-Grundschutz', [
      [1, 'Zwei-Faktor-Anmeldung überall', 'E-Mail, Cloud, Banking, Admin-Konten, VPN. Wichtigste Einzelmassnahme gegen gestohlene Passwörter.'],
      [1, 'Backups nach 3-2-1-Regel', '3 Kopien, 2 Medien, 1 ausser Haus und offline/unveränderbar. Wiederherstellung mindestens jährlich testen.'],
      [1, 'Automatische Updates', 'Betriebssysteme, Browser, Office, Firewall, NAS. Nicht mehr unterstützte Geräte ersetzen.'],
      [1, 'Passwort-Manager für alle', 'Lange, einzigartige Passwörter. Keine Excel-Listen und Post-its.'],
      [1, 'Admin-Rechte trennen', 'Täglich mit normalem Konto arbeiten, Admin nur für Verwaltung.'],
      [2, 'E-Mail-Schutz: SPF, DKIM, DMARC', 'Verhindert, dass Betrüger mit deiner Domain Mails versenden. Mit dem Mail Security Check prüfen.'],
      [2, 'Virenschutz und Festplattenverschlüsselung', 'Defender/XProtect aktiv, BitLocker/FileVault auf allen Notebooks.'],
      [2, 'Konten von Ausgetretenen sperren', 'Am letzten Arbeitstag alle Zugänge entziehen, gemeinsame Passwörter ändern.'],
      [2, 'Mitarbeitende schulen', 'Phishing erkennen, verdächtige Mails melden, keine Zahlungen auf Zuruf.'],
      [2, 'Notfallkarte und Ansprechpartner', 'Wer ist im Ernstfall zu rufen? Mit der Notfallkarte erstellen und aufhängen.'],
      [3, 'Inventar der Geräte und Software', 'Was haben wir, wer ist verantwortlich, bis wann wird es unterstützt?'],
      [3, 'Zahlungsprozess mit Rückruf', 'Neue oder geänderte Bankverbindungen nur nach telefonischer Bestätigung über bekannte Nummer.'],
    ]],
    mac: ['macOS', [
      [1, 'FileVault aktiv', 'Systemeinstellungen → Datenschutz & Sicherheit → FileVault.'],
      [1, 'Automatische Updates inkl. Sicherheitsantworten', 'Allgemein → Softwareupdate → Automatische Updates.'],
      [1, 'Firewall ein', 'Netzwerk → Firewall. Tarnmodus für Notebooks.'],
      [1, 'Passwort sofort nach Ruhezustand', 'Sperrbildschirm → Passwort erforderlich: sofort.'],
      [2, 'Standardkonto ohne Admin-Rechte', 'Separates Admin-Konto für Installationen.'],
      [2, 'Gatekeeper und SIP aktiv', 'Mit dem macOS Hardening Check prüfen.'],
      [2, 'Freigaben aus, wenn nicht genutzt', 'Allgemein → Teilen: Bildschirmfreigabe, Dateifreigabe, Entfernte Anmeldung.'],
      [2, '«Wo ist?» aktiv', 'Für Ortung und Fernlöschung bei Verlust.'],
      [3, 'Anmeldeobjekte und Hintergrund-Apps prüfen', 'Allgemein → Anmeldeobjekte: Unbekanntes entfernen.'],
      [3, 'Time Machine verschlüsselt', 'Backup-Medium mit Verschlüsselung einrichten.'],
    ]],
    win: ['Windows', [
      [1, 'BitLocker aktiv', 'Wiederherstellungsschlüssel ausserhalb des Geräts sichern (Entra ID/AD oder Ausdruck im Tresor).'],
      [1, 'Windows Update automatisch', 'Inkl. Treiber und Microsoft-Produkte.'],
      [1, 'Microsoft Defender und Firewall aktiv', 'Echtzeitschutz, Manipulationsschutz (Tamper Protection) ein.'],
      [1, 'Lokale Admin-Konten minimieren', 'Windows LAPS für einzigartige lokale Admin-Passwörter.'],
      [2, 'SMBv1 deaktiviert', 'PowerShell: Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'],
      [2, 'Makros aus dem Internet blockiert', 'Office-Richtlinie «Makros in Dateien aus dem Internet blockieren».'],
      [2, 'Attack Surface Reduction (ASR) Regeln', 'Mindestens im Überwachungsmodus einschalten.'],
      [2, 'RDP nur über VPN', 'Nie direkt ins Internet. Network Level Authentication erzwingen.'],
      [3, 'Audit-Richtlinien und Log-Grösse', 'Anmeldungen (4624/4625), Kontoänderungen (4720/4732), Log-Löschung (1102) protokollieren.'],
      [3, 'PowerShell Script Block Logging', 'Hilft bei der Aufklärung von Angriffen.'],
    ]],
    linux: ['Linux-Server', [
      [1, 'SSH nur mit Schlüssel, kein Root-Login', 'Mit «SSH-Konfiguration prüfen» kontrollieren.'],
      [1, 'Automatische Sicherheitsupdates', 'Debian/Ubuntu: unattended-upgrades. RHEL: dnf-automatic.'],
      [1, 'Firewall mit Default-Deny', 'ufw/nftables: nur benötigte Ports öffnen.'],
      [2, 'Fail2ban oder ähnliches', 'Sperrt IPs nach wiederholten Fehlanmeldungen.'],
      [2, 'Dienste minimieren', 'ss -tulpn: Was lauscht? Nicht Benötigtes deaktivieren.'],
      [2, 'sudo statt Root, sudo-Log prüfen', 'Nur benannte Benutzer in sudo/wheel.'],
      [2, 'Backups mit Wiederherstellungstest', 'Datenbank-Dumps nicht nur auf demselben Server.'],
      [3, 'Zentrales Logging', 'journald/rsyslog an einen separaten Server oder Dienst.'],
      [3, 'Dateirechte für Secrets', '.env und Schlüssel mit chmod 600, Eigentümer = Dienstkonto.'],
    ]],
    cloud: ['Microsoft 365 / Google Workspace', [
      [1, '2FA für alle Benutzer erzwingen', 'Nicht nur «verfügbar», sondern Pflicht. Admins mit Passkey/FIDO2.'],
      [1, 'Mindestens zwei, höchstens vier Global Admins', 'Separate Admin-Konten ohne Postfach. Notfallkonto («Break Glass») sicher verwahren.'],
      [1, 'Legacy-Authentifizierung blockiert', 'POP/IMAP/SMTP-Basic-Auth umgehen 2FA.'],
      [2, 'Externe Weiterleitungen sperren', 'Automatische Weiterleitung an externe Adressen ist ein typisches Zeichen kompromittierter Konten.'],
      [2, 'Audit-Log aktiviert', 'Unified Audit Log (M365) bzw. Admin-Log (Google) einschalten.'],
      [2, 'Freigaben nach aussen einschränken', 'OneDrive/SharePoint/Drive: «Jeder mit dem Link» deaktivieren oder befristen.'],
      [2, 'App-Zustimmungen durch Benutzer einschränken', 'Verhindert OAuth-Phishing (bösartige Apps mit Mailzugriff).'],
      [3, 'Inaktive Konten entfernen', 'Quartalsweise Liste prüfen.'],
      [3, 'Backup der Cloud-Daten', 'M365/Google sichern Daten nicht für jeden Fall (z. B. Ransomware, Löschung durch Benutzer).'],
    ]],
    net: ['Router, WLAN & Netzwerk', [
      [1, 'Standard-Passwort des Routers geändert', 'Admin-Oberfläche nicht aus dem Internet erreichbar.'],
      [1, 'Firmware aktuell', 'Automatische Updates einschalten, alte Geräte ersetzen.'],
      [1, 'WLAN mit WPA3 oder WPA2-AES', 'Kein WEP/WPA/TKIP. WPS aus.'],
      [2, 'Gäste-WLAN getrennt', 'Besucher und private Geräte nicht im Firmennetz.'],
      [2, 'Keine offenen Ports ohne Grund', 'Portweiterleitungen und UPnP prüfen, UPnP ausschalten.'],
      [2, 'Drucker, Kameras, IoT in eigenes Netz', 'VLAN oder separates WLAN.'],
      [3, 'DNS-Filter', 'z. B. Quad9 (9.9.9.9) blockiert bekannte Schadseiten.'],
      [3, 'VPN für Fernzugriff', 'Statt Portfreigaben für RDP/NAS.'],
    ]],
    web: ['Website & Domain', [
      [1, 'HTTPS mit automatischer Zertifikatsverlängerung', 'Mit dem Web Security Check prüfen.'],
      [1, 'CMS, Plugins und Themes aktuell', 'Nicht genutzte Plugins löschen. Admin-Login mit 2FA.'],
      [1, 'Registrar-Konto mit 2FA', 'Wer die Domain kapert, kapert auch E-Mail und Website.'],
      [2, 'Security-Header gesetzt', 'HSTS, CSP, X-Content-Type-Options, Referrer-Policy.'],
      [2, 'DNSSEC und CAA', 'Mit dem DNS & Domain Check prüfen.'],
      [2, 'security.txt veröffentlicht', 'Damit Lücken gemeldet statt ausgenutzt werden.'],
      [2, 'Backups der Website', 'Inkl. Datenbank, ausserhalb des Hostings.'],
      [3, 'Verwaiste Subdomains entfernen', 'Alte CNAMEs auf gelöschte Dienste sind ein Übernahme-Risiko.'],
    ]],
  };
  register({
    id: 'checklists', name: 'Härtungs-Checklisten', glyph: '✓', cat: 'shield',
    desc: 'Abhakbare Checklisten für KMU, macOS, Windows, Linux, M365/Google, Netzwerk und Website – mit Export.',
    keywords: 'checklist checkliste härtung baseline kmu windows linux mac m365 google router wlan website cis',
    render(root, U) {
      let cur = U.store.get('cl-cur', 'kmu');
      root.innerHTML = `<div class="panel"><div class="seg" id="tabs" style="flex-wrap:wrap">${Object.entries(LISTS).map(([k, [n]]) => `<button data-k="${k}">${esc(n)}</button>`).join('')}</div></div><div id="body"></div>`;
      const draw = () => {
        U.store.set('cl-cur', cur);
        U.qa('#tabs button').forEach((b) => b.classList.toggle('on', b.dataset.k === cur));
        const [name, items] = LISTS[cur]; const st = U.store.get('cl-' + cur, {});
        const done = items.filter((_, i) => st[i]).length; const pct = Math.round((done / items.length) * 100);
        U.q('#body').innerHTML = `<div class="panel"><div class="row"><div class="grow"><b style="font-size:15px">${esc(name)}</b><div class="small muted">${done} von ${items.length} erledigt · <span class="prio p1">P1</span> sofort <span class="prio p2">P2</span> bald <span class="prio p3">P3</span> später</div></div>
          <button class="btn btn-sm" id="exp">${U.icon('download')}Export</button><button class="btn btn-sm btn-ghost" id="reset">${U.icon('trash')}Zurücksetzen</button></div>
          <div class="meter" style="margin:12px 0 16px"><i style="width:${pct}%;background:${pct === 100 ? 'var(--ok)' : 'var(--accent-text)'}"></i></div>
          <div class="checklist">${items.map(([p, t, d], i) => `<label class="check-item ${st[i] ? 'done' : ''}"><input type="checkbox" data-i="${i}" ${st[i] ? 'checked' : ''}/><div><b>${esc(t)}</b><span class="prio p${p}">P${p}</span><p>${esc(d)}</p></div>${st[i] ? `<time>${esc(new Date(st[i]).toLocaleDateString('de-CH'))}</time>` : '<span></span>'}</label>`).join('')}</div></div>`;
        U.qa('[data-i]').forEach((c) => { c.onchange = () => { const s = U.store.get('cl-' + cur, {}); if (c.checked) s[c.dataset.i] = Date.now(); else delete s[c.dataset.i]; U.store.set('cl-' + cur, s); draw(); }; });
        U.q('#reset').onclick = () => { U.store.set('cl-' + cur, {}); draw(); };
        U.q('#exp').onclick = () => U.download(`checkliste-${cur}.md`, `# Checkliste ${name}\n\nStand: ${new Date().toLocaleDateString('de-CH')} · ${done}/${items.length} erledigt\n\n` + items.map(([p, t, d], i) => `- [${st[i] ? 'x' : ' '}] **${t}** (P${p}) — ${d}${st[i] ? ` _(erledigt ${new Date(st[i]).toLocaleDateString('de-CH')})_` : ''}`).join('\n') + '\n', 'text/markdown');
      };
      U.q('#tabs').onclick = (e) => { const b = e.target.closest('button'); if (b) { cur = b.dataset.k; draw(); } };
      draw();
    },
  });

  /* ================= Download prüfen (Prüfsumme) ================= */
  register({
    id: 'hash-verify', name: 'Download prüfen', glyph: '#', cat: 'shield',
    desc: 'Prüfsumme einer Datei mit dem Wert des Herstellers vergleichen (SHA-256, SHA-512, SHA-1).',
    keywords: 'checksum prüfsumme sha256 sha512 hash verify download integrity iso',
    render(root, U) {
      root.innerHTML = `<div class="cols"><div class="panel"><h3>Datei</h3><div class="dropzone" id="dz"><b>Datei hierher ziehen</b> oder klicken<br><span class="small">wird nur lokal berechnet</span></div><div id="fi" class="small muted" style="margin-top:10px"></div></div>
        <div class="panel"><h3>Erwarteter Wert</h3><textarea id="exp" style="min-height:90px" placeholder="Prüfsumme von der Hersteller-Website einfügen (auch «hash  dateiname» oder Inhalt einer .sha256-Datei)"></textarea><div id="cmp" style="margin-top:10px"></div></div></div>
        <div class="panel"><h3>Berechnet</h3><div id="out" class="muted">Noch keine Datei.</div></div>`;
      let hashes = null;
      const compare = () => {
        const e = (U.q('#exp').value.match(/[a-f0-9]{40,128}/i) || [''])[0].toLowerCase();
        if (!e || !hashes) { U.q('#cmp').innerHTML = ''; return; }
        const hit = Object.entries(hashes).find(([, v]) => v === e);
        U.q('#cmp').innerHTML = hit ? `<div class="finding ok"><div class="ic">✓</div><div><b>Stimmt überein (${hit[0]})</b><p>Die Datei ist identisch mit der veröffentlichten Version.</p></div><div></div></div>`
          : `<div class="finding err"><div class="ic">✕</div><div><b>Stimmt NICHT überein</b><p>Datei nicht öffnen. Erneut von der offiziellen Quelle laden und den Wert dort nochmals prüfen.</p></div><div></div></div>`;
      };
      U.dropzone(U.q('#dz'), async (files) => {
        const f = files[0];
        U.q('#fi').textContent = `${f.name} · ${U.fmtNum(f.size / 1048576, 1)} MB`;
        U.q('#out').innerHTML = '<span class="muted">Berechne …</span>';
        const buf = await U.readFile(f, 'buffer');
        hashes = {};
        for (const a of ['SHA-256', 'SHA-512', 'SHA-1']) hashes[a] = U.bytesToHex(new Uint8Array(await crypto.subtle.digest(a, buf)));
        U.q('#out').innerHTML = U.kv(Object.entries(hashes));
        compare();
      });
      U.q('#exp').addEventListener('input', compare);
    },
  });

  /* ================= Dateien verschlüsseln ================= */
  const MAGIC = [0x49, 0x53, 0x50, 0x48, 0x01]; // "ISPH" v1
  const ITER = 600000;
  const deriveKey = async (pw, salt) => {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  };
  register({
    id: 'file-crypt', name: 'Dateien verschlüsseln', glyph: 'AES', cat: 'shield',
    desc: 'Dateien mit AES-256-GCM und Passwort verschlüsseln, z. B. bevor sie per Mail oder Cloud verschickt werden.',
    keywords: 'encrypt decrypt verschlüsseln datei aes gcm pbkdf2 passwort file',
    render(root, U) {
      root.innerHTML = `<div class="cols"><div class="panel"><h3>Datei</h3><div class="dropzone" id="dz"><b>Datei wählen</b><br><span class="small">.isph-Dateien werden automatisch entschlüsselt</span></div><div id="fi" class="small muted" style="margin-top:10px"></div></div>
        <div class="panel"><h3>Passwort</h3><div class="field"><input id="pw" type="password" placeholder="mindestens 12 Zeichen" autocomplete="new-password"/></div>
          <div class="field"><input id="pw2" type="password" placeholder="wiederholen (beim Verschlüsseln)" autocomplete="new-password"/></div>
          <div class="row"><button class="btn btn-primary" id="enc">Verschlüsseln</button><button class="btn" id="dec">Entschlüsseln</button></div><div id="msg"></div></div></div>
        <div class="callout info">AES-256-GCM, Schlüssel aus dem Passwort mit PBKDF2-SHA-256 (${U.fmtNum(ITER, 0)} Runden). Passwort separat übermitteln (Telefon, SMS), nie in derselben Mail. Ohne Passwort ist die Datei nicht wiederherstellbar.</div>`;
      let file = null;
      U.dropzone(U.q('#dz'), (f) => { file = f[0]; U.q('#fi').textContent = `${file.name} · ${U.fmtNum(file.size / 1024, 0)} KB`; U.q('#msg').innerHTML = ''; });
      const msg = (t, ok) => { U.q('#msg').innerHTML = `<div class="msg ${ok ? 'ok' : 'err'}">${esc(t)}</div>`; };
      U.q('#enc').onclick = async () => {
        const pw = U.q('#pw').value;
        if (!file) return msg('Bitte zuerst eine Datei wählen.');
        if (pw.length < 12) return msg('Passwort zu kurz (mindestens 12 Zeichen).');
        if (pw !== U.q('#pw2').value) return msg('Passwörter stimmen nicht überein.');
        const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
        const name = new TextEncoder().encode(file.name);
        const plain = new Uint8Array(await U.readFile(file, 'buffer'));
        const payload = new Uint8Array(2 + name.length + plain.length);
        payload[0] = name.length >> 8; payload[1] = name.length & 255; payload.set(name, 2); payload.set(plain, 2 + name.length);
        const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await deriveKey(pw, salt), payload));
        U.download(file.name.replace(/\.[^.]+$/, '') + '.isph', new Blob([new Uint8Array(MAGIC), salt, iv, ct], { type: 'application/octet-stream' }));
        msg('Verschlüsselt und heruntergeladen. Der Dateiname ist mitverschlüsselt.', true);
      };
      U.q('#dec').onclick = async () => {
        if (!file) return msg('Bitte zuerst eine .isph-Datei wählen.');
        const b = new Uint8Array(await U.readFile(file, 'buffer'));
        if (!MAGIC.every((x, i) => b[i] === x)) return msg('Keine Infosphera-verschlüsselte Datei (.isph).');
        try {
          const salt = b.subarray(5, 21), iv = b.subarray(21, 33);
          const p = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, await deriveKey(U.q('#pw').value, salt), b.subarray(33)));
          const nl = (p[0] << 8) | p[1];
          U.download(new TextDecoder().decode(p.subarray(2, 2 + nl)), new Blob([p.subarray(2 + nl)]));
          msg('Entschlüsselt und heruntergeladen.', true);
        } catch { msg('Falsches Passwort oder beschädigte Datei.'); }
      };
    },
  });

  /* ================= Metadaten entfernen (JPEG/PNG) ================= */
  const readExif = (b, off, len) => {
    const out = {};
    if (String.fromCharCode(...b.subarray(off, off + 4)) !== 'Exif') return out;
    const t = off + 6; const le = b[t] === 0x49;
    const u16 = (p) => le ? b[p] | (b[p + 1] << 8) : (b[p] << 8) | b[p + 1];
    const u32 = (p) => (le ? (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) : ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3])) >>> 0;
    const ascii = (e) => { const n = u32(e + 4); const p = n > 4 ? t + u32(e + 8) : e + 8; return String.fromCharCode(...b.subarray(p, p + n)).replace(/\0+$/, '').trim(); };
    const rat = (p) => u32(p) / (u32(p + 4) || 1);
    const ifd = (p, cb) => { if (p <= 0 || p >= len + off) return; const n = u16(p); for (let i = 0; i < n && i < 200; i++) cb(p + 2 + i * 12, u16(p + 2 + i * 12)); };
    try {
      ifd(t + u32(t + 4), (e, tag) => {
        if (tag === 0x010F) out.Kamerahersteller = ascii(e);
        if (tag === 0x0110) out.Kameramodell = ascii(e);
        if (tag === 0x0131) out.Software = ascii(e);
        if (tag === 0x0132) out.Datum = ascii(e);
        if (tag === 0x013B) out.Autor = ascii(e);
        if (tag === 0x8298) out.Copyright = ascii(e);
        if (tag === 0x8769) ifd(t + u32(e + 8), (e2, t2) => { if (t2 === 0x9003) out.Aufnahmedatum = ascii(e2); if (t2 === 0xA434) out.Objektiv = ascii(e2); if (t2 === 0xA431) out.Seriennummer = ascii(e2); });
        if (tag === 0x8825) {
          const g = {};
          ifd(t + u32(e + 8), (e2, t2) => {
            if (t2 === 1 || t2 === 3) g[t2] = String.fromCharCode(b[e2 + 8]);
            if (t2 === 2 || t2 === 4) { const p = t + u32(e2 + 8); g[t2] = rat(p) + rat(p + 8) / 60 + rat(p + 16) / 3600; }
          });
          if (g[2] !== undefined && g[4] !== undefined) out.GPS = `${(g[1] === 'S' ? -g[2] : g[2]).toFixed(5)}, ${(g[3] === 'W' ? -g[4] : g[4]).toFixed(5)}`;
          else out.GPS = 'vorhanden';
        }
      });
    } catch { /* ignore */ }
    return out;
  };
  const cleanJpeg = (b) => {
    if (b[0] !== 0xFF || b[1] !== 0xD8) throw new Error('Kein JPEG');
    const parts = [b.subarray(0, 2)]; const found = {}; const removed = [];
    let p = 2;
    while (p < b.length) {
      if (b[p] !== 0xFF) throw new Error('Beschädigtes JPEG');
      const m = b[p + 1];
      if (m === 0xDA) { parts.push(b.subarray(p)); break; }
      if (m === 0xD8 || (m >= 0xD0 && m <= 0xD7) || m === 0x01) { parts.push(b.subarray(p, p + 2)); p += 2; continue; }
      const len = (b[p + 2] << 8) | b[p + 3]; const seg = b.subarray(p, p + 2 + len);
      const id = String.fromCharCode(...b.subarray(p + 4, p + 4 + 12));
      let drop = false;
      if (m === 0xE1) { drop = true; if (id.startsWith('Exif')) { Object.assign(found, readExif(b, p + 4, len)); removed.push('EXIF'); } else removed.push('XMP'); }
      else if (m === 0xED) { drop = true; removed.push('IPTC/Photoshop'); }
      else if (m === 0xFE) { drop = true; found.Kommentar = new TextDecoder().decode(b.subarray(p + 4, p + 2 + len)).slice(0, 120); removed.push('Kommentar'); }
      else if (m >= 0xE3 && m <= 0xEF && m !== 0xEE) { drop = true; removed.push('APP' + (m - 0xE0)); }
      if (!drop) parts.push(seg);
      p += 2 + len;
    }
    return { out: new Blob(parts, { type: 'image/jpeg' }), found, removed: [...new Set(removed)] };
  };
  const cleanPng = (b) => {
    const sig = [137, 80, 78, 71, 13, 10, 26, 10];
    if (!sig.every((x, i) => b[i] === x)) throw new Error('Kein PNG');
    const parts = [b.subarray(0, 8)]; const found = {}; const removed = []; let p = 8;
    while (p < b.length) {
      const len = ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;
      const type = String.fromCharCode(...b.subarray(p + 4, p + 8));
      const chunk = b.subarray(p, p + 12 + len);
      if (['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME'].includes(type)) {
        removed.push(type);
        if (type === 'tEXt' || type === 'iTXt') { const d = b.subarray(p + 8, p + 8 + len); const z = d.indexOf(0); found[new TextDecoder().decode(d.subarray(0, z))] = new TextDecoder().decode(d.subarray(z + 1)).replace(/\0/g, ' ').slice(0, 100); }
        if (type === 'eXIf') found.EXIF = 'vorhanden';
      } else parts.push(chunk);
      p += 12 + len;
      if (type === 'IEND') break;
    }
    return { out: new Blob(parts, { type: 'image/png' }), found, removed: [...new Set(removed)] };
  };
  register({
    id: 'meta-strip', name: 'Metadaten entfernen', glyph: 'GPS', cat: 'shield',
    desc: 'GPS-Standort, Kamera, Datum und Kommentare aus JPEG- und PNG-Bildern entfernen, bevor sie veröffentlicht werden.',
    keywords: 'exif metadata metadaten gps standort foto bild jpeg png entfernen privacy osint',
    render(root, U) {
      root.innerHTML = `<div class="panel"><div class="dropzone" id="dz"><b>Bilder hierher ziehen</b> oder klicken · JPEG, PNG · mehrere möglich</div>
        <div class="small muted" style="margin-top:8px">Die Bilddaten selbst werden nicht neu komprimiert, die Qualität bleibt gleich. Hinweis: Mit EXIF geht auch die Drehinformation verloren; hochkant fotografierte Bilder können danach quer erscheinen.</div></div><div id="res"></div>`;
      U.dropzone(U.q('#dz'), async (files) => {
        const rows = [];
        for (const f of files) {
          try {
            const b = new Uint8Array(await U.readFile(f, 'buffer'));
            const r = /png$/i.test(f.type) || f.name.toLowerCase().endsWith('.png') ? cleanPng(b) : cleanJpeg(b);
            const id = 'dl' + rows.length;
            rows.push({ f, r, id });
          } catch (e) { rows.push({ f, err: e.message }); }
        }
        U.q('#res').innerHTML = rows.map(({ f, r, id, err }) => `<div class="panel"><div class="row"><b class="grow">${esc(f.name)}</b>${err ? `<span class="badge err">${esc(err)}</span>` : `<span class="small muted">${U.fmtNum(f.size / 1024, 0)} KB → ${U.fmtNum(r.out.size / 1024, 0)} KB</span><button class="btn btn-sm btn-primary" id="${id}">${U.icon('download')}Bereinigt laden</button>`}</div>
          ${err ? '' : (Object.keys(r.found).length ? `<div style="margin-top:12px">${r.found.GPS ? `<div class="callout warn"><b>Standort im Bild:</b> ${esc(r.found.GPS)}${/,/.test(r.found.GPS) ? ` · <a href="https://www.openstreetmap.org/?mlat=${encodeURIComponent(r.found.GPS.split(',')[0].trim())}&mlon=${encodeURIComponent(r.found.GPS.split(',')[1].trim())}#map=17/${encodeURIComponent(r.found.GPS.split(',')[0].trim())}/${encodeURIComponent(r.found.GPS.split(',')[1].trim())}" target="_blank" rel="noopener">auf Karte zeigen</a>` : ''}</div>` : ''}${U.kv(Object.entries(r.found).filter(([k]) => k !== 'GPS'))}</div>` : '<div class="small muted" style="margin-top:8px">Keine lesbaren Metadaten gefunden.</div>') + (r.removed.length ? `<div class="small" style="margin-top:8px">Entfernt: ${r.removed.map((x) => `<span class="badge">${esc(x)}</span>`).join(' ')}</div>` : '')}</div>`).join('');
        rows.forEach(({ f, r, id }) => { if (r) U.q('#' + id).onclick = () => U.download(f.name.replace(/(\.[^.]+)$/, '-bereinigt$1'), r.out); });
      }, { multiple: true, accept: 'image/jpeg,image/png' });
    },
  });
})();
